#![allow(non_snake_case)]
use super::*;
use std::ffi::c_void;
use std::io::{Read, Seek, SeekFrom};
use std::mem::{size_of, ManuallyDrop};
use std::sync::mpsc::SyncSender;
use windows::{
    core::{implement, w, Ref, HRESULT},
    Win32::{
        Foundation::*,
        System::{Com::*, DataExchange::*, Memory::*, Ole::*},
        UI::{Shell::*, WindowsAndMessaging::*},
    },
};
type WinResult<T> = windows::core::Result<T>;

pub(super) fn owns(ticket: &Ticket) -> bool {
    ticket.owned.load(Ordering::Acquire)
        && unsafe {
            GetClipboardOwner()
                .map(|h| h.0 as usize == ticket.owner.load(Ordering::Acquire))
                .unwrap_or(false)
        }
}
pub(super) fn run(ticket: Arc<Ticket>, ready: &SyncSender<Result<(), String>>) -> Result<()> {
    unsafe {
        OleInitialize(None)?;
    }
    struct OleGuard;
    impl Drop for OleGuard {
        fn drop(&mut self) {
            unsafe {
                OleUninitialize();
            }
        }
    }
    let _ole = OleGuard;
    let formats = Formats {
        descriptor: unsafe { RegisterClipboardFormatW(w!("FileGroupDescriptorW")) } as u16,
        contents: unsafe { RegisterClipboardFormatW(w!("FileContents")) } as u16,
        effect: unsafe { RegisterClipboardFormatW(w!("Preferred DropEffect")) } as u16,
    };
    if formats.descriptor == 0 || formats.contents == 0 || formats.effect == 0 {
        return Err(anyhow!("could not register virtual file formats"));
    }
    let object: IDataObject = FileObject {
        ticket: ticket.clone(),
        formats,
        async_mode: AtomicBool::new(true),
        in_operation: AtomicBool::new(false),
    }
    .into();
    unsafe {
        OleSetClipboard(&object)?;
    }
    ticket.owner.store(
        unsafe { GetClipboardOwner()?.0 as usize },
        Ordering::Release,
    );
    ticket.owned.store(true, Ordering::Release);
    let _ = ready.send(Ok(()));
    while !ticket.stopped.load(Ordering::Acquire) && owns(&ticket) {
        let mut message = MSG::default();
        unsafe {
            while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if owns(&ticket) {
        unsafe {
            let _ = OleSetClipboard(None::<&IDataObject>);
        }
    }
    ticket.owned.store(false, Ordering::Release);
    ticket.cancel();
    Ok(())
}

#[derive(Clone, Copy)]
struct Formats {
    descriptor: u16,
    contents: u16,
    effect: u16,
}
#[implement(IDataObject, IDataObjectAsyncCapability)]
struct FileObject {
    ticket: Arc<Ticket>,
    formats: Formats,
    async_mode: AtomicBool,
    in_operation: AtomicBool,
}
fn format(id: u16, tymed: TYMED, index: i32) -> FORMATETC {
    FORMATETC {
        cfFormat: id,
        dwAspect: DVASPECT_CONTENT.0,
        lindex: index,
        tymed: tymed.0 as u32,
        ..Default::default()
    }
}
unsafe fn global(bytes: &[u8]) -> WinResult<STGMEDIUM> {
    let handle = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes.len())?;
    let pointer = GlobalLock(handle);
    if pointer.is_null() {
        let _ = GlobalFree(Some(handle));
        return Err(E_OUTOFMEMORY.into());
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.cast(), bytes.len());
    let _ = GlobalUnlock(handle);
    Ok(STGMEDIUM {
        tymed: TYMED_HGLOBAL.0 as u32,
        u: STGMEDIUM_0 { hGlobal: handle },
        ..Default::default()
    })
}
impl IDataObject_Impl for FileObject_Impl {
    fn GetData(&self, input: *const FORMATETC) -> WinResult<STGMEDIUM> {
        self.QueryGetData(input).ok()?;
        let input = unsafe { &*input };
        if input.cfFormat == self.formats.descriptor {
            let mut bytes = vec![0u8; 4 + size_of::<FILEDESCRIPTORW>() * self.ticket.files.len()];
            bytes[..4].copy_from_slice(&(self.ticket.files.len() as u32).to_le_bytes());
            for (index, file) in self.ticket.files.iter().enumerate() {
                let mut descriptor = FILEDESCRIPTORW {
                    dwFlags: (FD_FILESIZE.0 | FD_ATTRIBUTES.0 | FD_PROGRESSUI.0) as u32,
                    dwFileAttributes: 128,
                    nFileSizeHigh: (file.size >> 32) as u32,
                    nFileSizeLow: file.size as u32,
                    ..Default::default()
                };
                let name = file.name.encode_utf16().collect::<Vec<_>>();
                // FILEDESCRIPTORW is packed, so copy through an aligned array.
                let mut filename = [0u16; 260];
                filename[..name.len().min(259)].copy_from_slice(&name[..name.len().min(259)]);
                descriptor.cFileName = filename;
                unsafe {
                    std::ptr::write_unaligned(
                        bytes
                            .as_mut_ptr()
                            .add(4 + index * size_of::<FILEDESCRIPTORW>())
                            .cast::<FILEDESCRIPTORW>(),
                        descriptor,
                    );
                }
            }
            unsafe { global(&bytes) }
        } else if input.cfFormat == self.formats.effect {
            unsafe { global(&1u32.to_le_bytes()) }
        } else {
            if input.lindex < 0 || input.lindex as usize >= self.ticket.files.len() {
                return Err(DV_E_LINDEX.into());
            }
            // GetData and Stat are cheap; the first IStream::Read requests data.
            let stream: IStream = PromisedStream {
                ticket: self.ticket.clone(),
                index: input.lindex as usize,
                position: Mutex::new((0, None)),
            }
            .into();
            Ok(STGMEDIUM {
                tymed: TYMED_ISTREAM.0 as u32,
                u: STGMEDIUM_0 {
                    pstm: ManuallyDrop::new(Some(stream)),
                },
                ..Default::default()
            })
        }
    }
    fn QueryGetData(&self, input: *const FORMATETC) -> HRESULT {
        if input.is_null() {
            return E_POINTER;
        }
        let input = unsafe { &*input };
        if input.dwAspect != DVASPECT_CONTENT.0 {
            return DV_E_DVASPECT;
        }
        if (input.cfFormat == self.formats.descriptor || input.cfFormat == self.formats.effect)
            && input.tymed & TYMED_HGLOBAL.0 as u32 != 0
        {
            return S_OK;
        }
        if input.cfFormat == self.formats.contents
            && input.tymed & TYMED_ISTREAM.0 as u32 != 0
            && input.lindex >= -1
            && input.lindex < self.ticket.files.len() as i32
        {
            return S_OK;
        }
        DV_E_FORMATETC
    }
    fn GetDataHere(&self, _: *const FORMATETC, _: *mut STGMEDIUM) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }
    fn GetCanonicalFormatEtc(&self, _: *const FORMATETC, output: *mut FORMATETC) -> HRESULT {
        if !output.is_null() {
            unsafe {
                (*output).ptd = std::ptr::null_mut();
            }
        }
        E_NOTIMPL
    }
    fn SetData(
        &self,
        _: *const FORMATETC,
        medium: *const STGMEDIUM,
        release: BOOL,
    ) -> WinResult<()> {
        // Shell completion notifications are advisory; transfers are always copies.
        if medium.is_null() {
            return Err(E_POINTER.into());
        }
        if release.as_bool() {
            unsafe {
                ReleaseStgMedium(medium.cast_mut());
            }
        }
        Ok(())
    }
    fn EnumFormatEtc(&self, direction: u32) -> WinResult<IEnumFORMATETC> {
        if direction != DATADIR_GET.0 as u32 {
            return Err(E_NOTIMPL.into());
        }
        unsafe {
            SHCreateStdEnumFmtEtc(&[
                format(self.formats.descriptor, TYMED_HGLOBAL, -1),
                format(self.formats.contents, TYMED_ISTREAM, -1),
                format(self.formats.effect, TYMED_HGLOBAL, -1),
            ])
        }
    }
    fn DAdvise(&self, _: *const FORMATETC, _: u32, _: Ref<'_, IAdviseSink>) -> WinResult<u32> {
        Err(OLE_E_ADVISENOTSUPPORTED.into())
    }
    fn DUnadvise(&self, _: u32) -> WinResult<()> {
        Err(OLE_E_ADVISENOTSUPPORTED.into())
    }
    fn EnumDAdvise(&self) -> WinResult<IEnumSTATDATA> {
        Err(OLE_E_ADVISENOTSUPPORTED.into())
    }
}
impl IDataObjectAsyncCapability_Impl for FileObject_Impl {
    fn SetAsyncMode(&self, value: BOOL) -> WinResult<()> {
        self.async_mode.store(value.as_bool(), Ordering::Relaxed);
        Ok(())
    }
    fn GetAsyncMode(&self) -> WinResult<BOOL> {
        Ok(self.async_mode.load(Ordering::Relaxed).into())
    }
    fn StartOperation(&self, _: Ref<'_, IBindCtx>) -> WinResult<()> {
        self.in_operation.store(true, Ordering::Relaxed);
        Ok(())
    }
    fn InOperation(&self) -> WinResult<BOOL> {
        Ok(self.in_operation.load(Ordering::Relaxed).into())
    }
    fn EndOperation(&self, _: HRESULT, _: Ref<'_, IBindCtx>, _: u32) -> WinResult<()> {
        self.in_operation.store(false, Ordering::Relaxed);
        Ok(())
    }
}

#[implement(IStream)]
struct PromisedStream {
    ticket: Arc<Ticket>,
    index: usize,
    position: Mutex<(u64, Option<std::fs::File>)>,
}
impl ISequentialStream_Impl for PromisedStream_Impl {
    fn Read(&self, pointer: *mut c_void, size: u32, read: *mut u32) -> HRESULT {
        if !read.is_null() {
            unsafe {
                *read = 0;
            }
        }
        if size == 0 {
            return S_OK;
        }
        if pointer.is_null() {
            return E_POINTER;
        }
        let result = (|| -> Result<usize> {
            let mut position = self.position.lock().unwrap();
            if position.1.is_none() {
                let paths = self.ticket.wait()?;
                position.1 = Some(std::fs::File::open(
                    paths
                        .get(self.index)
                        .ok_or_else(|| anyhow!("missing promised file"))?,
                )?);
            }
            let offset = position.0;
            let file = position.1.as_mut().unwrap();
            file.seek(SeekFrom::Start(offset))?;
            let count = file.read(unsafe {
                std::slice::from_raw_parts_mut(pointer.cast::<u8>(), size as usize)
            })?;
            position.0 += count as u64;
            Ok(count)
        })();
        match result {
            Ok(count) => {
                if !read.is_null() {
                    unsafe {
                        *read = count as u32;
                    }
                }
                if count == size as usize {
                    S_OK
                } else {
                    S_FALSE
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "Windows promised file read failed");
                STG_E_READFAULT
            }
        }
    }
    fn Write(&self, _: *const c_void, _: u32, written: *mut u32) -> HRESULT {
        if !written.is_null() {
            unsafe {
                *written = 0;
            }
        }
        STG_E_ACCESSDENIED
    }
}
impl IStream_Impl for PromisedStream_Impl {
    fn Seek(&self, delta: i64, origin: STREAM_SEEK, result: *mut u64) -> WinResult<()> {
        let mut position = self.position.lock().unwrap();
        let base = match origin {
            STREAM_SEEK_SET => 0,
            STREAM_SEEK_CUR => position.0,
            STREAM_SEEK_END => self.ticket.files[self.index].size,
            _ => return Err(STG_E_INVALIDFUNCTION.into()),
        };
        let offset = i128::from(base) + i128::from(delta);
        if offset < 0 || offset > u64::MAX as i128 {
            return Err(STG_E_INVALIDFUNCTION.into());
        }
        position.0 = offset as u64;
        if !result.is_null() {
            unsafe {
                *result = position.0;
            }
        }
        Ok(())
    }
    fn Stat(&self, result: *mut STATSTG, flags: &STATFLAG) -> WinResult<()> {
        if result.is_null() {
            return Err(E_POINTER.into());
        }
        let mut stat = STATSTG {
            r#type: STGTY_STREAM.0 as u32,
            cbSize: self.ticket.files[self.index].size,
            ..Default::default()
        };
        if *flags != STATFLAG_NONAME {
            let name = self.ticket.files[self.index]
                .name
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let ptr = unsafe { CoTaskMemAlloc(name.len() * 2) }.cast::<u16>();
            if ptr.is_null() {
                return Err(E_OUTOFMEMORY.into());
            }
            unsafe {
                std::ptr::copy_nonoverlapping(name.as_ptr(), ptr, name.len());
            }
            stat.pwcsName = windows::core::PWSTR(ptr);
        }
        unsafe {
            *result = stat;
        }
        Ok(())
    }
    fn CopyTo(
        &self,
        target: Ref<'_, IStream>,
        count: u64,
        read: *mut u64,
        written: *mut u64,
    ) -> WinResult<()> {
        if !read.is_null() {
            unsafe {
                *read = 0;
            }
        }
        if !written.is_null() {
            unsafe {
                *written = 0;
            }
        }
        let target = target.as_ref().ok_or(E_POINTER)?;
        let mut buffer = [0u8; 65536];
        let mut total = 0;
        while total < count {
            let mut got = 0;
            self.Read(
                buffer.as_mut_ptr().cast(),
                (count - total).min(buffer.len() as u64) as u32,
                &mut got,
            )
            .ok()?;
            if got == 0 {
                break;
            }
            let mut sent = 0;
            unsafe {
                target
                    .Write(buffer.as_ptr().cast(), got, Some(&mut sent))
                    .ok()?;
            }
            total += got as u64;
            if !read.is_null() {
                unsafe {
                    *read += got as u64;
                }
            }
            if !written.is_null() {
                unsafe {
                    *written += sent as u64;
                }
            }
            if sent != got {
                return Err(STG_E_MEDIUMFULL.into());
            }
        }
        Ok(())
    }
    fn Clone(&self) -> WinResult<IStream> {
        Ok(PromisedStream {
            ticket: self.ticket.clone(),
            index: self.index,
            position: Mutex::new((self.position.lock().unwrap().0, None)),
        }
        .into())
    }
    fn SetSize(&self, _: u64) -> WinResult<()> {
        Err(STG_E_ACCESSDENIED.into())
    }
    fn Commit(&self, _: &STGC) -> WinResult<()> {
        Ok(())
    }
    fn Revert(&self) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }
    fn LockRegion(&self, _: u64, _: u64, _: &LOCKTYPE) -> WinResult<()> {
        Err(STG_E_INVALIDFUNCTION.into())
    }
    fn UnlockRegion(&self, _: u64, _: u64, _: u32) -> WinResult<()> {
        Err(STG_E_INVALIDFUNCTION.into())
    }
}
