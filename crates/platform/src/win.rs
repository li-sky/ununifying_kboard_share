//! Windows adapter: LL keyboard hook + SendInput + GetCursorPos polling.
//!
//! Lifetime notes:
//!
//! * `SetWindowsHookExW(WH_KEYBOARD_LL, ...)` installs a hook that delivers
//!   events to a C function pointer. The hook thread must run a message loop
//!   (`GetMessageW`) or the OS will not deliver events.
//! * Because the C callback cannot capture closures, we stash the mutable
//!   state in a file-scoped `OnceCell`. Only the hook thread writes; the
//!   consumer thread only reads via atomics or channels.

#![cfg(windows)]

use super::{KeyCapture, KeyInjector, MouseActivity, MouseWatcher, Result};
use anyhow::{anyhow, Context};
use crossbeam_channel::{bounded, Sender};
use kbshare_core::keycode::{from_win_vk, to_win_vk, Key};
use kbshare_core::protocol::KeyAction;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

// ---- shared hook state ----

struct HookState {
    forwarding: Arc<AtomicBool>,
    sender: Sender<(KeyAction, Key)>,
}

static HOOK_STATE: OnceCell<HookState> = OnceCell::new();

unsafe extern "system" fn hook_proc(n_code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if n_code < 0 {
        return CallNextHookEx(std::ptr::null_mut(), n_code, w_param, l_param);
    }
    if let Some(state) = HOOK_STATE.get() {
        let info = &*(l_param as *const KBDLLHOOKSTRUCT);
        let vk = info.vkCode;
        let is_down = w_param as u32 == WM_KEYDOWN || w_param as u32 == WM_SYSKEYDOWN;
        let action = if is_down {
            KeyAction::Press
        } else {
            KeyAction::Release
        };
        // The LL hook reports numpad Enter as VK_RETURN (0x0D) with the
        // LLKHF_EXTENDED flag set, identical to how the injector must send
        // it. Promote it to KEY_KPENTER so the peer reproduces the right
        // physical key instead of the main Enter key.
        let key = if vk == 0x0D && (info.flags & LLKHF_EXTENDED) != 0 {
            Some(Key::new(kbshare_core::keycode::codes::KEY_KPENTER))
        } else {
            from_win_vk(vk)
        };
        if let Some(key) = key {
            // Best-effort: non-blocking send. If the consumer is slow we'd
            // rather drop than stall the OS hook thread.
            let _ = state.sender.try_send((action, key));
        }
        if state.forwarding.load(Ordering::Relaxed) {
            return 1; // swallow
        }
    }
    CallNextHookEx(std::ptr::null_mut(), n_code, w_param, l_param)
}

// ---- capture ----

pub struct WinKeyCapture {
    forwarding: Arc<AtomicBool>,
    sender: Option<Sender<(KeyAction, Key)>>,
    hook_thread: Mutex<Option<JoinHandle<()>>>,
    consumer_thread: Mutex<Option<JoinHandle<()>>>,
    hook_tid: Arc<AtomicU32>,
    shutdown: Arc<AtomicBool>,
}

impl WinKeyCapture {
    pub fn new() -> Result<Self> {
        Ok(Self {
            forwarding: Arc::new(AtomicBool::new(false)),
            sender: None,
            hook_thread: Mutex::new(None),
            consumer_thread: Mutex::new(None),
            hook_tid: Arc::new(AtomicU32::new(0)),
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn forwarding_flag(&self) -> Arc<AtomicBool> {
        self.forwarding.clone()
    }
}

impl KeyCapture for WinKeyCapture {
    fn start(&mut self, mut on_event: Box<dyn FnMut(KeyAction, Key) + Send>) -> Result<()> {
        if HOOK_STATE.get().is_some() {
            return Err(anyhow!("WinKeyCapture already installed globally"));
        }

        // Reasonable bound; keystrokes are tiny, 1024 is more than plenty.
        let (tx, rx) = bounded::<(KeyAction, Key)>(1024);
        self.sender = Some(tx.clone());

        HOOK_STATE
            .set(HookState {
                forwarding: self.forwarding.clone(),
                sender: tx,
            })
            .map_err(|_| anyhow!("hook state already set"))?;

        // Consumer thread: drains the channel and invokes the user callback.
        let shutdown_c = self.shutdown.clone();
        let consumer = thread::spawn(move || {
            while !shutdown_c.load(Ordering::Relaxed) {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok((a, k)) => on_event(a, k),
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(_) => break,
                }
            }
        });
        *self.consumer_thread.lock() = Some(consumer);

        // Hook thread: owns SetWindowsHookExW + GetMessageW loop.
        let hook_tid = self.hook_tid.clone();
        let shutdown_h = self.shutdown.clone();
        let hook = thread::spawn(move || unsafe {
            hook_tid.store(GetCurrentThreadId(), Ordering::Release);
            let h_mod = GetModuleHandleW(std::ptr::null());
            let hook_h = SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), h_mod, 0);
            if hook_h.is_null() {
                tracing::error!("SetWindowsHookExW failed");
                return;
            }
            let mut msg: MSG = std::mem::zeroed();
            while !shutdown_h.load(Ordering::Relaxed) {
                let ret = GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0);
                if ret <= 0 {
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            UnhookWindowsHookEx(hook_h);
        });
        *self.hook_thread.lock() = Some(hook);

        Ok(())
    }

    fn forwarding_flag(&self) -> Arc<AtomicBool> {
        self.forwarding.clone()
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Wake the GetMessageW loop.
        let tid = self.hook_tid.load(Ordering::Acquire);
        if tid != 0 {
            unsafe {
                PostThreadMessageW(tid, WM_QUIT, 0, 0);
            }
        }
        if let Some(h) = self.hook_thread.lock().take() {
            let _ = h.join();
        }
        if let Some(h) = self.consumer_thread.lock().take() {
            let _ = h.join();
        }
    }
}

impl Drop for WinKeyCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---- mouse watcher ----

pub struct WinMouseWatcher {
    shutdown: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl WinMouseWatcher {
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            handle: Mutex::new(None),
        }
    }
}

impl Default for WinMouseWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl MouseWatcher for WinMouseWatcher {
    fn start(&mut self, mut on_activity: Box<dyn FnMut(MouseActivity) + Send>) -> Result<()> {
        let shutdown = self.shutdown.clone();
        let h = thread::spawn(move || unsafe {
            let mut last = POINT { x: 0, y: 0 };
            GetCursorPos(&mut last);
            let desktop_left = GetSystemMetrics(SM_XVIRTUALSCREEN);
            let desktop_right = desktop_left + GetSystemMetrics(SM_CXVIRTUALSCREEN);
            let desktop_top = GetSystemMetrics(SM_YVIRTUALSCREEN);
            let desktop_bottom = desktop_top + GetSystemMetrics(SM_CYVIRTUALSCREEN);
            while !shutdown.load(Ordering::Relaxed) {
                let mut now = POINT { x: 0, y: 0 };
                if GetCursorPos(&mut now) != 0 && (now.x != last.x || now.y != last.y) {
                    last = now;
                    on_activity(MouseActivity {
                        x: Some(now.x),
                        y: Some(now.y),
                        desktop_left: Some(desktop_left),
                        desktop_right: Some(desktop_right),
                        desktop_top: Some(desktop_top),
                        desktop_bottom: Some(desktop_bottom),
                    });
                }
                thread::sleep(Duration::from_millis(30));
            }
        });
        *self.handle.lock() = Some(h);
        Ok(())
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.lock().take() {
            let _ = h.join();
        }
    }
}

impl Drop for WinMouseWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---- injector ----

pub struct WinKeyInjector;

impl WinKeyInjector {
    pub fn new() -> Self {
        Self
    }

    fn send(&self, key: Key, release: bool) -> Result<()> {
        let vk = to_win_vk(key)
            .ok_or_else(|| anyhow!("no Windows VK mapping for key code {}", key.code()))?;
        unsafe {
            let scan = MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
            let mut flags: KEYBD_EVENT_FLAGS = 0;
            if is_extended_vk(vk) || is_extended_key(key) {
                flags |= KEYEVENTF_EXTENDEDKEY;
            }
            if release {
                flags |= KEYEVENTF_KEYUP;
            }
            let mut input = INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        wVk: vk as u16,
                        wScan: scan as u16,
                        dwFlags: flags,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };
            let sent = SendInput(1, &mut input, std::mem::size_of::<INPUT>() as i32);
            if sent != 1 {
                return Err(anyhow!("SendInput failed")).context("inject key");
            }
        }
        Ok(())
    }
}

impl Default for WinKeyInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyInjector for WinKeyInjector {
    fn press(&mut self, key: Key) -> Result<()> {
        self.send(key, false)
    }
    fn release(&mut self, key: Key) -> Result<()> {
        self.send(key, true)
    }
}

fn is_extended_vk(vk: u32) -> bool {
    // Arrow keys, INS, DEL, HOME, END, PAGEUP, PAGEDOWN, NumLock, Right
    // modifiers, PrintScreen — these need KEYEVENTF_EXTENDEDKEY to arrive
    // with the correct scan code in many apps (games, RDP, remote viewers).
    //
    // Numpad Divide (VK_DIVIDE 0x6F) is also an extended key on the PS/2
    // scan code set; without the flag many apps mis-identify it.
    matches!(
        vk,
        0x21..=0x28  // PGUP/PGDN/END/HOME/arrows
            | 0x2C   // PRINTSCREEN
            | 0x2D   // INSERT
            | 0x2E   // DELETE
            | 0x5B   // LWIN
            | 0x5C   // RWIN
            | 0x6F   // DIVIDE (numpad /)
            | 0x90   // NUMLOCK
            | 0xA1   // RSHIFT
            | 0xA3   // RCONTROL
            | 0xA5 // RMENU
    )
}

/// Some logical keys share a VK with a non-extended twin but still need the
/// extended-key flag when injected. The notable case is numpad Enter
/// (`KEY_KPENTER`), which maps to `VK_RETURN` (0x0D) just like the main
/// Enter key, but must be sent with `KEYEVENTF_EXTENDEDKEY` so apps can tell
/// the two apart.
fn is_extended_key(key: Key) -> bool {
    use kbshare_core::keycode::codes;
    matches!(key.code(), codes::KEY_KPENTER)
}
