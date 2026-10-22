use super::*;
use std::io::Write;
use std::sync::mpsc::SyncSender;
const URI: &str = "text/uri-list";
const GNOME: &str = "x-special/gnome-copied-files";

// Bound concurrent native clients, including abandoned paste requests.
static READERS: AtomicUsize = AtomicUsize::new(0);
struct Reader;
impl Reader {
    fn acquire() -> Option<Self> {
        READERS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 32).then_some(n + 1)
            })
            .ok()
            .map(|_| Self)
    }
}
impl Drop for Reader {
    fn drop(&mut self) {
        READERS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn contents(ticket: &Ticket, mime: &str) -> Result<Vec<u8>> {
    let paths = ticket.wait()?;
    let uris = paths
        .iter()
        .map(|path| {
            url::Url::from_file_path(path)
                .map(|u| u.to_string())
                .map_err(|_| anyhow!("invalid received file path"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(if mime == GNOME {
        format!("copy\n{}", uris.join("\n"))
    } else {
        format!("{}\r\n", uris.join("\r\n"))
    }
    .into_bytes())
}
pub(super) fn run(ticket: Arc<Ticket>, ready: &SyncSender<Result<(), String>>) -> Result<()> {
    if std::env::var_os("WAYLAND_DISPLAY").is_some()
        && std::env::var("XDG_SESSION_TYPE").as_deref() != Ok("x11")
    {
        wayland::run(ticket, ready)
    } else {
        x11::run(ticket, ready)
    }
}

mod x11 {
    use super::*;
    use std::sync::Arc;
    use x11rb::{
        connection::Connection,
        protocol::{xproto::*, Event},
        wrapper::ConnectionExt as _,
        COPY_DEPTH_FROM_PARENT, CURRENT_TIME, NONE,
    };
    pub(super) fn run(ticket: Arc<Ticket>, ready: &SyncSender<Result<(), String>>) -> Result<()> {
        let (connection, screen) = x11rb::connect(None)?;
        let connection = Arc::new(connection);
        let window = connection.generate_id()?;
        connection
            .create_window(
                COPY_DEPTH_FROM_PARENT,
                window,
                connection.setup().roots[screen].root,
                0,
                0,
                1,
                1,
                0,
                WindowClass::INPUT_OUTPUT,
                0,
                &CreateWindowAux::new(),
            )?
            .check()?;
        let atom = |name: &str| -> Result<Atom> {
            Ok(connection
                .intern_atom(false, name.as_bytes())?
                .reply()?
                .atom)
        };
        let clipboard = atom("CLIPBOARD")?;
        let targets = atom("TARGETS")?;
        let uri = atom(URI)?;
        let gnome = atom(GNOME)?;
        connection
            .set_selection_owner(window, clipboard, CURRENT_TIME)?
            .check()?;
        connection.flush()?;
        if connection.get_selection_owner(clipboard)?.reply()?.owner != window {
            return Err(anyhow!("could not own X11 clipboard"));
        }
        ticket.owned.store(true, Ordering::Release);
        let _ = ready.send(Ok(()));
        while !ticket.stopped.load(Ordering::Acquire) {
            match connection.poll_for_event()? {
                Some(Event::SelectionClear(_)) => break,
                Some(Event::SelectionRequest(request)) => {
                    let property = if request.property == NONE {
                        request.target
                    } else {
                        request.property
                    };
                    let connection = connection.clone();
                    let ticket = ticket.clone();
                    // TARGETS probes must never request the file payload.
                    if request.target == targets {
                        connection.change_property32(
                            PropMode::REPLACE,
                            request.requestor,
                            property,
                            AtomEnum::ATOM,
                            &[targets, uri, gnome],
                        )?;
                        notify(&*connection, request, property)?;
                    } else if request.target == uri || request.target == gnome {
                        let Some(reader) = Reader::acquire() else {
                            notify(&*connection, request, NONE)?;
                            continue;
                        };
                        std::thread::Builder::new()
                            .name("clipboard-file-paste".into())
                            .spawn(move || {
                                let _reader = reader;
                                let result = (|| -> Result<()> {
                                    let bytes = contents(
                                        &ticket,
                                        if request.target == uri { URI } else { GNOME },
                                    )?;
                                    connection
                                        .change_property8(
                                            PropMode::REPLACE,
                                            request.requestor,
                                            property,
                                            request.target,
                                            &bytes,
                                        )?
                                        .check()?;
                                    notify(&*connection, request, property)
                                })();
                                if let Err(error) = result {
                                    let _ = notify(&*connection, request, NONE);
                                    tracing::warn!(error = %error, "X11 deferred paste failed");
                                }
                            })?;
                    } else {
                        notify(&*connection, request, NONE)?;
                    }
                }
                _ => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        ticket.owned.store(false, Ordering::Release);
        ticket.cancel();
        connection.destroy_window(window)?.check()?;
        connection.flush()?;
        Ok(())
    }
    fn notify(
        connection: &x11rb::rust_connection::RustConnection,
        request: SelectionRequestEvent,
        property: Atom,
    ) -> Result<()> {
        connection.send_event(
            false,
            request.requestor,
            EventMask::NO_EVENT,
            SelectionNotifyEvent {
                response_type: SELECTION_NOTIFY_EVENT,
                sequence: 0,
                time: request.time,
                requestor: request.requestor,
                selection: request.selection,
                target: request.target,
                property,
            },
        )?;
        connection.flush()?;
        Ok(())
    }
}

mod wayland {
    use super::*;
    use std::os::fd::AsRawFd;
    use wayland_client::{
        globals::{registry_queue_init, GlobalListContents},
        protocol::{wl_registry, wl_seat},
        Connection, Dispatch, QueueHandle,
    };
    use wayland_protocols::ext::data_control::v1::client::{
        ext_data_control_device_v1 as ed, ext_data_control_manager_v1 as em,
        ext_data_control_offer_v1 as eo, ext_data_control_source_v1 as es,
    };
    use wayland_protocols_wlr::data_control::v1::client::{
        zwlr_data_control_device_v1 as wd, zwlr_data_control_manager_v1 as wm,
        zwlr_data_control_offer_v1 as wo, zwlr_data_control_source_v1 as ws,
    };
    struct State {
        ticket: Arc<Ticket>,
    }
    impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for State {
        fn event(
            _: &mut Self,
            _: &wl_registry::WlRegistry,
            _: wl_registry::Event,
            _: &GlobalListContents,
            _: &Connection,
            _: &QueueHandle<Self>,
        ) {
        }
    }
    wayland_client::delegate_noop!(State: ignore wl_seat::WlSeat);
    wayland_client::delegate_noop!(State: ignore em::ExtDataControlManagerV1);
    wayland_client::delegate_noop!(State: ignore wm::ZwlrDataControlManagerV1);
    wayland_client::delegate_noop!(State: ignore eo::ExtDataControlOfferV1);
    wayland_client::delegate_noop!(State: ignore wo::ZwlrDataControlOfferV1);
    impl Dispatch<ed::ExtDataControlDeviceV1, ()> for State {
        fn event(
            state: &mut Self,
            _: &ed::ExtDataControlDeviceV1,
            event: ed::Event,
            _: &(),
            _: &Connection,
            _: &QueueHandle<Self>,
        ) {
            match event {
                ed::Event::DataOffer { id } => id.destroy(),
                ed::Event::Finished => state.ticket.cancel(),
                _ => {}
            }
        }
        wayland_client::event_created_child!(State, ed::ExtDataControlDeviceV1, [0 => (eo::ExtDataControlOfferV1, ())]);
    }
    impl Dispatch<wd::ZwlrDataControlDeviceV1, ()> for State {
        fn event(
            state: &mut Self,
            _: &wd::ZwlrDataControlDeviceV1,
            event: wd::Event,
            _: &(),
            _: &Connection,
            _: &QueueHandle<Self>,
        ) {
            match event {
                wd::Event::DataOffer { id } => id.destroy(),
                wd::Event::Finished => state.ticket.cancel(),
                _ => {}
            }
        }
        wayland_client::event_created_child!(State, wd::ZwlrDataControlDeviceV1, [0 => (wo::ZwlrDataControlOfferV1, ())]);
    }
    fn serve(ticket: Arc<Ticket>, mime: String, fd: std::os::fd::OwnedFd) {
        if mime != URI && mime != GNOME {
            return;
        }
        let Some(reader) = Reader::acquire() else {
            return;
        };
        let _ = std::thread::Builder::new()
            .name("clipboard-file-paste".into())
            .spawn(move || {
                let _reader = reader;
                let result =
                    contents(&ticket, &mime).and_then(|bytes| write_pipe(&ticket, fd, &bytes));
                if let Err(error) = result {
                    tracing::warn!(error = %error, "Wayland deferred paste failed");
                }
            });
    }
    fn write_pipe(ticket: &Ticket, fd: std::os::fd::OwnedFd, mut bytes: &[u8]) -> Result<()> {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut pipe = std::fs::File::from(fd);
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !bytes.is_empty() {
            if ticket.stopped.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
                return Err(anyhow!(
                    "clipboard reader cancelled or stopped consuming data"
                ));
            }
            match pipe.write(bytes) {
                Ok(0) => return Err(anyhow!("clipboard pipe closed")),
                Ok(count) => bytes = &bytes[count..],
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
    impl Dispatch<es::ExtDataControlSourceV1, ()> for State {
        fn event(
            state: &mut Self,
            _: &es::ExtDataControlSourceV1,
            event: es::Event,
            _: &(),
            _: &Connection,
            _: &QueueHandle<Self>,
        ) {
            match event {
                es::Event::Send { mime_type, fd } => serve(state.ticket.clone(), mime_type, fd),
                es::Event::Cancelled => state.ticket.cancel(),
                _ => {}
            }
        }
    }
    impl Dispatch<ws::ZwlrDataControlSourceV1, ()> for State {
        fn event(
            state: &mut Self,
            _: &ws::ZwlrDataControlSourceV1,
            event: ws::Event,
            _: &(),
            _: &Connection,
            _: &QueueHandle<Self>,
        ) {
            match event {
                ws::Event::Send { mime_type, fd } => serve(state.ticket.clone(), mime_type, fd),
                ws::Event::Cancelled => state.ticket.cancel(),
                _ => {}
            }
        }
    }
    pub(super) fn run(ticket: Arc<Ticket>, ready: &SyncSender<Result<(), String>>) -> Result<()> {
        let connection = Connection::connect_to_env()?;
        let (globals, mut queue) = registry_queue_init::<State>(&connection)?;
        let qh = queue.handle();
        let seat: wl_seat::WlSeat = globals.bind(&qh, 1..=1, ())?;
        let mut state = State {
            ticket: ticket.clone(),
        };
        // Keep every proxy alive until ownership ends.
        let mut ext = None;
        let mut wlr = None;
        if let Ok(manager) = globals.bind::<em::ExtDataControlManagerV1, _, _>(&qh, 1..=1, ()) {
            let source = manager.create_data_source(&qh, ());
            source.offer(URI.into());
            source.offer(GNOME.into());
            let device = manager.get_data_device(&seat, &qh, ());
            device.set_selection(Some(&source));
            ext = Some((manager, source, device));
        } else {
            let manager: wm::ZwlrDataControlManagerV1 =
                globals.bind(&qh, 1..=2, ()).map_err(|e| {
                    anyhow!("compositor lacks ext/wlr data-control for deferred paste: {e}")
                })?;
            let source = manager.create_data_source(&qh, ());
            source.offer(URI.into());
            source.offer(GNOME.into());
            let device = manager.get_data_device(&seat, &qh, ());
            device.set_selection(Some(&source));
            wlr = Some((manager, source, device));
        }
        queue.roundtrip(&mut state)?;
        if ticket.stopped.load(Ordering::Acquire) {
            return Err(anyhow!("Wayland rejected clipboard ownership"));
        }
        ticket.owned.store(true, Ordering::Release);
        let _ = ready.send(Ok(()));
        while !ticket.stopped.load(Ordering::Acquire) {
            queue.dispatch_pending(&mut state)?;
            connection.flush()?;
            if let Some(guard) = queue.prepare_read() {
                let mut fd = libc::pollfd {
                    fd: connection.backend().poll_fd().as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let result = unsafe { libc::poll(&mut fd, 1, 20) };
                if result > 0 {
                    guard.read()?;
                } else if result < 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
        }
        ticket.owned.store(false, Ordering::Release);
        if let Some((manager, source, device)) = ext {
            source.destroy();
            device.destroy();
            manager.destroy();
        }
        if let Some((manager, source, device)) = wlr {
            source.destroy();
            device.destroy();
            manager.destroy();
        }
        connection.flush()?;
        Ok(())
    }
}
