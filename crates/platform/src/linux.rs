//! Linux adapter: evdev capture/injection, X11 pointer lookup, and the
//! compositor-mediated Wayland InputCapture portal.
//!
//! Kept intentionally compact. The Python project's `linux_input.py`
//! already documents the permission model (`input`, `uinput` groups,
//! `/dev/input/event*`, `/dev/uinput`). The same caveats apply here.

#![cfg(target_os = "linux")]

use super::{KeyCapture, KeyInjector, MouseActivity, MouseEdge, MouseWatcher, Result};
use anyhow::{anyhow, Context};
use ashpd::desktop::input_capture::{Barrier, BarrierID, Capabilities, InputCapture, Region};
use ashpd::desktop::remote_desktop::{DeviceType, RemoteDesktop};
use ashpd::desktop::PersistMode;
use futures_util::StreamExt;
use kbshare_core::keycode::Key;
use kbshare_core::protocol::KeyAction;
use once_cell::sync::Lazy;
use parking_lot::{Condvar, Mutex};
use reis::{
    ei,
    event::{DeviceCapability, EiEvent},
};
use std::collections::{HashMap, HashSet};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::sync::mpsc as tokio_mpsc;

use evdev::{AttributeSet, Device, EventType, InputEventKind, Key as EvKey};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::ConnectionExt;
use x11rb::rust_connection::RustConnection;

const VIRTUAL_KEYBOARD_NAME: &str = "kbshare-virtual-keyboard";

type SharedKeyCallback = Arc<Mutex<Box<dyn FnMut(KeyAction, Key) + Send>>>;
type SharedMouseCallback = Arc<Mutex<Box<dyn FnMut(MouseActivity) + Send>>>;

struct WaylandInputHub {
    forwarding: Arc<AtomicBool>,
    key_callback: Mutex<Option<SharedKeyCallback>>,
    mouse_callback: Mutex<Option<SharedMouseCallback>>,
    shutdown: Arc<AtomicBool>,
    engine_shutdown: Arc<AtomicBool>,
    started: AtomicBool,
    initialization: Mutex<Option<std::result::Result<(), String>>>,
    initialization_changed: Condvar,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl WaylandInputHub {
    fn new(engine_shutdown: Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            forwarding: Arc::new(AtomicBool::new(false)),
            key_callback: Mutex::new(None),
            mouse_callback: Mutex::new(None),
            shutdown: Arc::new(AtomicBool::new(false)),
            engine_shutdown,
            started: AtomicBool::new(false),
            initialization: Mutex::new(None),
            initialization_changed: Condvar::new(),
            handle: Mutex::new(None),
        })
    }

    fn ensure_started(self: &Arc<Self>) -> Result<()> {
        if self
            .started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let hub = self.clone();
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let handle = thread::spawn(move || run_wayland_input_thread(hub, ready_tx));
            *self.handle.lock() = Some(handle);
            let result = ready_rx
                .recv()
                .map_err(|_| "Wayland InputCapture thread stopped during setup".to_string())
                .and_then(|result| result);
            *self.initialization.lock() = Some(result.clone());
            self.initialization_changed.notify_all();
        }

        let mut initialization = self.initialization.lock();
        while initialization.is_none() {
            self.initialization_changed.wait(&mut initialization);
        }
        initialization
            .as_ref()
            .expect("initialization checked")
            .clone()
            .map_err(anyhow::Error::msg)
    }

    fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.lock().take() {
            let _ = handle.join();
        }
    }
}

static WAYLAND_INPUT_HUB: Lazy<Mutex<Weak<WaylandInputHub>>> =
    Lazy::new(|| Mutex::new(Weak::new()));

fn shared_wayland_input_hub(engine_shutdown: Arc<AtomicBool>) -> Arc<WaylandInputHub> {
    let mut weak = WAYLAND_INPUT_HUB.lock();
    if let Some(hub) = weak.upgrade() {
        return hub;
    }
    let hub = WaylandInputHub::new(engine_shutdown);
    *weak = Arc::downgrade(&hub);
    hub
}

fn set_nonblocking(device: &Device) -> Result<()> {
    let fd = device.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("read evdev flags");
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error()).context("set evdev nonblocking");
    }
    Ok(())
}

pub struct LinuxKeyCapture {
    forwarding: Arc<AtomicBool>,
    portal: Option<Arc<WaylandInputHub>>,
    engine_shutdown: Arc<AtomicBool>,
    devices: Vec<Device>,
    shutdown: Arc<AtomicBool>,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl LinuxKeyCapture {
    pub fn new() -> Result<Self> {
        Self::new_with_shutdown(Arc::new(AtomicBool::new(false)))
    }

    pub fn new_with_shutdown(engine_shutdown: Arc<AtomicBool>) -> Result<Self> {
        let portal =
            is_wayland_session().then(|| shared_wayland_input_hub(engine_shutdown.clone()));
        // Auto-discover keyboard-capable devices.
        let mut devices = Vec::new();
        for (_, dev) in evdev::enumerate() {
            if is_keyboard(&dev) {
                match set_nonblocking(&dev) {
                    Ok(()) => devices.push(dev),
                    Err(error) => {
                        tracing::warn!(error = %error, "skipping inaccessible evdev keyboard")
                    }
                }
            }
        }
        if devices.is_empty() && portal.is_none() {
            return Err(anyhow!(
                "no keyboard devices found; ensure the user has read access to /dev/input/event*"
            ));
        }
        let forwarding = portal
            .as_ref()
            .map(|portal| portal.forwarding.clone())
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        Ok(Self {
            forwarding,
            portal,
            engine_shutdown,
            devices,
            shutdown: Arc::new(AtomicBool::new(false)),
            handles: Mutex::new(Vec::new()),
        })
    }
}

fn is_keyboard(dev: &Device) -> bool {
    if is_own_virtual_keyboard_name(dev.name()) {
        return false;
    }
    if let Some(keys) = dev.supported_keys() {
        keys.contains(EvKey::KEY_A) && keys.contains(EvKey::KEY_SPACE)
    } else {
        false
    }
}

fn is_own_virtual_keyboard_name(name: Option<&str>) -> bool {
    name.is_some_and(|name| name == VIRTUAL_KEYBOARD_NAME)
}

fn key_action(value: i32) -> Option<KeyAction> {
    match value {
        0 => Some(KeyAction::Release),
        1 | 2 => Some(KeyAction::Press),
        _ => None,
    }
}

impl KeyCapture for LinuxKeyCapture {
    fn start(&mut self, on_event: Box<dyn FnMut(KeyAction, Key) + Send>) -> Result<()> {
        let on_event = Arc::new(Mutex::new(on_event));
        let mut portal_error = None;
        if let Some(portal) = &self.portal {
            *portal.key_callback.lock() = Some(on_event.clone());
            match portal.ensure_started() {
                Ok(()) => return Ok(()),
                Err(error) => {
                    if self.engine_shutdown.load(Ordering::Relaxed) {
                        return Err(error);
                    }
                    tracing::warn!(
                        error = %error,
                        "Wayland keyboard capture unavailable; trying evdev fallback"
                    );
                    portal_error = Some(error);
                    *portal.key_callback.lock() = None;
                }
            }
        }
        if self.devices.is_empty() {
            return Err(match portal_error {
                Some(error) => anyhow!(
                    "no Linux keyboard capture backend is available; \
                     Wayland InputCapture/libei: {error:#}; \
                     evdev fallback: no readable keyboard in /dev/input/event*"
                ),
                None => anyhow!(
                    "no keyboard devices found; ensure the user has read access to /dev/input/event*"
                ),
            });
        }
        let shutdown = self.shutdown.clone();
        let forwarding = self.forwarding.clone();
        let devices = std::mem::take(&mut self.devices);

        for mut dev in devices {
            let on_event = on_event.clone();
            let shutdown = shutdown.clone();
            let forwarding = forwarding.clone();
            let h = thread::spawn(move || {
                let mut grabbed = false;
                let mut grab_error_reported = false;
                while !shutdown.load(Ordering::Relaxed) {
                    // Adjust grab state to match current forwarding flag.
                    let want = forwarding.load(Ordering::Relaxed);
                    if want != grabbed {
                        let result = if want { dev.grab() } else { dev.ungrab() };
                        match result {
                            Ok(()) => {
                                grabbed = want;
                                grab_error_reported = false;
                            }
                            Err(error) => {
                                // Do not update `grabbed`: a transient failure must
                                // be retried, otherwise local keys may leak while the
                                // capture thread believes they are being swallowed
                                // (or remain swallowed after returning to local mode).
                                if !grab_error_reported {
                                    tracing::warn!(
                                        error = %error,
                                        device = dev.name().unwrap_or("unnamed"),
                                        requested = if want { "grab" } else { "ungrab" },
                                        "failed to update evdev keyboard grab; will retry"
                                    );
                                    grab_error_reported = true;
                                }
                            }
                        }
                    } else {
                        grab_error_reported = false;
                    }
                    match dev.fetch_events() {
                        Ok(events) => {
                            for ev in events {
                                if ev.event_type() != EventType::KEY {
                                    continue;
                                }
                                let Some(action) = key_action(ev.value()) else {
                                    continue;
                                };
                                if let InputEventKind::Key(k) = ev.kind() {
                                    let logical = Key::new(k.code());
                                    if forwarding.load(Ordering::Relaxed) {
                                        tracing::info!(
                                            backend = "evdev",
                                            ?action,
                                            keycode = logical.code(),
                                            "captured Linux key for forwarding"
                                        );
                                    }
                                    (on_event.lock())(action, logical);
                                }
                            }
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(10));
                        }
                    }
                }
                if grabbed {
                    let _ = dev.ungrab();
                }
            });
            self.handles.lock().push(h);
        }
        Ok(())
    }
    fn forwarding_flag(&self) -> Arc<AtomicBool> {
        self.forwarding.clone()
    }
    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        for h in self.handles.lock().drain(..) {
            let _ = h.join();
        }
        if let Some(portal) = &self.portal {
            *portal.key_callback.lock() = None;
            portal.stop();
        }
    }
}

impl Drop for LinuxKeyCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct LinuxMouseWatcher {
    portal: Option<Arc<WaylandInputHub>>,
    shutdown: Arc<AtomicBool>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    devices: Vec<Device>,
}

impl LinuxMouseWatcher {
    pub fn new() -> Result<Self> {
        let portal = is_wayland_session()
            .then(|| shared_wayland_input_hub(Arc::new(AtomicBool::new(false))));
        let mut devices = Vec::new();
        for (_, dev) in evdev::enumerate() {
            if is_mouse(&dev) {
                match set_nonblocking(&dev) {
                    Ok(()) => devices.push(dev),
                    Err(error) => {
                        tracing::warn!(error = %error, "skipping inaccessible evdev mouse")
                    }
                }
            }
        }
        if devices.is_empty() && portal.is_none() {
            return Err(anyhow!("no mouse devices found"));
        }
        Ok(Self {
            portal,
            shutdown: Arc::new(AtomicBool::new(false)),
            handles: Mutex::new(Vec::new()),
            devices,
        })
    }
}

fn is_wayland_session() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var("XDG_SESSION_TYPE").is_ok_and(|value| value == "wayland")
}

impl MouseEdge {
    fn activity(self) -> MouseActivity {
        match self {
            Self::Left => MouseActivity {
                edge: Some(self),
                x: Some(0),
                dx: Some(-1),
                desktop_left: Some(0),
                ..MouseActivity::UNKNOWN
            },
            Self::Right => MouseActivity {
                edge: Some(self),
                x: Some(0),
                dx: Some(1),
                desktop_right: Some(1),
                ..MouseActivity::UNKNOWN
            },
            Self::Top => MouseActivity {
                edge: Some(self),
                y: Some(0),
                dy: Some(-1),
                desktop_top: Some(0),
                ..MouseActivity::UNKNOWN
            },
            Self::Bottom => MouseActivity {
                edge: Some(self),
                y: Some(0),
                dy: Some(1),
                desktop_bottom: Some(1),
                ..MouseActivity::UNKNOWN
            },
        }
    }

    fn release_position(self, cursor: Option<(f32, f32)>) -> Option<(f64, f64)> {
        let (x, y) = cursor?;
        let (x, y) = (f64::from(x), f64::from(y));
        Some(match self {
            Self::Left => (x + 1.0, y),
            Self::Right => (x - 1.0, y),
            Self::Top => (x, y + 1.0),
            Self::Bottom => (x, y - 1.0),
        })
    }

    fn is_inward_motion(self, dx: f32, dy: f32) -> bool {
        match self {
            Self::Left => dx > 0.0,
            Self::Right => dx < 0.0,
            Self::Top => dy > 0.0,
            Self::Bottom => dy < 0.0,
        }
    }
}

fn portal_barriers(regions: &[Region]) -> (Vec<Barrier>, HashMap<BarrierID, MouseEdge>) {
    let mut barriers = Vec::with_capacity(regions.len() * 4);
    let mut edges = HashMap::with_capacity(regions.len() * 4);
    let mut next_id = 1u32;

    for region in regions {
        let x = region.x_offset();
        let y = region.y_offset();
        let width = region.width() as i32;
        let height = region.height() as i32;
        let candidates = [
            (MouseEdge::Left, (x, y, x, y + height - 1)),
            (MouseEdge::Right, (x + width, y, x + width, y + height - 1)),
            (MouseEdge::Top, (x, y, x + width - 1, y)),
            (
                MouseEdge::Bottom,
                (x, y + height, x + width - 1, y + height),
            ),
        ];
        for (edge, position) in candidates {
            let id = next_id;
            barriers.push(Barrier::new(id, position));
            edges.insert(id, edge);
            next_id = next_id.saturating_add(1);
        }
    }

    (barriers, edges)
}

async fn configure_portal_barriers(
    portal: &InputCapture<'_>,
    session: &ashpd::desktop::Session<'_, InputCapture<'_>>,
) -> Result<HashMap<BarrierID, MouseEdge>> {
    let zones = portal
        .zones(session)
        .await
        .context("request Wayland input-capture zones")?
        .response()
        .context("read Wayland input-capture zones")?;
    let (barriers, mut edges) = portal_barriers(zones.regions());
    let response = portal
        .set_pointer_barriers(session, &barriers, zones.zone_set())
        .await
        .context("request Wayland pointer barriers")?
        .response()
        .context("set Wayland pointer barriers")?;
    let failed = response
        .failed_barriers()
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    edges.retain(|id, _| !failed.contains(id));
    if edges.is_empty() {
        return Err(anyhow!(
            "the Wayland compositor rejected every requested desktop-edge barrier"
        ));
    }
    tracing::info!(
        accepted = edges.len(),
        rejected = failed.len(),
        "Wayland InputCapture pointer barriers configured"
    );
    Ok(edges)
}

struct ActiveCapture {
    edge: MouseEdge,
    activation_id: Option<u32>,
    release_position: Option<(f64, f64)>,
}

async fn run_wayland_input_portal(
    hub: Arc<WaylandInputHub>,
    ready: &mut Option<SyncSender<std::result::Result<(), String>>>,
) -> Result<()> {
    let portal = InputCapture::new()
        .await
        .context("connect to the Wayland InputCapture portal")?;
    let (session, capabilities) = portal
        .create_session(
            &ashpd::WindowIdentifier::default(),
            Capabilities::Pointer | Capabilities::Keyboard,
        )
        .await
        .context("create Wayland input-capture session")?;
    if !capabilities.contains(Capabilities::Pointer)
        || !capabilities.contains(Capabilities::Keyboard)
    {
        return Err(anyhow!(
            "the Wayland InputCapture portal did not grant pointer and keyboard capture"
        ));
    }

    let fd = portal
        .connect_to_eis(&session)
        .await
        .context("connect Wayland InputCapture session to EIS")?;
    let stream = UnixStream::from(fd);
    stream
        .set_nonblocking(true)
        .context("set EIS stream nonblocking")?;
    let context = ei::Context::new(stream).context("create EIS receiver")?;
    context.flush().context("flush EIS receiver")?;
    let (_connection, mut ei_events) = context
        .handshake_tokio("kbshare", ei::handshake::ContextType::Receiver)
        .await
        .context("complete EIS receiver handshake")?;

    let mut edges = configure_portal_barriers(&portal, &session).await?;
    let mut activations = portal
        .receive_activated()
        .await
        .context("subscribe to Wayland barrier activation")?;
    let mut zones_changed = portal
        .receive_zones_changed()
        .await
        .context("subscribe to Wayland zone changes")?;
    portal
        .enable(&session)
        .await
        .context("enable Wayland input capture")?;
    if let Some(ready) = ready.take() {
        let _ = ready.send(Ok(()));
    }
    tracing::info!(
        "Wayland keyboard capture and Flow edge detection are active through InputCapture/libei"
    );

    let mut active_capture: Option<ActiveCapture> = None;
    let mut shutdown_poll = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            _ = shutdown_poll.tick() => {
                if active_capture.is_some() && !hub.forwarding.load(Ordering::Relaxed) {
                    let active = active_capture.take().expect("active capture checked");
                    portal
                        .release(&session, active.activation_id, active.release_position)
                        .await
                        .context("release Wayland keyboard capture")?;
                }
                if hub.shutdown.load(Ordering::Relaxed)
                    || hub.engine_shutdown.load(Ordering::Relaxed)
                {
                    if let Some(active) = active_capture.take() {
                        let _ = portal
                            .release(&session, active.activation_id, active.release_position)
                            .await;
                    }
                    let _ = portal.disable(&session).await;
                    return Ok(());
                }
            }
            activated = activations.next() => {
                let Some(activated) = activated else {
                    return Err(anyhow!("Wayland InputCapture activation stream closed"));
                };
                let edge = activated
                    .barrier_id()
                    .and_then(|id| edges.get(&id).copied());
                if let Some(edge) = edge {
                    if let Some(callback) = hub.mouse_callback.lock().clone() {
                        (callback.lock())(edge.activity());
                    }
                    let active = ActiveCapture {
                        edge,
                        activation_id: activated.activation_id(),
                        release_position: edge.release_position(activated.cursor_position()),
                    };
                    if hub.forwarding.load(Ordering::Relaxed) {
                        active_capture = Some(active);
                    } else {
                        portal
                            .release(&session, active.activation_id, active.release_position)
                            .await
                            .context("release unused Wayland input capture")?;
                    }
                } else {
                    tracing::warn!("Wayland InputCapture activated without a known barrier");
                    portal
                        .release(&session, activated.activation_id(), None)
                        .await
                        .context("release unknown Wayland input capture")?;
                }
            }
            changed = zones_changed.next() => {
                let Some(_changed) = changed else {
                    return Err(anyhow!("Wayland InputCapture zone-change stream closed"));
                };
                // Explicit Disable also works around portal implementations
                // that do not suspend the session from SetPointerBarriers.
                active_capture = None;
                portal.disable(&session).await.context("disable changed Wayland zones")?;
                edges = configure_portal_barriers(&portal, &session).await?;
                portal.enable(&session).await.context("re-enable changed Wayland zones")?;
            }
            event = ei_events.next() => {
                let Some(event) = event else {
                    return Err(anyhow!("EIS input-capture stream closed"));
                };
                match event.context("read captured EIS event")? {
                    EiEvent::SeatAdded(event) => {
                        event.seat.bind_capabilities(
                            DeviceCapability::Keyboard
                                | DeviceCapability::Pointer
                                | DeviceCapability::PointerAbsolute
                                | DeviceCapability::Scroll
                                | DeviceCapability::Button,
                        );
                        context.flush().context("bind EIS input capabilities")?;
                    }
                    EiEvent::KeyboardKey(event)
                        if hub.forwarding.load(Ordering::Relaxed) =>
                    {
                        let Ok(code) = u16::try_from(event.key) else {
                            tracing::warn!(keycode = event.key, "ignoring oversized EIS keycode");
                            continue;
                        };
                        let action = match event.state {
                            ei::keyboard::KeyState::Press => KeyAction::Press,
                            ei::keyboard::KeyState::Released => KeyAction::Release,
                        };
                        if let Some(callback) = hub.key_callback.lock().clone() {
                            tracing::info!(
                                backend = "wayland-input-capture",
                                ?action,
                                keycode = code,
                                "captured Linux key for forwarding"
                            );
                            (callback.lock())(action, Key::new(code));
                        }
                    }
                    EiEvent::PointerMotion(event)
                        if active_capture
                            .as_ref()
                            .is_some_and(|active| {
                                active.edge.is_inward_motion(event.dx, event.dy)
                            }) =>
                    {
                        if let Some(callback) = hub.mouse_callback.lock().clone() {
                            (callback.lock())(MouseActivity::UNKNOWN);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn wait_for_shutdown(shutdown: Arc<AtomicBool>) {
    let mut poll = tokio::time::interval(Duration::from_millis(100));
    while !shutdown.load(Ordering::Relaxed) {
        poll.tick().await;
    }
}

async fn run_wayland_input(
    hub: Arc<WaylandInputHub>,
    ready_tx: SyncSender<std::result::Result<(), String>>,
) {
    let mut ready = Some(ready_tx);
    let result = tokio::select! {
        result = run_wayland_input_portal(hub.clone(), &mut ready) => result,
        _ = wait_for_shutdown(hub.shutdown.clone()) => {
            Err(anyhow!("Wayland InputCapture setup was cancelled"))
        }
        _ = wait_for_shutdown(hub.engine_shutdown.clone()) => {
            Err(anyhow!("Wayland InputCapture setup was cancelled"))
        }
    };
    if let Some(ready) = ready.take() {
        let message = match result {
            Ok(()) => "Wayland InputCapture ended during setup".to_string(),
            Err(error) => format!("{error:#}"),
        };
        let _ = ready.send(Err(message));
    } else if let Err(error) = result {
        if hub.shutdown.load(Ordering::Relaxed) || hub.engine_shutdown.load(Ordering::Relaxed) {
            tracing::info!("Wayland InputCapture session stopped during application shutdown");
        } else {
            tracing::error!(error = %error, "Wayland InputCapture session ended");
        }
    }
}

fn run_wayland_input_thread(
    hub: Arc<WaylandInputHub>,
    ready_tx: SyncSender<std::result::Result<(), String>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .context("create Wayland InputCapture runtime")
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready_tx.send(Err(format!("{error:#}")));
            return;
        }
    };
    runtime.block_on(run_wayland_input(hub, ready_tx));
}

fn is_mouse(dev: &Device) -> bool {
    if let Some(rel) = dev.supported_relative_axes() {
        if rel.contains(evdev::RelativeAxisType::REL_X) {
            return true;
        }
    }
    false
}

struct X11Pointer {
    connection: RustConnection,
    root: u32,
    desktop_right: i32,
    desktop_bottom: i32,
}

impl X11Pointer {
    fn connect() -> Result<Self> {
        let (connection, screen_number) =
            x11rb::connect(None).context("connect to X11 display for pointer tracking")?;
        let screen = &connection.setup().roots[screen_number];
        Ok(Self {
            root: screen.root,
            desktop_right: i32::from(screen.width_in_pixels),
            desktop_bottom: i32::from(screen.height_in_pixels),
            connection,
        })
    }

    fn activity(&self, dx: i32, dy: i32) -> Result<MouseActivity> {
        let pointer = self
            .connection
            .query_pointer(self.root)
            .context("query X11 pointer")?
            .reply()
            .context("read X11 pointer reply")?;
        Ok(MouseActivity {
            edge: None,
            x: Some(i32::from(pointer.root_x)),
            y: Some(i32::from(pointer.root_y)),
            dx: Some(dx),
            dy: Some(dy),
            desktop_left: Some(0),
            desktop_right: Some(self.desktop_right),
            desktop_top: Some(0),
            desktop_bottom: Some(self.desktop_bottom),
        })
    }
}

impl MouseWatcher for LinuxMouseWatcher {
    fn start(&mut self, on_activity: Box<dyn FnMut(MouseActivity) + Send>) -> Result<()> {
        let on_activity = Arc::new(Mutex::new(on_activity));
        let shutdown = self.shutdown.clone();
        let mut portal_error = None;
        if let Some(portal) = &self.portal {
            *portal.mouse_callback.lock() = Some(on_activity.clone());
            if let Err(error) = portal.ensure_started() {
                tracing::warn!(
                    error = %error,
                    "Wayland pointer barriers unavailable; trying X11/XWayland fallback"
                );
                portal_error = Some(error);
                *portal.mouse_callback.lock() = None;
            }
        }
        if self.devices.is_empty() && portal_error.is_some() {
            return Err(anyhow!(
                "no Linux mouse watcher backend is available; \
                 Wayland InputCapture: {:#}; \
                 evdev/X11 fallback: no readable mouse in /dev/input/event*",
                portal_error.expect("portal error checked")
            ));
        }
        let devices = std::mem::take(&mut self.devices);
        for mut dev in devices {
            let on_activity = on_activity.clone();
            let shutdown = shutdown.clone();
            let h = thread::spawn(move || {
                let pointer = X11Pointer::connect().map_err(|error| {
                    tracing::warn!(
                        error = %error,
                        "global pointer position unavailable; Flow edge switching requires X11/XWayland"
                    );
                });
                let pointer = pointer.ok();
                while !shutdown.load(Ordering::Relaxed) {
                    match dev.fetch_events() {
                        Ok(events) => {
                            let mut dx = 0i32;
                            let mut dy = 0i32;
                            for event in events {
                                match event.kind() {
                                    InputEventKind::RelAxis(evdev::RelativeAxisType::REL_X) => {
                                        dx = dx.saturating_add(event.value())
                                    }
                                    InputEventKind::RelAxis(evdev::RelativeAxisType::REL_Y) => {
                                        dy = dy.saturating_add(event.value())
                                    }
                                    InputEventKind::Synchronization(_) if dx != 0 || dy != 0 => {
                                        let activity = pointer
                                            .as_ref()
                                            .and_then(|pointer| pointer.activity(dx, dy).ok())
                                            .unwrap_or(MouseActivity {
                                                dx: Some(dx),
                                                dy: Some(dy),
                                                ..MouseActivity::UNKNOWN
                                            });
                                        (on_activity.lock())(activity);
                                        dx = 0;
                                        dy = 0;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Err(_) => thread::sleep(Duration::from_millis(10)),
                    }
                }
            });
            self.handles.lock().push(h);
        }
        Ok(())
    }
    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        for h in self.handles.lock().drain(..) {
            let _ = h.join();
        }
        if let Some(portal) = &self.portal {
            *portal.mouse_callback.lock() = None;
        }
    }
}

impl Drop for LinuxMouseWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

struct UinputKeyInjector {
    device: evdev::uinput::VirtualDevice,
}

impl UinputKeyInjector {
    pub fn new() -> Result<Self> {
        let mut keys = AttributeSet::<EvKey>::new();
        for code in 1u16..=0x2ff {
            keys.insert(EvKey::new(code));
        }
        let device = evdev::uinput::VirtualDeviceBuilder::new()
            .context("build uinput device")?
            .name(VIRTUAL_KEYBOARD_NAME)
            .with_keys(&keys)
            .context("attach keys")?
            .build()
            .context("build uinput")?;
        Ok(Self { device })
    }
}

impl KeyInjector for UinputKeyInjector {
    fn press(&mut self, key: Key) -> Result<()> {
        let ev = evdev::InputEvent::new(EventType::KEY, key.code(), 1);
        self.device.emit(&[ev]).context("emit press")?;
        Ok(())
    }
    fn release(&mut self, key: Key) -> Result<()> {
        let ev = evdev::InputEvent::new(EventType::KEY, key.code(), 0);
        self.device.emit(&[ev]).context("emit release")?;
        Ok(())
    }
}

enum PortalInjectCommand {
    Key {
        action: KeyAction,
        key: Key,
        done: SyncSender<Result<()>>,
    },
    Shutdown,
}

struct PortalKeyInjector {
    commands: tokio_mpsc::Sender<PortalInjectCommand>,
    handle: Option<JoinHandle<()>>,
}

impl PortalKeyInjector {
    fn new(shutdown: Arc<AtomicBool>) -> Result<Self> {
        let (commands, command_rx) = tokio_mpsc::channel(64);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let handle = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .context("create Wayland injection runtime")
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            runtime.block_on(run_portal_key_injector(command_rx, ready_tx, shutdown));
        });

        match ready_rx
            .recv()
            .context("Wayland injection thread stopped during initialization")?
        {
            Ok(()) => Ok(Self {
                commands,
                handle: Some(handle),
            }),
            Err(error) => {
                let _ = handle.join();
                Err(error)
            }
        }
    }

    fn inject(&self, action: KeyAction, key: Key) -> Result<()> {
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        self.commands
            .blocking_send(PortalInjectCommand::Key {
                action,
                key,
                done: done_tx,
            })
            .context("Wayland injection session is no longer running")?;
        done_rx
            .recv()
            .context("Wayland injection session stopped before acknowledging the key")?
    }
}

impl Drop for PortalKeyInjector {
    fn drop(&mut self) {
        let _ = self.commands.blocking_send(PortalInjectCommand::Shutdown);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn monotonic_time_us() -> u64 {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timestamp) } != 0 {
        return 0;
    }
    u64::try_from(timestamp.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000)
        .saturating_add(u64::try_from(timestamp.tv_nsec).unwrap_or(0) / 1_000)
}

fn portal_key_state(action: KeyAction) -> ei::keyboard::KeyState {
    match action {
        KeyAction::Press => ei::keyboard::KeyState::Press,
        KeyAction::Release => ei::keyboard::KeyState::Released,
    }
}

fn send_portal_key(
    connection: &reis::event::Connection,
    device: Option<&reis::event::Device>,
    active: bool,
    action: KeyAction,
    key: Key,
) -> Result<()> {
    let device = device.ok_or_else(|| anyhow!("no Wayland EIS keyboard device is available"))?;
    if !active {
        return Err(anyhow!("the Wayland EIS keyboard device is paused"));
    }
    let keyboard = device
        .interface::<ei::Keyboard>()
        .ok_or_else(|| anyhow!("Wayland EIS device has no keyboard interface"))?;
    keyboard.key(u32::from(key.code()), portal_key_state(action));
    device
        .device()
        .frame(connection.serial(), monotonic_time_us());
    connection.flush().context("flush Wayland EIS key event")?;
    Ok(())
}

fn release_portal_keys(
    connection: &reis::event::Connection,
    device: Option<&reis::event::Device>,
    pressed: &mut HashSet<Key>,
) -> Result<()> {
    if pressed.is_empty() {
        return Ok(());
    }
    let device = device.ok_or_else(|| anyhow!("no Wayland EIS keyboard device is available"))?;
    let keyboard = device
        .interface::<ei::Keyboard>()
        .ok_or_else(|| anyhow!("Wayland EIS device has no keyboard interface"))?;
    for key in pressed.drain() {
        keyboard.key(u32::from(key.code()), ei::keyboard::KeyState::Released);
    }
    device
        .device()
        .frame(connection.serial(), monotonic_time_us());
    connection
        .flush()
        .context("flush Wayland EIS key releases")?;
    Ok(())
}

async fn portal_key_injector_main(
    mut commands: tokio_mpsc::Receiver<PortalInjectCommand>,
    ready: &mut Option<SyncSender<Result<()>>>,
) -> Result<()> {
    let portal = RemoteDesktop::new()
        .await
        .context("connect to the Wayland RemoteDesktop portal")?;
    let available = portal
        .available_device_types()
        .await
        .context("query Wayland remote-control device types")?;
    if !available.contains(DeviceType::Keyboard) {
        return Err(anyhow!(
            "the Wayland RemoteDesktop portal does not support keyboard control"
        ));
    }

    let session = portal
        .create_session()
        .await
        .context("create Wayland remote-desktop session")?;
    portal
        .select_devices(
            &session,
            DeviceType::Keyboard.into(),
            None,
            PersistMode::Application,
        )
        .await
        .context("request Wayland keyboard control")?
        .response()
        .context("select Wayland keyboard control")?;
    let selected = portal
        .start(&session, &ashpd::WindowIdentifier::default())
        .await
        .context("start Wayland remote-desktop session")?
        .response()
        .context("authorize Wayland remote-desktop session")?;
    if !selected.devices().contains(DeviceType::Keyboard) {
        return Err(anyhow!(
            "Wayland remote-desktop permission did not include keyboard control"
        ));
    }

    let fd = portal
        .connect_to_eis(&session)
        .await
        .context("connect Wayland remote-desktop session to EIS")?;
    let stream = UnixStream::from(fd);
    stream
        .set_nonblocking(true)
        .context("set Wayland injection EIS stream nonblocking")?;
    let context = ei::Context::new(stream).context("create Wayland EIS sender")?;
    context.flush().context("flush Wayland EIS sender")?;
    let (connection, mut events) = context
        .handshake_tokio("kbshare", ei::handshake::ContextType::Sender)
        .await
        .context("complete Wayland EIS sender handshake")?;

    let mut keyboard_device: Option<reis::event::Device> = None;
    let mut active = false;
    let mut sequence = 1u32;
    let mut pressed = HashSet::new();

    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(PortalInjectCommand::Key { action, key, done }) => {
                        let result = send_portal_key(
                            &connection,
                            keyboard_device.as_ref(),
                            active,
                            action,
                            key,
                        );
                        if result.is_ok() {
                            match action {
                                KeyAction::Press => {
                                    pressed.insert(key);
                                }
                                KeyAction::Release => {
                                    pressed.remove(&key);
                                }
                            }
                        }
                        let _ = done.send(result);
                    }
                    Some(PortalInjectCommand::Shutdown) | None => {
                        if active {
                            if let Some(device) = keyboard_device.as_ref() {
                                let _ = release_portal_keys(
                                    &connection,
                                    Some(device),
                                    &mut pressed,
                                );
                                device.device().stop_emulating(connection.serial());
                                let _ = connection.flush();
                            }
                        }
                        let _ = session.close().await;
                        return Ok(());
                    }
                }
            }
            event = events.next() => {
                let Some(event) = event else {
                    return Err(anyhow!("Wayland injection EIS stream closed"));
                };
                match event.context("read Wayland injection EIS event")? {
                    EiEvent::SeatAdded(event) => {
                        event
                            .seat
                            .bind_capabilities(DeviceCapability::Keyboard.into());
                        connection.flush().context("bind Wayland EIS keyboard capability")?;
                    }
                    EiEvent::DeviceAdded(event)
                        if event.device.device_type() == ei::device::DeviceType::Virtual
                            && event.device.has_capability(DeviceCapability::Keyboard) =>
                    {
                        if event.device.device().version() >= 3 {
                            event.device.device().ready();
                            connection.flush().context("ready Wayland EIS keyboard device")?;
                        }
                        keyboard_device = Some(event.device);
                    }
                    EiEvent::DeviceResumed(event)
                        if keyboard_device.as_ref() == Some(&event.device) =>
                    {
                        event
                            .device
                            .device()
                            .start_emulating(connection.serial(), sequence);
                        sequence = sequence.wrapping_add(1).max(1);
                        connection.flush().context("start Wayland keyboard emulation")?;
                        active = true;
                        if let Some(ready) = ready.take() {
                            let _ = ready.send(Ok(()));
                            tracing::info!(
                                device = event.device.name().unwrap_or("unnamed"),
                                "Wayland keyboard injection is active through RemoteDesktop/libei"
                            );
                        }
                    }
                    EiEvent::DevicePaused(event)
                        if keyboard_device.as_ref() == Some(&event.device) =>
                    {
                        active = false;
                        pressed.clear();
                    }
                    EiEvent::DeviceRemoved(event)
                        if keyboard_device.as_ref() == Some(&event.device) =>
                    {
                        active = false;
                        pressed.clear();
                        keyboard_device = None;
                    }
                    EiEvent::Disconnected(event) => {
                        return Err(anyhow!(
                            "Wayland EIS disconnected: {:?}: {}",
                            event.reason,
                            event.explanation.as_deref().unwrap_or("no explanation")
                        ));
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn run_portal_key_injector(
    commands: tokio_mpsc::Receiver<PortalInjectCommand>,
    ready_tx: SyncSender<Result<()>>,
    shutdown: Arc<AtomicBool>,
) {
    let mut ready = Some(ready_tx);
    let result = tokio::select! {
        result = portal_key_injector_main(commands, &mut ready) => result,
        _ = wait_for_shutdown(shutdown.clone()) => {
            Err(anyhow!("Wayland keyboard injection setup was cancelled"))
        }
    };
    if let Some(ready) = ready.take() {
        let error = match result {
            Ok(()) => anyhow!("Wayland injection session ended before a keyboard became ready"),
            Err(error) => error,
        };
        let _ = ready.send(Err(error));
    } else if let Err(error) = result {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!(
                "Wayland keyboard injection session stopped during application shutdown"
            );
        } else {
            tracing::error!(error = %error, "Wayland keyboard injection session ended");
        }
    }
}

enum LinuxKeyInjectorBackend {
    Portal(PortalKeyInjector),
    Uinput(UinputKeyInjector),
}

pub struct LinuxKeyInjector {
    backend: LinuxKeyInjectorBackend,
}

impl LinuxKeyInjector {
    pub fn new() -> Result<Self> {
        Self::new_with_shutdown(Arc::new(AtomicBool::new(false)))
    }

    pub fn new_with_shutdown(shutdown: Arc<AtomicBool>) -> Result<Self> {
        if is_wayland_session() {
            match PortalKeyInjector::new(shutdown.clone()) {
                Ok(injector) => {
                    return Ok(Self {
                        backend: LinuxKeyInjectorBackend::Portal(injector),
                    });
                }
                Err(portal_error) => {
                    if shutdown.load(Ordering::Relaxed) {
                        return Err(portal_error);
                    }
                    tracing::warn!(
                        error = %portal_error,
                        "Wayland portal keyboard injection unavailable; trying uinput fallback"
                    );
                    return UinputKeyInjector::new()
                        .map(|injector| Self {
                            backend: LinuxKeyInjectorBackend::Uinput(injector),
                        })
                        .map_err(|uinput_error| {
                            anyhow!(
                                "no Linux keyboard injection backend is available; \
                                 Wayland RemoteDesktop/libei: {portal_error:#}; \
                                 uinput fallback: {uinput_error:#}"
                            )
                        });
                }
            }
        }

        UinputKeyInjector::new().map(|injector| Self {
            backend: LinuxKeyInjectorBackend::Uinput(injector),
        })
    }
}

impl KeyInjector for LinuxKeyInjector {
    fn press(&mut self, key: Key) -> Result<()> {
        match &mut self.backend {
            LinuxKeyInjectorBackend::Portal(injector) => injector.inject(KeyAction::Press, key),
            LinuxKeyInjectorBackend::Uinput(injector) => injector.press(key),
        }
    }

    fn release(&mut self, key: Key) -> Result<()> {
        match &mut self.backend {
            LinuxKeyInjectorBackend::Portal(injector) => injector.inject(KeyAction::Release, key),
            LinuxKeyInjectorBackend::Uinput(injector) => injector.release(key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autorepeat_is_forwarded_as_another_press() {
        assert_eq!(key_action(0), Some(KeyAction::Release));
        assert_eq!(key_action(1), Some(KeyAction::Press));
        assert_eq!(key_action(2), Some(KeyAction::Press));
        assert_eq!(key_action(3), None);
    }

    #[test]
    fn own_uinput_keyboard_is_not_recaptured() {
        assert!(is_own_virtual_keyboard_name(Some(VIRTUAL_KEYBOARD_NAME)));
        assert!(!is_own_virtual_keyboard_name(Some("USB Keyboard")));
        assert!(!is_own_virtual_keyboard_name(None));
    }

    #[test]
    fn portal_edges_translate_to_directional_edge_activity() {
        let left = MouseEdge::Left.activity();
        assert_eq!(left.edge, Some(MouseEdge::Left));
        assert!(left.at_left_edge(0));
        assert!(left.moving_left());

        let right = MouseEdge::Right.activity();
        assert!(right.at_right_edge(0));
        assert!(right.moving_right());

        let top = MouseEdge::Top.activity();
        assert!(top.at_top_edge(0));
        assert!(top.moving_up());

        let bottom = MouseEdge::Bottom.activity();
        assert!(bottom.at_bottom_edge(0));
        assert!(bottom.moving_down());

        assert!(MouseEdge::Left.is_inward_motion(1.0, 0.0));
        assert!(MouseEdge::Right.is_inward_motion(-1.0, 0.0));
        assert!(MouseEdge::Top.is_inward_motion(0.0, 1.0));
        assert!(MouseEdge::Bottom.is_inward_motion(0.0, -1.0));
    }

    #[test]
    fn portal_release_moves_cursor_back_inside_local_zone() {
        assert_eq!(
            MouseEdge::Left.release_position(Some((0.0, 10.0))),
            Some((1.0, 10.0))
        );
        assert_eq!(
            MouseEdge::Right.release_position(Some((1920.0, 10.0))),
            Some((1919.0, 10.0))
        );
        assert_eq!(
            MouseEdge::Top.release_position(Some((10.0, 0.0))),
            Some((10.0, 1.0))
        );
        assert_eq!(
            MouseEdge::Bottom.release_position(Some((10.0, 1080.0))),
            Some((10.0, 1079.0))
        );
    }

    #[test]
    fn portal_injector_preserves_evdev_key_states() {
        assert_eq!(
            portal_key_state(KeyAction::Press),
            ei::keyboard::KeyState::Press
        );
        assert_eq!(
            portal_key_state(KeyAction::Release),
            ei::keyboard::KeyState::Released
        );
        assert!(monotonic_time_us() > 0);
    }
}
