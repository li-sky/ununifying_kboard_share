//! Linux adapter: evdev capture + evdev uinput injection.
//!
//! Kept intentionally compact. The Python project's `linux_input.py`
//! already documents the permission model (`input`, `uinput` groups,
//! `/dev/input/event*`, `/dev/uinput`). The same caveats apply here.

#![cfg(target_os = "linux")]

use super::{KeyCapture, KeyInjector, MouseActivity, MouseWatcher, Result};
use anyhow::{anyhow, Context};
use kbshare_core::keycode::Key;
use kbshare_core::protocol::KeyAction;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use evdev::{AttributeSet, Device, EventType, InputEventKind, Key as EvKey};

pub struct LinuxKeyCapture {
    forwarding: Arc<AtomicBool>,
    devices: Vec<Device>,
    shutdown: Arc<AtomicBool>,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl LinuxKeyCapture {
    pub fn new() -> Result<Self> {
        // Auto-discover keyboard-capable devices.
        let mut devices = Vec::new();
        for (_, dev) in evdev::enumerate() {
            if is_keyboard(&dev) {
                devices.push(dev);
            }
        }
        if devices.is_empty() {
            return Err(anyhow!(
                "no keyboard devices found; ensure the user has read access to /dev/input/event*"
            ));
        }
        Ok(Self {
            forwarding: Arc::new(AtomicBool::new(false)),
            devices,
            shutdown: Arc::new(AtomicBool::new(false)),
            handles: Mutex::new(Vec::new()),
        })
    }
}

fn is_keyboard(dev: &Device) -> bool {
    if let Some(keys) = dev.supported_keys() {
        keys.contains(EvKey::KEY_A) && keys.contains(EvKey::KEY_SPACE)
    } else {
        false
    }
}

impl KeyCapture for LinuxKeyCapture {
    fn start(&mut self, on_event: Box<dyn FnMut(KeyAction, Key) + Send>) -> Result<()> {
        let on_event = Arc::new(Mutex::new(on_event));
        let shutdown = self.shutdown.clone();
        let forwarding = self.forwarding.clone();
        let devices = std::mem::take(&mut self.devices);

        for mut dev in devices {
            let on_event = on_event.clone();
            let shutdown = shutdown.clone();
            let forwarding = forwarding.clone();
            let h = thread::spawn(move || {
                let mut grabbed = false;
                while !shutdown.load(Ordering::Relaxed) {
                    // Adjust grab state to match current forwarding flag.
                    let want = forwarding.load(Ordering::Relaxed);
                    if want != grabbed {
                        let _ = if want { dev.grab() } else { dev.ungrab() };
                        grabbed = want;
                    }
                    match dev.fetch_events() {
                        Ok(events) => {
                            for ev in events {
                                if ev.event_type() != EventType::KEY {
                                    continue;
                                }
                                let action = match ev.value() {
                                    1 => KeyAction::Press,
                                    0 => KeyAction::Release,
                                    _ => continue, // autorepeat (value=2) is OS-level; core handles de-dup.
                                };
                                if let InputEventKind::Key(k) = ev.kind() {
                                    let logical = Key::new(k.code());
                                    (on_event.lock())(action, logical);
                                }
                            }
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(100));
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
    }
}

pub struct LinuxMouseWatcher {
    shutdown: Arc<AtomicBool>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    devices: Vec<Device>,
}

impl LinuxMouseWatcher {
    pub fn new() -> Result<Self> {
        let mut devices = Vec::new();
        for (_, dev) in evdev::enumerate() {
            if is_mouse(&dev) {
                devices.push(dev);
            }
        }
        if devices.is_empty() {
            return Err(anyhow!("no mouse devices found"));
        }
        Ok(Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            handles: Mutex::new(Vec::new()),
            devices,
        })
    }
}

fn is_mouse(dev: &Device) -> bool {
    if let Some(rel) = dev.supported_relative_axes() {
        if rel.contains(evdev::RelativeAxisType::REL_X) {
            return true;
        }
    }
    false
}

impl MouseWatcher for LinuxMouseWatcher {
    fn start(&mut self, on_activity: Box<dyn FnMut(MouseActivity) + Send>) -> Result<()> {
        let on_activity = Arc::new(Mutex::new(on_activity));
        let shutdown = self.shutdown.clone();
        let devices = std::mem::take(&mut self.devices);
        for mut dev in devices {
            let on_activity = on_activity.clone();
            let shutdown = shutdown.clone();
            let h = thread::spawn(move || {
                while !shutdown.load(Ordering::Relaxed) {
                    match dev.fetch_events() {
                        Ok(events) => {
                            for _ in events {
                                (on_activity.lock())(MouseActivity::UNKNOWN);
                            }
                        }
                        Err(_) => thread::sleep(Duration::from_millis(100)),
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
    }
}

pub struct LinuxKeyInjector {
    device: evdev::uinput::VirtualDevice,
}

impl LinuxKeyInjector {
    pub fn new() -> Result<Self> {
        let mut keys = AttributeSet::<EvKey>::new();
        for code in 1u16..=0x2ff {
            keys.insert(EvKey::new(code));
        }
        let device = evdev::uinput::VirtualDeviceBuilder::new()
            .context("build uinput device")?
            .name("kbshare-virtual-keyboard")
            .with_keys(&keys)
            .context("attach keys")?
            .build()
            .context("build uinput")?;
        Ok(Self { device })
    }
}

impl KeyInjector for LinuxKeyInjector {
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
