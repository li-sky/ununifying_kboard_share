//! In-memory mock adapters. Used by tests and by dev-time dry runs.

use super::{KeyCapture, KeyInjector, MouseActivity, MouseWatcher, Result};
use crossbeam_channel::{unbounded, Receiver, Sender};
use kbshare_core::keycode::Key;
use kbshare_core::protocol::KeyAction;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Capture that simply lets tests push events in directly.
pub struct MockKeyCapture {
    tx: Sender<(KeyAction, Key)>,
    rx: Mutex<Option<Receiver<(KeyAction, Key)>>>,
    forwarding: Arc<AtomicBool>,
    handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    shutdown: Arc<AtomicBool>,
}

impl MockKeyCapture {
    pub fn new() -> Self {
        let (tx, rx) = unbounded();
        Self {
            tx,
            rx: Mutex::new(Some(rx)),
            forwarding: Arc::new(AtomicBool::new(false)),
            handle: Mutex::new(None),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Expose the sender so a test can inject key events.
    pub fn sender(&self) -> Sender<(KeyAction, Key)> {
        self.tx.clone()
    }

    /// Expose the forwarding flag so tests can assert on it.
    pub fn forwarding_flag(&self) -> Arc<AtomicBool> {
        self.forwarding.clone()
    }
}

impl Default for MockKeyCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyCapture for MockKeyCapture {
    fn start(&mut self, mut on_event: Box<dyn FnMut(KeyAction, Key) + Send>) -> Result<()> {
        let rx = self
            .rx
            .lock()
            .take()
            .ok_or_else(|| anyhow::anyhow!("MockKeyCapture started twice"))?;
        let shutdown = self.shutdown.clone();
        let handle = std::thread::spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                match rx.recv_timeout(std::time::Duration::from_millis(50)) {
                    Ok((action, key)) => on_event(action, key),
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(_) => break,
                }
            }
        });
        *self.handle.lock() = Some(handle);
        Ok(())
    }

    fn forwarding_flag(&self) -> Arc<AtomicBool> {
        self.forwarding.clone()
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.lock().take() {
            let _ = h.join();
        }
    }
}

/// Mouse watcher whose activity is driven entirely by test code.
pub struct MockMouseWatcher {
    tx: Sender<MouseActivity>,
    rx: Mutex<Option<Receiver<MouseActivity>>>,
    handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    shutdown: Arc<AtomicBool>,
}

impl MockMouseWatcher {
    pub fn new() -> Self {
        let (tx, rx) = unbounded();
        Self {
            tx,
            rx: Mutex::new(Some(rx)),
            handle: Mutex::new(None),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn sender(&self) -> Sender<MouseActivity> {
        self.tx.clone()
    }
}

impl Default for MockMouseWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl MouseWatcher for MockMouseWatcher {
    fn start(&mut self, mut on_activity: Box<dyn FnMut(MouseActivity) + Send>) -> Result<()> {
        let rx = self
            .rx
            .lock()
            .take()
            .ok_or_else(|| anyhow::anyhow!("MockMouseWatcher started twice"))?;
        let shutdown = self.shutdown.clone();
        let handle = std::thread::spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                match rx.recv_timeout(std::time::Duration::from_millis(50)) {
                    Ok(activity) => on_activity(activity),
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(_) => break,
                }
            }
        });
        *self.handle.lock() = Some(handle);
        Ok(())
    }
    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.lock().take() {
            let _ = h.join();
        }
    }
}

/// Injector that records every call into a Vec for assertion.
#[derive(Default)]
pub struct MockKeyInjector {
    pub log: Arc<Mutex<Vec<(KeyAction, Key)>>>,
}

impl MockKeyInjector {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn take_log(&self) -> Vec<(KeyAction, Key)> {
        std::mem::take(&mut *self.log.lock())
    }
}

impl KeyInjector for MockKeyInjector {
    fn press(&mut self, key: Key) -> Result<()> {
        self.log.lock().push((KeyAction::Press, key));
        Ok(())
    }
    fn release(&mut self, key: Key) -> Result<()> {
        self.log.lock().push((KeyAction::Release, key));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kbshare_core::keycode::codes::KEY_A;

    #[test]
    fn capture_forwards_events_to_callback() {
        let mut cap = MockKeyCapture::new();
        let tx = cap.sender();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = seen.clone();
        cap.start(Box::new(move |a, k| seen_cb.lock().push((a, k))))
            .unwrap();

        tx.send((KeyAction::Press, Key::new(KEY_A))).unwrap();
        tx.send((KeyAction::Release, Key::new(KEY_A))).unwrap();
        // Give the thread time to drain.
        std::thread::sleep(std::time::Duration::from_millis(150));
        cap.stop();

        let seen = seen.lock().clone();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, KeyAction::Press);
        assert_eq!(seen[1].0, KeyAction::Release);
    }

    #[test]
    fn injector_records_actions() {
        let mut inj = MockKeyInjector::new();
        inj.press(Key::new(KEY_A)).unwrap();
        inj.release(Key::new(KEY_A)).unwrap();
        let log = inj.take_log();
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn forwarding_flag_is_atomic_and_visible() {
        let cap = MockKeyCapture::new();
        let flag = cap.forwarding_flag();
        assert!(!flag.load(Ordering::Relaxed));
        flag.store(true, Ordering::Relaxed);
        assert!(cap.forwarding_flag().load(Ordering::Relaxed));
    }
}
