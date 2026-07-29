//! OS adapters for keyboard capture, mouse activity detection, and keyboard
//! injection.
//!
//! The traits here are deliberately minimal. The runtime in `kbshare-core`
//! stays completely above this layer and never reaches into OS land.

use kbshare_core::keycode::Key;
use kbshare_core::protocol::KeyAction;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub mod mock;

#[cfg(windows)]
pub mod win;

#[cfg(target_os = "linux")]
pub mod linux;

/// Result alias used across platform adapters.
pub type Result<T> = anyhow::Result<T>;

/// Captures local keyboard events. In `forwarding = true` mode the
/// implementation MUST swallow physical keystrokes so they are not delivered
/// to the OS; only the callback sees them.
pub trait KeyCapture: Send {
    /// Begin delivering captured key events to `on_event`. Called exactly
    /// once per capture instance.
    fn start(&mut self, on_event: Box<dyn FnMut(KeyAction, Key) + Send>) -> Result<()>;

    /// A shared handle to the atomic "forwarding mode" flag. Callers can
    /// read or toggle it from any thread; the capture implementation reads
    /// it on every captured event to decide whether to swallow or pass
    /// through.
    fn forwarding_flag(&self) -> Arc<AtomicBool>;

    fn stop(&mut self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseEdge {
    Left,
    Right,
    Top,
    Bottom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseActivity {
    /// Compositor-confirmed desktop edge, when the activity came from a
    /// Wayland InputCapture pointer barrier.
    pub edge: Option<MouseEdge>,
    pub x: Option<i32>,
    pub y: Option<i32>,
    pub dx: Option<i32>,
    pub dy: Option<i32>,
    pub desktop_left: Option<i32>,
    pub desktop_right: Option<i32>,
    pub desktop_top: Option<i32>,
    pub desktop_bottom: Option<i32>,
}

impl MouseActivity {
    pub const UNKNOWN: Self = Self {
        edge: None,
        x: None,
        y: None,
        dx: None,
        dy: None,
        desktop_left: None,
        desktop_right: None,
        desktop_top: None,
        desktop_bottom: None,
    };

    pub fn at_left_edge(self, threshold_px: i32) -> bool {
        matches!((self.x, self.desktop_left), (Some(x), Some(left)) if x <= left + threshold_px)
    }

    pub fn at_right_edge(self, threshold_px: i32) -> bool {
        matches!((self.x, self.desktop_right), (Some(x), Some(right)) if x >= right - 1 - threshold_px)
    }

    pub fn at_top_edge(self, threshold_px: i32) -> bool {
        matches!((self.y, self.desktop_top), (Some(y), Some(top)) if y <= top + threshold_px)
    }

    pub fn at_bottom_edge(self, threshold_px: i32) -> bool {
        matches!((self.y, self.desktop_bottom), (Some(y), Some(bottom)) if y >= bottom - 1 - threshold_px)
    }

    pub fn moving_left(self) -> bool {
        self.dx.is_some_and(|delta| delta < 0)
    }

    pub fn moving_right(self) -> bool {
        self.dx.is_some_and(|delta| delta > 0)
    }

    pub fn moving_up(self) -> bool {
        self.dy.is_some_and(|delta| delta < 0)
    }

    pub fn moving_down(self) -> bool {
        self.dy.is_some_and(|delta| delta > 0)
    }
}

/// Monitors local mouse activity and reports coordinates when available.
pub trait MouseWatcher: Send {
    fn start(&mut self, on_activity: Box<dyn FnMut(MouseActivity) + Send>) -> Result<()>;
    fn stop(&mut self);
}

/// Injects synthetic keystrokes into the local OS.
pub trait KeyInjector: Send {
    fn press(&mut self, key: Key) -> Result<()>;
    fn release(&mut self, key: Key) -> Result<()>;
}

/// Factory: produce the default capture + watcher + injector for the running
/// platform. Returns mock implementations on platforms with no real adapter.
pub fn default_capture() -> Result<Box<dyn KeyCapture>> {
    default_capture_with_shutdown(Arc::new(AtomicBool::new(false)))
}

/// Produce the default capture backend and allow interactive Wayland portal
/// setup to be cancelled while the application is shutting down.
pub fn default_capture_with_shutdown(shutdown: Arc<AtomicBool>) -> Result<Box<dyn KeyCapture>> {
    #[cfg(windows)]
    {
        let _ = shutdown;
        return Ok(Box::new(win::WinKeyCapture::new()?));
    }
    #[cfg(target_os = "linux")]
    {
        return linux::LinuxKeyCapture::new_with_shutdown(shutdown)
            .map(|c| Box::new(c) as Box<dyn KeyCapture>);
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = shutdown;
        Ok(Box::new(mock::MockKeyCapture::new()))
    }
}

pub fn default_mouse_watcher() -> Result<Box<dyn MouseWatcher>> {
    #[cfg(windows)]
    {
        return Ok(Box::new(win::WinMouseWatcher::new()));
    }
    #[cfg(target_os = "linux")]
    {
        return linux::LinuxMouseWatcher::new().map(|c| Box::new(c) as Box<dyn MouseWatcher>);
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Ok(Box::new(mock::MockMouseWatcher::new()))
    }
}

pub fn default_injector() -> Result<Box<dyn KeyInjector>> {
    default_injector_with_shutdown(Arc::new(AtomicBool::new(false)))
}

/// Produce the default injector and allow long-running, interactive platform
/// setup (such as a Wayland portal permission request) to be cancelled.
pub fn default_injector_with_shutdown(shutdown: Arc<AtomicBool>) -> Result<Box<dyn KeyInjector>> {
    #[cfg(windows)]
    {
        let _ = shutdown;
        return Ok(Box::new(win::WinKeyInjector::new()));
    }
    #[cfg(target_os = "linux")]
    {
        return linux::LinuxKeyInjector::new_with_shutdown(shutdown)
            .map(|c| Box::new(c) as Box<dyn KeyInjector>);
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = shutdown;
        Ok(Box::new(mock::MockKeyInjector::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::MouseActivity;

    #[test]
    fn edge_detection_uses_virtual_desktop_bounds() {
        let activity = MouseActivity {
            edge: None,
            x: Some(1917),
            y: Some(500),
            dx: Some(12),
            dy: Some(0),
            desktop_left: Some(-1920),
            desktop_right: Some(1920),
            desktop_top: Some(0),
            desktop_bottom: Some(1080),
        };
        assert!(activity.at_right_edge(2));
        assert!(!activity.at_left_edge(2));
        assert!(!activity.at_top_edge(2));
    }

    #[test]
    fn unknown_position_never_hits_an_edge() {
        assert!(!MouseActivity::UNKNOWN.at_left_edge(10));
        assert!(!MouseActivity::UNKNOWN.at_right_edge(10));
    }
}
