//! Mode state machine.
//!
//! Mouse-follows-mouse semantics:
//! * Whichever side's mouse moves most recently owns the keyboard.
//! * `PeerMouseActivity` (the *client* just moved its mouse, signalled via
//!   its keepalive) → **Remote**.
//! * `LocalMouseActivity` (the *host* just moved its mouse) → **Local**.
//! * Default on connect is **Local**; the user must touch the client mouse
//!   to hand the keyboard over.
//! * Session loss / panic hotkey → **Local + flush**.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Local,
    Remote,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Local
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Host's own mouse just moved. Pull keyboard back to host.
    LocalMouseActivity,
    /// The peer (client) reported mouse activity on its side.
    PeerMouseActivity,
    /// TLS/TCP session came up. Peer is reachable; mode unchanged.
    SessionEstablished,
    /// TLS/TCP session is gone. Drop to Local with flush.
    SessionLost,
    /// Panic hotkey. Force Local + flush.
    PanicHotkey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideEffect {
    ResumeLocalKeyboard,
    StartForwardingKeyboard,
    FlushPressedKeys,
    Notify(Mode),
}

#[derive(Debug, Clone, Default)]
pub struct StateMachine {
    mode: Mode,
    peer_connected: bool,
}

impl StateMachine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn peer_connected(&self) -> bool {
        self.peer_connected
    }

    pub fn apply(&mut self, event: Event) -> Vec<SideEffect> {
        match event {
            Event::SessionEstablished => {
                self.peer_connected = true;
                Vec::new()
            }
            Event::SessionLost => {
                self.peer_connected = false;
                let mut fx = self.set_mode(Mode::Local);
                if !fx.iter().any(|e| matches!(e, SideEffect::FlushPressedKeys)) {
                    fx.insert(0, SideEffect::FlushPressedKeys);
                }
                fx
            }
            Event::PeerMouseActivity => {
                if self.peer_connected {
                    self.set_mode(Mode::Remote)
                } else {
                    Vec::new()
                }
            }
            Event::LocalMouseActivity | Event::PanicHotkey => self.set_mode(Mode::Local),
        }
    }

    fn set_mode(&mut self, next: Mode) -> Vec<SideEffect> {
        if self.mode == next {
            return Vec::new();
        }
        self.mode = next;
        match next {
            Mode::Remote => vec![
                SideEffect::StartForwardingKeyboard,
                SideEffect::Notify(next),
            ],
            Mode::Local => vec![
                SideEffect::FlushPressedKeys,
                SideEffect::ResumeLocalKeyboard,
                SideEffect::Notify(next),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_in_local_with_no_peer() {
        let sm = StateMachine::new();
        assert_eq!(sm.mode(), Mode::Local);
        assert!(!sm.peer_connected());
    }

    #[test]
    fn session_established_does_not_change_mode() {
        let mut sm = StateMachine::new();
        let fx = sm.apply(Event::SessionEstablished);
        assert_eq!(sm.mode(), Mode::Local);
        assert!(fx.is_empty());
        assert!(sm.peer_connected());
    }

    #[test]
    fn peer_mouse_activity_enters_remote() {
        let mut sm = StateMachine::new();
        sm.apply(Event::SessionEstablished);
        let fx = sm.apply(Event::PeerMouseActivity);
        assert_eq!(sm.mode(), Mode::Remote);
        assert_eq!(
            fx,
            vec![
                SideEffect::StartForwardingKeyboard,
                SideEffect::Notify(Mode::Remote),
            ]
        );
    }

    #[test]
    fn peer_mouse_activity_without_session_is_noop() {
        let mut sm = StateMachine::new();
        let fx = sm.apply(Event::PeerMouseActivity);
        assert!(fx.is_empty());
        assert_eq!(sm.mode(), Mode::Local);
    }

    #[test]
    fn local_mouse_pulls_back_to_local_with_flush() {
        let mut sm = StateMachine::new();
        sm.apply(Event::SessionEstablished);
        sm.apply(Event::PeerMouseActivity);
        let fx = sm.apply(Event::LocalMouseActivity);
        assert_eq!(sm.mode(), Mode::Local);
        assert_eq!(
            fx,
            vec![
                SideEffect::FlushPressedKeys,
                SideEffect::ResumeLocalKeyboard,
                SideEffect::Notify(Mode::Local),
            ]
        );
    }

    #[test]
    fn alternating_mouse_activity_flips_mode() {
        let mut sm = StateMachine::new();
        sm.apply(Event::SessionEstablished);
        sm.apply(Event::PeerMouseActivity);
        assert_eq!(sm.mode(), Mode::Remote);
        sm.apply(Event::LocalMouseActivity);
        assert_eq!(sm.mode(), Mode::Local);
        sm.apply(Event::PeerMouseActivity);
        assert_eq!(sm.mode(), Mode::Remote);
    }

    #[test]
    fn session_lost_flushes_and_returns_to_local() {
        let mut sm = StateMachine::new();
        sm.apply(Event::SessionEstablished);
        sm.apply(Event::PeerMouseActivity);
        let fx = sm.apply(Event::SessionLost);
        assert_eq!(sm.mode(), Mode::Local);
        assert!(!sm.peer_connected());
        assert_eq!(
            fx,
            vec![
                SideEffect::FlushPressedKeys,
                SideEffect::ResumeLocalKeyboard,
                SideEffect::Notify(Mode::Local),
            ]
        );
    }

    #[test]
    fn session_lost_from_local_still_flushes() {
        let mut sm = StateMachine::new();
        let fx = sm.apply(Event::SessionLost);
        assert_eq!(sm.mode(), Mode::Local);
        assert!(fx.contains(&SideEffect::FlushPressedKeys));
    }

    #[test]
    fn panic_hotkey_from_remote_returns_to_local() {
        let mut sm = StateMachine::new();
        sm.apply(Event::SessionEstablished);
        sm.apply(Event::PeerMouseActivity);
        let fx = sm.apply(Event::PanicHotkey);
        assert_eq!(sm.mode(), Mode::Local);
        assert!(fx.contains(&SideEffect::FlushPressedKeys));
    }

    #[test]
    fn idempotent_local_mouse_is_noop() {
        let mut sm = StateMachine::new();
        let fx = sm.apply(Event::LocalMouseActivity);
        assert!(fx.is_empty());
    }
}
