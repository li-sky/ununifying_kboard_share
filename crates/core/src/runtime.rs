//! Host & client runtime driver — still a pure function, still zero I/O.
//!
//! Binaries own the threads, sockets, OS calls and timers. This module owns
//! the *decisions*: "I just saw event X, what should I emit on the wire and
//! what side-effects should I request?"
//!
//! Both drivers share one invariant: whenever the state machine requests
//! `SideEffect::FlushPressedKeys`, the driver automatically materialises
//! it into wire messages (host) or injection events (client). Callers
//! never need to remember to flush.

use crate::codec::{encode_line, CodecError};
use crate::keycode::Key;
use crate::pressed::PressedKeys;
use crate::protocol::{KeyAction, Message, MouseState, PROTOCOL_VERSION};
use crate::state::{Event, Mode, SideEffect, StateMachine};
use std::time::{Duration, Instant};

/// How long after the host's own mouse moves we refuse to hand the keyboard
/// back to the peer. Keeps mouse-priority intuitive: the user's last-moved
/// mouse wins, with a short grace so peer-side residual jitter doesn't rip
/// the keyboard right back.
const LOCAL_MOUSE_PRIORITY: Duration = Duration::from_millis(300);

// ------------------------- HOST -------------------------

#[derive(Debug)]
pub struct HostDriver {
    state: StateMachine,
    pressed: PressedKeys,
    local_id: String,
    peer_id: String,
    fingerprint: String,
    last_local_mouse: Option<Instant>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Step {
    pub outgoing: Vec<Message>,
    pub effects: Vec<SideEffect>,
}

impl HostDriver {
    pub fn new(
        local_id: impl Into<String>,
        peer_id: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            state: StateMachine::new(),
            pressed: PressedKeys::new(),
            local_id: local_id.into(),
            peer_id: peer_id.into(),
            fingerprint: fingerprint.into(),
            last_local_mouse: None,
        }
    }

    pub fn mode(&self) -> Mode {
        self.state.mode()
    }

    pub fn pressed_count(&self) -> usize {
        self.pressed.len()
    }

    pub fn on_session_established(&mut self) -> Step {
        let mut step = Step::default();
        step.outgoing.push(Message::Hello {
            id: self.local_id.clone(),
            fingerprint: self.fingerprint.clone(),
            version: PROTOCOL_VERSION,
        });
        self.apply_event(Event::SessionEstablished, &mut step);
        step
    }

    pub fn on_session_lost(&mut self) -> Step {
        let mut step = Step::default();
        self.apply_event(Event::SessionLost, &mut step);
        step
    }

    pub fn on_local_mouse(&mut self) -> Step {
        let mut step = Step::default();
        self.last_local_mouse = Some(Instant::now());
        self.apply_event(Event::LocalMouseActivity, &mut step);
        step
    }

    pub fn on_panic_hotkey(&mut self) -> Step {
        let mut step = Step::default();
        self.apply_event(Event::PanicHotkey, &mut step);
        step
    }

    pub fn on_flow_departure(&mut self) -> Step {
        let mut step = Step::default();
        self.apply_event(Event::PeerMouseActivity, &mut step);
        step
    }

    pub fn on_incoming(&mut self, msg: Message) -> Step {
        let mut step = Step::default();
        match msg {
            Message::Hello { id, .. } if id != self.peer_id => {
                tracing::warn!(actual = %id, expected = %self.peer_id, "peer identity mismatch");
            }
            Message::Hello { .. } => {
                tracing::debug!("peer hello received");
            }
            Message::Heartbeat { id, .. } if id != self.peer_id => {
                tracing::debug!(actual = %id, "heartbeat from unknown peer ignored");
            }
            Message::Heartbeat { state, .. } => match state {
                MouseState::Active => {
                    let in_grace = self
                        .last_local_mouse
                        .map(|t| t.elapsed() < LOCAL_MOUSE_PRIORITY)
                        .unwrap_or(false);
                    if in_grace {
                        tracing::debug!(
                            "ignoring peer mouse activity during local-priority window"
                        );
                    } else {
                        tracing::debug!("peer mouse activity reported");
                        self.apply_event(Event::PeerMouseActivity, &mut step);
                    }
                }
                MouseState::Inactive => {
                    tracing::trace!("peer keepalive (idle)");
                }
            },
            Message::FlowReturn { id } if id == self.peer_id => {
                self.apply_event(Event::LocalMouseActivity, &mut step);
            }
            Message::FlowReturn { id } => {
                tracing::debug!(actual = %id, "FlowReturn from unknown peer ignored");
            }
            Message::Key { .. }
            | Message::Flush { .. }
            | Message::MouseInfo { .. }
            | Message::FlowLayout { .. } => {
                tracing::debug!("unexpected key/flush from client (ignored)");
            }
        }
        step
    }

    pub fn on_local_key(&mut self, action: KeyAction, code: Key) -> Step {
        if self.state.mode() != Mode::Remote {
            tracing::trace!(?action, code = code.code(), "key swallowed (not Remote)");
            return Step::default();
        }
        // Track for cleanup, but *always* forward the event so that OS-level
        // autorepeat (repeated Press frames while a key is held) produces
        // autorepeat on the client side too.
        match action {
            KeyAction::Press => {
                let _ = self.pressed.press(code);
            }
            KeyAction::Release => {
                let _ = self.pressed.release(code);
            }
        }
        tracing::debug!(?action, code = code.code(), "forwarding key");
        Step {
            outgoing: vec![Message::Key { action, code }],
            effects: vec![],
        }
    }

    fn apply_event(&mut self, event: Event, step: &mut Step) {
        let effects = self.state.apply(event);
        for fx in &effects {
            if matches!(fx, SideEffect::FlushPressedKeys) {
                // Emit release messages for everything we told the peer to hold,
                // then an explicit Flush announcement so the peer can also
                // reset its view (belt-and-braces).
                for k in self.pressed.flush() {
                    step.outgoing.push(Message::Key {
                        action: KeyAction::Release,
                        code: k,
                    });
                }
                step.outgoing.push(Message::Flush {
                    id: self.local_id.clone(),
                });
            }
        }
        step.effects.extend(effects);
    }

    pub fn encode_step(step: &Step) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::new();
        for msg in &step.outgoing {
            out.extend(encode_line(msg)?);
        }
        Ok(out)
    }
}

// ------------------------- CLIENT -------------------------

#[derive(Debug, Default)]
pub struct ClientDriver {
    state: StateMachine,
    pressed: PressedKeys,
    local_id: String,
    peer_id: String,
    fingerprint: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ClientStep {
    pub outgoing: Vec<Message>,
    pub inject: Vec<(KeyAction, Key)>,
    pub effects: Vec<SideEffect>,
}

impl ClientDriver {
    pub fn new(
        local_id: impl Into<String>,
        peer_id: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            state: StateMachine::new(),
            pressed: PressedKeys::new(),
            local_id: local_id.into(),
            peer_id: peer_id.into(),
            fingerprint: fingerprint.into(),
        }
    }

    pub fn pressed_count(&self) -> usize {
        self.pressed.len()
    }

    pub fn on_session_established(&mut self) -> ClientStep {
        let mut step = ClientStep::default();
        step.outgoing.push(Message::Hello {
            id: self.local_id.clone(),
            fingerprint: self.fingerprint.clone(),
            version: PROTOCOL_VERSION,
        });
        self.apply_event(Event::SessionEstablished, &mut step);
        step
    }

    pub fn on_session_lost(&mut self) -> ClientStep {
        let mut step = ClientStep::default();
        self.apply_event(Event::SessionLost, &mut step);
        step
    }

    /// The client's local mouse is active. Emit a heartbeat that the host
    /// will interpret as "hand the keyboard over to me".
    pub fn on_local_mouse_active(&mut self) -> ClientStep {
        ClientStep {
            outgoing: vec![Message::Heartbeat {
                id: self.local_id.clone(),
                state: MouseState::Active,
            }],
            ..Default::default()
        }
    }

    /// The client's local mouse has been idle. Emit an inactive heartbeat
    /// (pure keepalive — does not steal the keyboard back from the host).
    pub fn on_local_mouse_idle(&mut self) -> ClientStep {
        ClientStep {
            outgoing: vec![Message::Heartbeat {
                id: self.local_id.clone(),
                state: MouseState::Inactive,
            }],
            ..Default::default()
        }
    }

    pub fn on_flow_return(&mut self) -> ClientStep {
        ClientStep {
            outgoing: vec![Message::FlowReturn {
                id: self.local_id.clone(),
            }],
            ..Default::default()
        }
    }

    pub fn on_incoming(&mut self, msg: Message) -> ClientStep {
        let mut step = ClientStep::default();
        match msg {
            Message::Hello { id, .. } if id != self.peer_id => {
                tracing::warn!(actual = %id, expected = %self.peer_id, "peer identity mismatch");
            }
            Message::Hello { .. }
            | Message::Heartbeat { .. }
            | Message::FlowReturn { .. }
            | Message::MouseInfo { .. }
            | Message::FlowLayout { .. } => {}
            Message::Key { action, code } => {
                // Track for cleanup; always inject so OS-level autorepeat on
                // the host produces autorepeat on the client too.
                match action {
                    KeyAction::Press => {
                        let _ = self.pressed.press(code);
                    }
                    KeyAction::Release => {
                        let _ = self.pressed.release(code);
                    }
                }
                step.inject.push((action, code));
            }
            Message::Flush { .. } => {
                for k in self.pressed.flush() {
                    step.inject.push((KeyAction::Release, k));
                }
            }
        }
        step
    }

    fn apply_event(&mut self, event: Event, step: &mut ClientStep) {
        let effects = self.state.apply(event);
        for fx in &effects {
            if matches!(fx, SideEffect::FlushPressedKeys) {
                for k in self.pressed.flush() {
                    step.inject.push((KeyAction::Release, k));
                }
            }
        }
        step.effects.extend(effects);
    }
}

// ------------------------- TESTS -------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keycode::codes::{KEY_A, KEY_LEFTCTRL};

    fn host() -> HostDriver {
        HostDriver::new("host-test", "client-test", "HOSTFP")
    }
    fn client() -> ClientDriver {
        ClientDriver::new("client-test", "host-test", "CLIFP")
    }

    #[test]
    fn host_sends_hello_on_session_up() {
        let mut h = host();
        let step = h.on_session_established();
        assert!(matches!(step.outgoing[0], Message::Hello { .. }));
    }

    #[test]
    fn host_does_not_forward_keys_before_remote_mode() {
        let mut h = host();
        let step = h.on_local_key(KeyAction::Press, Key::new(KEY_A));
        assert!(step.outgoing.is_empty());
        assert_eq!(h.pressed_count(), 0);
    }

    #[test]
    fn host_forwards_keys_only_in_remote_mode() {
        let mut h = host();
        // Before session: Local. Key is swallowed.
        let step = h.on_local_key(KeyAction::Press, Key::new(KEY_A));
        assert!(step.outgoing.is_empty());

        // After session: still Local until peer mouse moves.
        h.on_session_established();
        assert_eq!(h.mode(), Mode::Local);
        let step = h.on_local_key(KeyAction::Press, Key::new(KEY_A));
        assert!(step.outgoing.is_empty());

        // Peer reports mouse activity → Remote. Key is forwarded.
        h.on_incoming(Message::Heartbeat {
            id: "client-test".into(),
            state: MouseState::Active,
        });
        assert_eq!(h.mode(), Mode::Remote);
        let step = h.on_local_key(KeyAction::Press, Key::new(KEY_A));
        assert_eq!(step.outgoing.len(), 1);
        assert_eq!(h.pressed_count(), 1);

        // Host mouse moves → Local with flush.
        let step = h.on_local_mouse();
        assert!(step.outgoing.iter().any(|m| matches!(
            m,
            Message::Key {
                action: KeyAction::Release,
                ..
            }
        )));
        assert!(step
            .outgoing
            .iter()
            .any(|m| matches!(m, Message::Flush { .. })));
        let step = h.on_local_key(KeyAction::Press, Key::new(KEY_A));
        assert!(step.outgoing.is_empty());
    }

    #[test]
    fn flow_departure_and_return_control_host_mode() {
        let mut h = host();
        h.on_session_established();
        let departure = h.on_flow_departure();
        assert_eq!(h.mode(), Mode::Remote);
        assert!(departure
            .effects
            .contains(&SideEffect::StartForwardingKeyboard));

        let returned = h.on_incoming(Message::FlowReturn {
            id: "client-test".into(),
        });
        assert_eq!(h.mode(), Mode::Local);
        assert!(returned.effects.contains(&SideEffect::ResumeLocalKeyboard));
    }

    #[test]
    fn client_announces_flow_return() {
        let mut c = client();
        assert_eq!(
            c.on_flow_return().outgoing,
            vec![Message::FlowReturn {
                id: "client-test".into(),
            }]
        );
    }

    #[test]
    fn host_forwards_autorepeat_presses() {
        let mut h = host();
        h.on_session_established();
        h.on_incoming(Message::Heartbeat {
            id: "client-test".into(),
            state: MouseState::Active,
        });
        assert_eq!(h.mode(), Mode::Remote);
        h.on_local_key(KeyAction::Press, Key::new(KEY_A));
        // OS autorepeat pumps more Press frames; they must all go out so
        // that the client sees repeated characters.
        let step = h.on_local_key(KeyAction::Press, Key::new(KEY_A));
        assert_eq!(step.outgoing.len(), 1);
        // Still only one entry in the pressed-set (for flush bookkeeping).
        assert_eq!(h.pressed_count(), 1);
    }

    #[test]
    fn panic_hotkey_releases_all_tracked_keys() {
        let mut h = host();
        h.on_session_established();
        h.on_incoming(Message::Heartbeat {
            id: "client-test".into(),
            state: MouseState::Active,
        });
        h.on_local_key(KeyAction::Press, Key::new(KEY_LEFTCTRL));
        h.on_local_key(KeyAction::Press, Key::new(KEY_A));
        assert_eq!(h.pressed_count(), 2);

        let step = h.on_panic_hotkey();
        assert_eq!(step.outgoing.len(), 3);
        assert!(matches!(step.outgoing.last(), Some(Message::Flush { .. })));
        assert_eq!(h.pressed_count(), 0);
        assert_eq!(h.mode(), Mode::Local);
    }

    #[test]
    fn client_injects_every_transition_including_autorepeat() {
        let mut c = client();
        c.on_session_established();

        let step = c.on_incoming(Message::Key {
            action: KeyAction::Press,
            code: Key::new(KEY_A),
        });
        assert_eq!(step.inject, vec![(KeyAction::Press, Key::new(KEY_A))]);

        // Autorepeat: another Press must also be injected.
        let step = c.on_incoming(Message::Key {
            action: KeyAction::Press,
            code: Key::new(KEY_A),
        });
        assert_eq!(step.inject, vec![(KeyAction::Press, Key::new(KEY_A))]);

        let step = c.on_incoming(Message::Key {
            action: KeyAction::Release,
            code: Key::new(KEY_A),
        });
        assert_eq!(step.inject, vec![(KeyAction::Release, Key::new(KEY_A))]);
    }

    #[test]
    fn client_releases_everything_on_session_loss() {
        let mut c = client();
        c.on_session_established();
        c.on_incoming(Message::Key {
            action: KeyAction::Press,
            code: Key::new(KEY_LEFTCTRL),
        });
        c.on_incoming(Message::Key {
            action: KeyAction::Press,
            code: Key::new(KEY_A),
        });
        assert_eq!(c.pressed_count(), 2);

        let step = c.on_session_lost();
        let codes: Vec<_> = step.inject.iter().map(|(_, k)| k.code()).collect();
        assert_eq!(codes, vec![KEY_A, KEY_LEFTCTRL]);
        assert_eq!(c.pressed_count(), 0);
    }

    #[test]
    fn host_flush_triggers_client_cleanup() {
        let mut c = client();
        c.on_session_established();
        c.on_incoming(Message::Key {
            action: KeyAction::Press,
            code: Key::new(KEY_A),
        });
        let step = c.on_incoming(Message::Flush {
            id: "host-test".into(),
        });
        assert_eq!(step.inject, vec![(KeyAction::Release, Key::new(KEY_A))]);
        assert_eq!(c.pressed_count(), 0);
    }
}
