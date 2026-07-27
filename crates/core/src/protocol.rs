//! Wire protocol.
//!
//! One message per line, each line is a JSON object. This keeps the protocol
//! human-readable, trivial to log, easy to fuzz, and compatible with any
//! transport that is byte-stream oriented.
//!
//! Forward compatibility: unknown message types fail loudly in tests but
//! should be *ignored* by runtime code. The runtime code in `session.rs`
//! (net crate) is responsible for that policy.

use crate::keycode::Key;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MouseState {
    Active,
    Inactive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyAction {
    Press,
    Release,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FlowLayout {
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub updated_by: String,
    #[serde(default)]
    pub devices: Vec<FlowLayoutDevice>,
}

impl FlowLayout {
    pub fn is_newer_than(&self, other: &Self) -> bool {
        (self.version, self.updated_by.as_str()) > (other.version, other.updated_by.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowLayoutDevice {
    pub id: String,
    pub label: String,
    pub host_index: u8,
    pub x: i32,
    pub y: i32,
}

/// Envelope for every wire message.
///
/// Using `tag = "type"` gives us forward-compatible discrimination and keeps
/// messages flat (no nesting noise on the wire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// First message after TLS handshake. Carries the sender's declared
    /// identity and the SHA-256 fingerprint of its own certificate, for
    /// TOFU verification.
    Hello {
        id: String,
        fingerprint: String,
        /// Protocol version. Bumped on breaking changes.
        version: u32,
    },
    /// Sent by the receiver-side to tell the sender whether to be in remote
    /// mode. Also serves as a keep-alive.
    Heartbeat { id: String, state: MouseState },
    /// A single key event.
    Key { action: KeyAction, code: Key },
    /// Announce that the sender is flushing its pressed-key set. Purely
    /// informational; receivers can log it for diagnostics.
    Flush { id: String },
    /// The shared mouse is about to switch from the client back to the host.
    FlowReturn { id: String },
    /// Versioned device topology. Both peers keep the newest complete layout.
    FlowLayout { id: String, layout: FlowLayout },
}

pub const PROTOCOL_VERSION: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keycode::codes::KEY_A;

    #[test]
    fn hello_roundtrip() {
        let msg = Message::Hello {
            id: "host-alpha".into(),
            fingerprint: "ABCD".into(),
            version: PROTOCOL_VERSION,
        };
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains("\"type\":\"hello\""));
        let back: Message = serde_json::from_str(&s).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn heartbeat_roundtrip() {
        let msg = Message::Heartbeat {
            id: "client-alpha".into(),
            state: MouseState::Active,
        };
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains("\"state\":\"active\""));
        let back: Message = serde_json::from_str(&s).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn key_roundtrip() {
        let msg = Message::Key {
            action: KeyAction::Press,
            code: Key::new(KEY_A),
        };
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains("\"action\":\"press\""));
        assert!(s.contains("\"code\":30"));
        let back: Message = serde_json::from_str(&s).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn unknown_type_is_rejected() {
        let r: Result<Message, _> = serde_json::from_str(r#"{"type":"mystery","payload":42}"#);
        assert!(r.is_err());
    }

    #[test]
    fn flow_return_roundtrip() {
        let msg = Message::FlowReturn {
            id: "client-alpha".into(),
        };
        let encoded = serde_json::to_string(&msg).unwrap();
        assert!(encoded.contains("\"type\":\"flow_return\""));
        assert_eq!(serde_json::from_str::<Message>(&encoded).unwrap(), msg);
    }

    #[test]
    fn flow_layout_newer_version_wins_with_writer_tiebreak() {
        let mut old = FlowLayout {
            version: 7,
            updated_by: "host-a".into(),
            devices: vec![],
        };
        let newer = FlowLayout {
            version: 8,
            updated_by: "peer-z".into(),
            devices: vec![],
        };
        assert!(newer.is_newer_than(&old));
        old.version = 8;
        assert!(newer.is_newer_than(&old));
    }

    #[test]
    fn flow_layout_message_roundtrip_preserves_offline_devices() {
        let msg = Message::FlowLayout {
            id: "host-a".into(),
            layout: FlowLayout {
                version: 42,
                updated_by: "host-a".into(),
                devices: vec![FlowLayoutDevice {
                    id: "offline-laptop".into(),
                    label: "Offline laptop".into(),
                    host_index: 1,
                    x: 400,
                    y: 100,
                }],
            },
        };
        let encoded = serde_json::to_string(&msg).unwrap();
        assert!(encoded.contains("\"type\":\"flow_layout\""));
        assert_eq!(serde_json::from_str::<Message>(&encoded).unwrap(), msg);
    }
}
