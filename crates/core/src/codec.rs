//! NDJSON line framing.
//!
//! Framing is split from the message definitions on purpose:
//!
//!   * `protocol.rs` only cares about what messages mean.
//!   * `codec.rs` only cares about how they sit on the wire.
//!
//! The codec is buffered: partial reads are fine, but we cap the line length
//! to reject pathological inputs.

use crate::protocol::Message;
use thiserror::Error;

/// Maximum size of a single line in bytes. Well above anything our protocol
/// actually emits, but low enough to prevent DoS via a never-terminating
/// line.
pub const MAX_LINE_LEN: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("line too long ({0} bytes, limit is {})", MAX_LINE_LEN)]
    LineTooLong(usize),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Encode a message as a single NDJSON line, terminated by `\n`.
pub fn encode_line(msg: &Message) -> Result<Vec<u8>, CodecError> {
    let mut buf = serde_json::to_vec(msg)?;
    buf.push(b'\n');
    Ok(buf)
}

/// Decode one NDJSON line (without the trailing `\n`).
pub fn decode_line(line: &[u8]) -> Result<Message, CodecError> {
    Ok(serde_json::from_slice(line)?)
}

/// Incremental line reader. Feed bytes with `extend`, pull messages with
/// `next_message` until it returns `Ok(None)`.
///
/// Intentionally byte-oriented: works identically on top of `std::io::Read`,
/// rustls `Stream`, or a `Vec<u8>` in tests.
#[derive(Debug, Default)]
pub struct LineDecoder {
    buf: Vec<u8>,
}

impl LineDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extend(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn next_message(&mut self) -> Result<Option<Message>, CodecError> {
        // Find a newline.
        let Some(pos) = self.buf.iter().position(|&b| b == b'\n') else {
            if self.buf.len() > MAX_LINE_LEN {
                return Err(CodecError::LineTooLong(self.buf.len()));
            }
            return Ok(None);
        };
        if pos > MAX_LINE_LEN {
            return Err(CodecError::LineTooLong(pos));
        }
        let line = self.buf.drain(..=pos).collect::<Vec<_>>();
        let line = &line[..line.len() - 1]; // drop the '\n'
        if line.is_empty() {
            return self.next_message();
        }
        Ok(Some(decode_line(line)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keycode::{codes::KEY_A, Key};
    use crate::protocol::{KeyAction, Message, MouseState};

    #[test]
    fn encode_emits_exactly_one_line() {
        let msg = Message::Heartbeat {
            id: "c".into(),
            state: MouseState::Active,
        };
        let bytes = encode_line(&msg).unwrap();
        assert_eq!(*bytes.last().unwrap(), b'\n');
        assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), 1);
    }

    #[test]
    fn decoder_handles_streamed_bytes() {
        let msgs = vec![
            Message::Heartbeat {
                id: "c".into(),
                state: MouseState::Active,
            },
            Message::Key {
                action: KeyAction::Press,
                code: Key::new(KEY_A),
            },
            Message::Key {
                action: KeyAction::Release,
                code: Key::new(KEY_A),
            },
        ];
        let mut wire = Vec::new();
        for m in &msgs {
            wire.extend(encode_line(m).unwrap());
        }

        let mut dec = LineDecoder::new();
        // Feed one byte at a time to exercise partial reads.
        let mut out = Vec::new();
        for b in &wire {
            dec.extend(&[*b]);
            while let Some(m) = dec.next_message().unwrap() {
                out.push(m);
            }
        }
        assert_eq!(out, msgs);
    }

    #[test]
    fn decoder_rejects_overlong_line() {
        let mut dec = LineDecoder::new();
        // Feed more than MAX_LINE_LEN without a newline.
        let junk = vec![b'x'; MAX_LINE_LEN + 1];
        dec.extend(&junk);
        let err = dec.next_message().unwrap_err();
        assert!(matches!(err, CodecError::LineTooLong(_)));
    }

    #[test]
    fn decoder_skips_blank_lines() {
        let mut dec = LineDecoder::new();
        dec.extend(b"\n\n");
        dec.extend(&encode_line(&Message::Flush { id: "x".into() }).unwrap());
        let m = dec.next_message().unwrap().expect("should have a message");
        assert!(matches!(m, Message::Flush { .. }));
    }

    #[test]
    fn encode_then_decode_is_identity() {
        let msg = Message::Hello {
            id: "host".into(),
            fingerprint: "FF".into(),
            version: crate::protocol::PROTOCOL_VERSION,
        };
        let bytes = encode_line(&msg).unwrap();
        let mut dec = LineDecoder::new();
        dec.extend(&bytes);
        assert_eq!(dec.next_message().unwrap(), Some(msg));
    }
}
