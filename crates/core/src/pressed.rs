//! Tracks keys the sender believes are currently held down on the receiver.
//!
//! This solves the "stuck key" problem: if the transport drops while a
//! modifier is held, the receiver would be left holding Ctrl forever. The
//! sender (or the receiver on connection teardown) uses this to generate the
//! exact release sequence needed to bring the remote keyboard state back to
//! neutral.

use crate::keycode::Key;
use std::collections::BTreeSet;

/// A monotonic, ordered set of logically-pressed keys.
///
/// Uses a BTreeSet so that `flush()` emits a deterministic release order.
/// Deterministic order matters for:
///
///   1. Reproducible tests.
///   2. Producing a stable transcript when debugging.
#[derive(Debug, Default, Clone)]
pub struct PressedKeys {
    inner: BTreeSet<Key>,
}

impl PressedKeys {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn contains(&self, key: Key) -> bool {
        self.inner.contains(&key)
    }

    /// Record a press. Returns `true` if this is a transition from
    /// released-to-pressed (i.e. the caller should actually emit a press).
    pub fn press(&mut self, key: Key) -> bool {
        self.inner.insert(key)
    }

    /// Record a release. Returns `true` if the key was actually pressed.
    pub fn release(&mut self, key: Key) -> bool {
        self.inner.remove(&key)
    }

    /// Drain the set, returning the keys that need to be released to
    /// restore a neutral state. Ordering is deterministic by Key code so
    /// callers can diff two runs reliably.
    pub fn flush(&mut self) -> Vec<Key> {
        let mut out: Vec<Key> = self.inner.iter().copied().collect();
        // Release modifiers LAST so that "Ctrl+A ... release A first, then
        // Ctrl" matches how humans release. BTreeSet is ordered by code; we
        // keep that order but sink common modifiers to the end.
        out.sort_by_key(|k| (is_modifier(*k), k.code()));
        self.inner.clear();
        out
    }

    pub fn snapshot(&self) -> Vec<Key> {
        self.inner.iter().copied().collect()
    }
}

fn is_modifier(k: Key) -> bool {
    use crate::keycode::codes::*;
    matches!(
        k.code(),
        KEY_LEFTCTRL
            | KEY_RIGHTCTRL
            | KEY_LEFTSHIFT
            | KEY_RIGHTSHIFT
            | KEY_LEFTALT
            | KEY_RIGHTALT
            | KEY_LEFTMETA
            | KEY_RIGHTMETA
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keycode::codes::*;

    fn k(code: u16) -> Key {
        Key::new(code)
    }

    #[test]
    fn press_then_release_reports_transitions() {
        let mut p = PressedKeys::new();
        assert!(p.press(k(KEY_A)), "first press is a transition");
        assert!(!p.press(k(KEY_A)), "repeat press is NOT a transition");
        assert!(p.release(k(KEY_A)), "release of held key is a transition");
        assert!(
            !p.release(k(KEY_A)),
            "release of unheld key is NOT a transition"
        );
    }

    #[test]
    fn flush_returns_everything_and_empties() {
        let mut p = PressedKeys::new();
        p.press(k(KEY_A));
        p.press(k(KEY_LEFTCTRL));
        p.press(k(KEY_B));
        let out = p.flush();
        assert_eq!(out.len(), 3);
        assert!(p.is_empty());
    }

    #[test]
    fn flush_releases_modifiers_last() {
        let mut p = PressedKeys::new();
        p.press(k(KEY_LEFTCTRL));
        p.press(k(KEY_A));
        p.press(k(KEY_LEFTSHIFT));
        let out = p.flush();
        // Non-modifier first, modifiers at the tail.
        assert_eq!(out.first(), Some(&k(KEY_A)));
        assert!(is_modifier(*out.last().unwrap()));
    }

    #[test]
    fn flush_is_deterministic() {
        // Same set of presses, regardless of order, yields the same release
        // order. This is the property we rely on when comparing transcripts.
        let mut a = PressedKeys::new();
        a.press(k(KEY_B));
        a.press(k(KEY_LEFTCTRL));
        a.press(k(KEY_A));

        let mut b = PressedKeys::new();
        b.press(k(KEY_LEFTCTRL));
        b.press(k(KEY_A));
        b.press(k(KEY_B));

        assert_eq!(a.flush(), b.flush());
    }

    #[test]
    fn snapshot_does_not_mutate() {
        let mut p = PressedKeys::new();
        p.press(k(KEY_A));
        let snap = p.snapshot();
        assert_eq!(snap, vec![k(KEY_A)]);
        assert_eq!(p.len(), 1);
    }
}
