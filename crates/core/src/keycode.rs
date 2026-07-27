//! Cross-platform logical key codes.
//!
//! We chose the Linux evdev `KEY_*` numbering space as our logical key space,
//! because it is exhaustive, stable, and already what we need on Linux. For
//! Windows we translate via an explicit virtual-key <-> evdev table.
//!
//! The wire format carries the evdev code directly. This means protocol
//! captures are identical regardless of the sender's OS.

use serde::{Deserialize, Serialize};

/// A logical key, stored as its Linux evdev code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Key(pub u16);

impl Key {
    pub const fn new(code: u16) -> Self {
        Self(code)
    }
    pub const fn code(self) -> u16 {
        self.0
    }
}

impl From<u16> for Key {
    fn from(v: u16) -> Self {
        Key(v)
    }
}

// -- evdev codes (subset). Full list lives in linux/input-event-codes.h.
// We list the keys we actually translate. Unmapped codes still pass through
// on the wire; only the OS adapters need to know how to emit them.

pub mod codes {
    pub const KEY_ESC: u16 = 1;
    pub const KEY_1: u16 = 2;
    pub const KEY_2: u16 = 3;
    pub const KEY_3: u16 = 4;
    pub const KEY_4: u16 = 5;
    pub const KEY_5: u16 = 6;
    pub const KEY_6: u16 = 7;
    pub const KEY_7: u16 = 8;
    pub const KEY_8: u16 = 9;
    pub const KEY_9: u16 = 10;
    pub const KEY_0: u16 = 11;
    pub const KEY_MINUS: u16 = 12;
    pub const KEY_EQUAL: u16 = 13;
    pub const KEY_BACKSPACE: u16 = 14;
    pub const KEY_TAB: u16 = 15;
    pub const KEY_Q: u16 = 16;
    pub const KEY_W: u16 = 17;
    pub const KEY_E: u16 = 18;
    pub const KEY_R: u16 = 19;
    pub const KEY_T: u16 = 20;
    pub const KEY_Y: u16 = 21;
    pub const KEY_U: u16 = 22;
    pub const KEY_I: u16 = 23;
    pub const KEY_O: u16 = 24;
    pub const KEY_P: u16 = 25;
    pub const KEY_LEFTBRACE: u16 = 26;
    pub const KEY_RIGHTBRACE: u16 = 27;
    pub const KEY_ENTER: u16 = 28;
    pub const KEY_LEFTCTRL: u16 = 29;
    pub const KEY_A: u16 = 30;
    pub const KEY_S: u16 = 31;
    pub const KEY_D: u16 = 32;
    pub const KEY_F: u16 = 33;
    pub const KEY_G: u16 = 34;
    pub const KEY_H: u16 = 35;
    pub const KEY_J: u16 = 36;
    pub const KEY_K: u16 = 37;
    pub const KEY_L: u16 = 38;
    pub const KEY_SEMICOLON: u16 = 39;
    pub const KEY_APOSTROPHE: u16 = 40;
    pub const KEY_GRAVE: u16 = 41;
    pub const KEY_LEFTSHIFT: u16 = 42;
    pub const KEY_BACKSLASH: u16 = 43;
    pub const KEY_Z: u16 = 44;
    pub const KEY_X: u16 = 45;
    pub const KEY_C: u16 = 46;
    pub const KEY_V: u16 = 47;
    pub const KEY_B: u16 = 48;
    pub const KEY_N: u16 = 49;
    pub const KEY_M: u16 = 50;
    pub const KEY_COMMA: u16 = 51;
    pub const KEY_DOT: u16 = 52;
    pub const KEY_SLASH: u16 = 53;
    pub const KEY_RIGHTSHIFT: u16 = 54;
    pub const KEY_KPASTERISK: u16 = 55;
    pub const KEY_LEFTALT: u16 = 56;
    pub const KEY_SPACE: u16 = 57;
    pub const KEY_CAPSLOCK: u16 = 58;
    pub const KEY_F1: u16 = 59;
    pub const KEY_F2: u16 = 60;
    pub const KEY_F3: u16 = 61;
    pub const KEY_F4: u16 = 62;
    pub const KEY_F5: u16 = 63;
    pub const KEY_F6: u16 = 64;
    pub const KEY_F7: u16 = 65;
    pub const KEY_F8: u16 = 66;
    pub const KEY_F9: u16 = 67;
    pub const KEY_F10: u16 = 68;
    pub const KEY_NUMLOCK: u16 = 69;
    pub const KEY_SCROLLLOCK: u16 = 70;
    // Numeric keypad (numpad). When NumLock is on these emit digits; when
    // off they emit navigation. We carry the dedicated evdev codes so the
    // peer can reproduce the exact physical key, regardless of the local
    // NumLock state.
    pub const KEY_KP7: u16 = 71;
    pub const KEY_KP8: u16 = 72;
    pub const KEY_KP9: u16 = 73;
    pub const KEY_KPMINUS: u16 = 74;
    pub const KEY_KP4: u16 = 75;
    pub const KEY_KP5: u16 = 76;
    pub const KEY_KP6: u16 = 77;
    pub const KEY_KPPLUS: u16 = 78;
    pub const KEY_KP1: u16 = 79;
    pub const KEY_KP2: u16 = 80;
    pub const KEY_KP3: u16 = 81;
    pub const KEY_KP0: u16 = 82;
    pub const KEY_KPDOT: u16 = 83;
    pub const KEY_KPENTER: u16 = 96;
    pub const KEY_KPSLASH: u16 = 98;
    pub const KEY_F11: u16 = 87;
    pub const KEY_F12: u16 = 88;
    pub const KEY_RIGHTCTRL: u16 = 97;
    pub const KEY_RIGHTALT: u16 = 100;
    pub const KEY_HOME: u16 = 102;
    pub const KEY_UP: u16 = 103;
    pub const KEY_PAGEUP: u16 = 104;
    pub const KEY_LEFT: u16 = 105;
    pub const KEY_RIGHT: u16 = 106;
    pub const KEY_END: u16 = 107;
    pub const KEY_DOWN: u16 = 108;
    pub const KEY_PAGEDOWN: u16 = 109;
    pub const KEY_INSERT: u16 = 110;
    pub const KEY_DELETE: u16 = 111;
    pub const KEY_PAUSE: u16 = 119;
    pub const KEY_LEFTMETA: u16 = 125;
    pub const KEY_RIGHTMETA: u16 = 126;
    pub const KEY_PRINT: u16 = 99;
}

/// Translate a Windows Virtual-Key code into our logical key space.
pub fn from_win_vk(vk: u32) -> Option<Key> {
    let c = match vk {
        0x08 => codes::KEY_BACKSPACE,
        0x09 => codes::KEY_TAB,
        0x0D => codes::KEY_ENTER,
        0x10 => codes::KEY_LEFTSHIFT, // generic shift -> left
        0x11 => codes::KEY_LEFTCTRL,  // generic ctrl -> left
        0x12 => codes::KEY_LEFTALT,   // generic alt -> left
        0x13 => codes::KEY_PAUSE,
        0x14 => codes::KEY_CAPSLOCK,
        0x1B => codes::KEY_ESC,
        0x20 => codes::KEY_SPACE,
        0x21 => codes::KEY_PAGEUP,
        0x22 => codes::KEY_PAGEDOWN,
        0x23 => codes::KEY_END,
        0x24 => codes::KEY_HOME,
        0x25 => codes::KEY_LEFT,
        0x26 => codes::KEY_UP,
        0x27 => codes::KEY_RIGHT,
        0x28 => codes::KEY_DOWN,
        0x2C => codes::KEY_PRINT,
        0x2D => codes::KEY_INSERT,
        0x2E => codes::KEY_DELETE,
        0x30..=0x39 => {
            // '0'..'9'
            let n = (vk - 0x30) as u16;
            return Some(Key(if n == 0 {
                codes::KEY_0
            } else {
                codes::KEY_1 + n - 1
            }));
        }
        0x41..=0x5A => {
            // 'A'..'Z' -> evdev rows
            return Some(Key(vk_letter_to_evdev(vk as u8)?));
        }
        0x5B => codes::KEY_LEFTMETA,
        0x5C => codes::KEY_RIGHTMETA,
        0x70 => codes::KEY_F1,
        0x71 => codes::KEY_F2,
        0x72 => codes::KEY_F3,
        0x73 => codes::KEY_F4,
        0x74 => codes::KEY_F5,
        0x75 => codes::KEY_F6,
        0x76 => codes::KEY_F7,
        0x77 => codes::KEY_F8,
        0x78 => codes::KEY_F9,
        0x79 => codes::KEY_F10,
        0x7A => codes::KEY_F11,
        0x7B => codes::KEY_F12,
        0x90 => codes::KEY_NUMLOCK,
        0x91 => codes::KEY_SCROLLLOCK,
        // Numpad digit keys (VK_NUMPAD0..VK_NUMPAD9). These are emitted
        // independently of NumLock state by the LL hook, so we map them to
        // the dedicated KP codes rather than folding them onto KEY_0..KEY_9.
        0x60 => codes::KEY_KP0,
        0x61 => codes::KEY_KP1,
        0x62 => codes::KEY_KP2,
        0x63 => codes::KEY_KP3,
        0x64 => codes::KEY_KP4,
        0x65 => codes::KEY_KP5,
        0x66 => codes::KEY_KP6,
        0x67 => codes::KEY_KP7,
        0x68 => codes::KEY_KP8,
        0x69 => codes::KEY_KP9,
        0x6A => codes::KEY_KPASTERISK,
        0x6B => codes::KEY_KPPLUS,
        0x6D => codes::KEY_KPMINUS,
        0x6E => codes::KEY_KPDOT,
        0x6F => codes::KEY_KPSLASH,
        // Numpad Enter comes through as VK_RETURN (0x0D) just like the
        // main Enter key. The LL hook sets the KBDLLHOOKSTRUCT flags with
        // LLKHF_EXTENDED when the event originated from the numpad Enter,
        // but from_win_vk only sees the VK. We keep mapping 0x0D to the
        // main KEY_ENTER above; numpad Enter is handled at the capture
        // site via the extended-key flag (see win.rs).
        0xA0 => codes::KEY_LEFTSHIFT,
        0xA1 => codes::KEY_RIGHTSHIFT,
        0xA2 => codes::KEY_LEFTCTRL,
        0xA3 => codes::KEY_RIGHTCTRL,
        0xA4 => codes::KEY_LEFTALT,
        0xA5 => codes::KEY_RIGHTALT,
        0xBA => codes::KEY_SEMICOLON,
        0xBB => codes::KEY_EQUAL,
        0xBC => codes::KEY_COMMA,
        0xBD => codes::KEY_MINUS,
        0xBE => codes::KEY_DOT,
        0xBF => codes::KEY_SLASH,
        0xC0 => codes::KEY_GRAVE,
        0xDB => codes::KEY_LEFTBRACE,
        0xDC => codes::KEY_BACKSLASH,
        0xDD => codes::KEY_RIGHTBRACE,
        0xDE => codes::KEY_APOSTROPHE,
        _ => return None,
    };
    Some(Key(c))
}

/// Translate our logical key back into a Windows Virtual-Key code.
pub fn to_win_vk(key: Key) -> Option<u32> {
    let c = key.0;
    let vk = match c {
        codes::KEY_BACKSPACE => 0x08,
        codes::KEY_TAB => 0x09,
        codes::KEY_ENTER => 0x0D,
        // Numpad Enter shares VK_RETURN with the main Enter key. The
        // injector sets KEYEVENTF_EXTENDEDKEY for KPENTER so apps can tell
        // them apart (see win.rs is_extended_vk).
        codes::KEY_KPENTER => 0x0D,
        codes::KEY_PAUSE => 0x13,
        codes::KEY_CAPSLOCK => 0x14,
        codes::KEY_ESC => 0x1B,
        codes::KEY_SPACE => 0x20,
        codes::KEY_PAGEUP => 0x21,
        codes::KEY_PAGEDOWN => 0x22,
        codes::KEY_END => 0x23,
        codes::KEY_HOME => 0x24,
        codes::KEY_LEFT => 0x25,
        codes::KEY_UP => 0x26,
        codes::KEY_RIGHT => 0x27,
        codes::KEY_DOWN => 0x28,
        codes::KEY_PRINT => 0x2C,
        codes::KEY_INSERT => 0x2D,
        codes::KEY_DELETE => 0x2E,
        codes::KEY_0 => 0x30,
        codes::KEY_1 => 0x31,
        codes::KEY_2 => 0x32,
        codes::KEY_3 => 0x33,
        codes::KEY_4 => 0x34,
        codes::KEY_5 => 0x35,
        codes::KEY_6 => 0x36,
        codes::KEY_7 => 0x37,
        codes::KEY_8 => 0x38,
        codes::KEY_9 => 0x39,
        codes::KEY_LEFTMETA => 0x5B,
        codes::KEY_RIGHTMETA => 0x5C,
        codes::KEY_F1 => 0x70,
        codes::KEY_F2 => 0x71,
        codes::KEY_F3 => 0x72,
        codes::KEY_F4 => 0x73,
        codes::KEY_F5 => 0x74,
        codes::KEY_F6 => 0x75,
        codes::KEY_F7 => 0x76,
        codes::KEY_F8 => 0x77,
        codes::KEY_F9 => 0x78,
        codes::KEY_F10 => 0x79,
        codes::KEY_F11 => 0x7A,
        codes::KEY_F12 => 0x7B,
        codes::KEY_NUMLOCK => 0x90,
        codes::KEY_SCROLLLOCK => 0x91,
        codes::KEY_KP0 => 0x60,
        codes::KEY_KP1 => 0x61,
        codes::KEY_KP2 => 0x62,
        codes::KEY_KP3 => 0x63,
        codes::KEY_KP4 => 0x64,
        codes::KEY_KP5 => 0x65,
        codes::KEY_KP6 => 0x66,
        codes::KEY_KP7 => 0x67,
        codes::KEY_KP8 => 0x68,
        codes::KEY_KP9 => 0x69,
        codes::KEY_KPASTERISK => 0x6A,
        codes::KEY_KPPLUS => 0x6B,
        codes::KEY_KPMINUS => 0x6D,
        codes::KEY_KPDOT => 0x6E,
        codes::KEY_KPSLASH => 0x6F,
        // KEY_KPENTER is handled below together with KEY_ENTER, since both
        // map to VK_RETURN (0x0D). The injector distinguishes them via the
        // extended-key flag.
        codes::KEY_LEFTSHIFT => 0xA0,
        codes::KEY_RIGHTSHIFT => 0xA1,
        codes::KEY_LEFTCTRL => 0xA2,
        codes::KEY_RIGHTCTRL => 0xA3,
        codes::KEY_LEFTALT => 0xA4,
        codes::KEY_RIGHTALT => 0xA5,
        codes::KEY_SEMICOLON => 0xBA,
        codes::KEY_EQUAL => 0xBB,
        codes::KEY_COMMA => 0xBC,
        codes::KEY_MINUS => 0xBD,
        codes::KEY_DOT => 0xBE,
        codes::KEY_SLASH => 0xBF,
        codes::KEY_GRAVE => 0xC0,
        codes::KEY_LEFTBRACE => 0xDB,
        codes::KEY_BACKSLASH => 0xDC,
        codes::KEY_RIGHTBRACE => 0xDD,
        codes::KEY_APOSTROPHE => 0xDE,
        _ => return evdev_letter_to_vk(c),
    };
    Some(vk)
}

fn vk_letter_to_evdev(vk: u8) -> Option<u16> {
    // VK 'A'..'Z' == 0x41..0x5A
    let table: &[(u8, u16)] = &[
        (b'A', codes::KEY_A),
        (b'B', codes::KEY_B),
        (b'C', codes::KEY_C),
        (b'D', codes::KEY_D),
        (b'E', codes::KEY_E),
        (b'F', codes::KEY_F),
        (b'G', codes::KEY_G),
        (b'H', codes::KEY_H),
        (b'I', codes::KEY_I),
        (b'J', codes::KEY_J),
        (b'K', codes::KEY_K),
        (b'L', codes::KEY_L),
        (b'M', codes::KEY_M),
        (b'N', codes::KEY_N),
        (b'O', codes::KEY_O),
        (b'P', codes::KEY_P),
        (b'Q', codes::KEY_Q),
        (b'R', codes::KEY_R),
        (b'S', codes::KEY_S),
        (b'T', codes::KEY_T),
        (b'U', codes::KEY_U),
        (b'V', codes::KEY_V),
        (b'W', codes::KEY_W),
        (b'X', codes::KEY_X),
        (b'Y', codes::KEY_Y),
        (b'Z', codes::KEY_Z),
    ];
    table.iter().find(|(v, _)| *v == vk).map(|(_, c)| *c)
}

fn evdev_letter_to_vk(code: u16) -> Option<u32> {
    let table: &[(u16, u32)] = &[
        (codes::KEY_A, 0x41),
        (codes::KEY_B, 0x42),
        (codes::KEY_C, 0x43),
        (codes::KEY_D, 0x44),
        (codes::KEY_E, 0x45),
        (codes::KEY_F, 0x46),
        (codes::KEY_G, 0x47),
        (codes::KEY_H, 0x48),
        (codes::KEY_I, 0x49),
        (codes::KEY_J, 0x4A),
        (codes::KEY_K, 0x4B),
        (codes::KEY_L, 0x4C),
        (codes::KEY_M, 0x4D),
        (codes::KEY_N, 0x4E),
        (codes::KEY_O, 0x4F),
        (codes::KEY_P, 0x50),
        (codes::KEY_Q, 0x51),
        (codes::KEY_R, 0x52),
        (codes::KEY_S, 0x53),
        (codes::KEY_T, 0x54),
        (codes::KEY_U, 0x55),
        (codes::KEY_V, 0x56),
        (codes::KEY_W, 0x57),
        (codes::KEY_X, 0x58),
        (codes::KEY_Y, 0x59),
        (codes::KEY_Z, 0x5A),
    ];
    table.iter().find(|(c, _)| *c == code).map(|(_, v)| *v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_roundtrip() {
        for vk in 0x41u32..=0x5A {
            let k = from_win_vk(vk).expect("letter must map");
            assert_eq!(to_win_vk(k), Some(vk), "letter vk {:#x} roundtrip", vk);
        }
    }

    #[test]
    fn digits_roundtrip() {
        for vk in 0x30u32..=0x39 {
            let k = from_win_vk(vk).expect("digit must map");
            assert_eq!(to_win_vk(k), Some(vk), "digit vk {:#x} roundtrip", vk);
        }
    }

    #[test]
    fn modifiers_distinguish_left_right() {
        // Explicit left/right VKs keep their side.
        assert_eq!(from_win_vk(0xA0), Some(Key(codes::KEY_LEFTSHIFT)));
        assert_eq!(from_win_vk(0xA1), Some(Key(codes::KEY_RIGHTSHIFT)));
        assert_eq!(from_win_vk(0xA2), Some(Key(codes::KEY_LEFTCTRL)));
        assert_eq!(from_win_vk(0xA3), Some(Key(codes::KEY_RIGHTCTRL)));
        assert_eq!(from_win_vk(0xA4), Some(Key(codes::KEY_LEFTALT)));
        assert_eq!(from_win_vk(0xA5), Some(Key(codes::KEY_RIGHTALT)));
    }

    #[test]
    fn generic_modifiers_fold_to_left() {
        // Generic modifier VKs (no side) fold to the left-side logical key.
        // Intentional: on Windows the LL-hook delivers the specific VK, but
        // if we ever see a generic one we must not drop it.
        assert_eq!(from_win_vk(0x10), Some(Key(codes::KEY_LEFTSHIFT)));
        assert_eq!(from_win_vk(0x11), Some(Key(codes::KEY_LEFTCTRL)));
        assert_eq!(from_win_vk(0x12), Some(Key(codes::KEY_LEFTALT)));
    }

    #[test]
    fn function_keys_roundtrip() {
        for vk in 0x70u32..=0x7B {
            let k = from_win_vk(vk).expect("F-key must map");
            assert_eq!(to_win_vk(k), Some(vk));
        }
    }

    #[test]
    fn numpad_digits_roundtrip() {
        // VK_NUMPAD0..VK_NUMPAD9 == 0x60..0x69
        let expected = [
            codes::KEY_KP0,
            codes::KEY_KP1,
            codes::KEY_KP2,
            codes::KEY_KP3,
            codes::KEY_KP4,
            codes::KEY_KP5,
            codes::KEY_KP6,
            codes::KEY_KP7,
            codes::KEY_KP8,
            codes::KEY_KP9,
        ];
        for (i, want) in expected.iter().enumerate() {
            let vk = 0x60 + i as u32;
            let k = from_win_vk(vk).expect("numpad digit must map");
            assert_eq!(k, Key(*want), "numpad digit vk {:#x}", vk);
            assert_eq!(to_win_vk(k), Some(vk), "numpad digit vk {:#x} roundtrip", vk);
        }
    }

    #[test]
    fn numpad_operators_roundtrip() {
        // The arithmetic operators on the numpad each have a dedicated VK.
        let cases: &[(u32, u16)] = &[
            (0x6A, codes::KEY_KPASTERISK), // VK_MULTIPLY
            (0x6B, codes::KEY_KPPLUS),     // VK_ADD
            (0x6D, codes::KEY_KPMINUS),    // VK_SUBTRACT
            (0x6E, codes::KEY_KPDOT),      // VK_DECIMAL
            (0x6F, codes::KEY_KPSLASH),     // VK_DIVIDE
        ];
        for (vk, want) in cases {
            let k = from_win_vk(*vk).expect("numpad operator must map");
            assert_eq!(k, Key(*want), "numpad operator vk {:#x}", vk);
            assert_eq!(to_win_vk(k), Some(*vk), "numpad operator vk {:#x} roundtrip", vk);
        }
    }

    #[test]
    fn numpad_enter_maps_to_vk_return() {
        // Numpad Enter shares VK_RETURN (0x0D) with the main Enter key.
        // The capture site distinguishes them via the LLKHF_EXTENDED flag;
        // here we only verify the forward mapping collapses onto 0x0D.
        assert_eq!(to_win_vk(Key(codes::KEY_KPENTER)), Some(0x0D));
        assert_eq!(to_win_vk(Key(codes::KEY_ENTER)), Some(0x0D));
    }

    #[test]
    fn unknown_vk_returns_none() {
        // 0x07 is undefined in the VK space.
        assert_eq!(from_win_vk(0x07), None);
    }
}
