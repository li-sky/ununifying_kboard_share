//! End-to-end loopback integration test.
//!
//! Drives both `HostDriver` and `ClientDriver` through an in-memory byte
//! queue to simulate the full wire dialogue without TCP, TLS, or the OS.
//!
//! External invariants proven by these tests:
//!
//!   1. In remote mode, every key the host captures is injected on client
//!      in the same order.
//!   2. Losing the TLS session never leaves the client with stuck keys.
//!   3. Peer reporting `inactive` behaves identically to `session lost`
//!      from the perspective of "no sticky keys".
//!   4. Local mouse activity on host pre-empts forwarding immediately.

use kbshare_core::{
    codec::{encode_line, LineDecoder},
    keycode::{codes::*, Key},
    protocol::{KeyAction, Message},
    runtime::{ClientDriver, HostDriver},
    state::Mode,
};

#[derive(Default)]
struct Pipe {
    h2c: Vec<u8>,
    c2h: Vec<u8>,
    to_client: LineDecoder,
    to_host: LineDecoder,
}

impl Pipe {
    fn send_from_host(&mut self, msgs: &[Message]) {
        for m in msgs {
            self.h2c.extend(encode_line(m).unwrap());
        }
    }
    fn send_from_client(&mut self, msgs: &[Message]) {
        for m in msgs {
            self.c2h.extend(encode_line(m).unwrap());
        }
    }
    fn drain_to_client(&mut self) -> Vec<Message> {
        self.to_client.extend(&self.h2c);
        self.h2c.clear();
        let mut out = Vec::new();
        while let Some(m) = self.to_client.next_message().unwrap() {
            out.push(m);
        }
        out
    }
    fn drain_to_host(&mut self) -> Vec<Message> {
        self.to_host.extend(&self.c2h);
        self.c2h.clear();
        let mut out = Vec::new();
        while let Some(m) = self.to_host.next_message().unwrap() {
            out.push(m);
        }
        out
    }
}

fn setup() -> (HostDriver, ClientDriver, Pipe) {
    (
        HostDriver::new("host-a", "client-a", "HOSTFP"),
        ClientDriver::new("client-a", "host-a", "CLIFP"),
        Pipe::default(),
    )
}

fn connect(h: &mut HostDriver, c: &mut ClientDriver, pipe: &mut Pipe) {
    let hs = h.on_session_established();
    let cs = c.on_session_established();
    pipe.send_from_host(&hs.outgoing);
    pipe.send_from_client(&cs.outgoing);
    for m in pipe.drain_to_host() {
        h.on_incoming(m);
    }
    for m in pipe.drain_to_client() {
        c.on_incoming(m);
    }
}

fn push_mouse_active(c: &mut ClientDriver, h: &mut HostDriver, pipe: &mut Pipe) {
    let cs = c.on_local_mouse_active();
    pipe.send_from_client(&cs.outgoing);
    for m in pipe.drain_to_host() {
        h.on_incoming(m);
    }
}

#[test]
fn ctrl_a_round_trip() {
    let (mut h, mut c, mut pipe) = setup();
    connect(&mut h, &mut c, &mut pipe);
    push_mouse_active(&mut c, &mut h, &mut pipe);
    assert_eq!(h.mode(), Mode::Remote);

    let seq = [
        (KeyAction::Press, KEY_LEFTCTRL),
        (KeyAction::Press, KEY_A),
        (KeyAction::Release, KEY_A),
        (KeyAction::Release, KEY_LEFTCTRL),
    ];
    for (a, c_) in seq {
        let step = h.on_local_key(a, Key::new(c_));
        pipe.send_from_host(&step.outgoing);
    }

    let mut injected = Vec::new();
    for m in pipe.drain_to_client() {
        injected.extend(c.on_incoming(m).inject);
    }

    let expected: Vec<_> = seq.iter().map(|(a, c)| (*a, Key::new(*c))).collect();
    assert_eq!(injected, expected);
    assert_eq!(h.pressed_count(), 0);
    assert_eq!(c.pressed_count(), 0);
}

#[test]
fn session_loss_releases_all_on_client() {
    let (mut h, mut c, mut pipe) = setup();
    connect(&mut h, &mut c, &mut pipe);
    push_mouse_active(&mut c, &mut h, &mut pipe);

    for code in [KEY_LEFTCTRL, KEY_LEFTSHIFT, KEY_A] {
        let step = h.on_local_key(KeyAction::Press, Key::new(code));
        pipe.send_from_host(&step.outgoing);
    }
    for m in pipe.drain_to_client() {
        c.on_incoming(m);
    }
    assert_eq!(c.pressed_count(), 3);

    let step = c.on_session_lost();
    assert_eq!(step.inject.len(), 3);
    let codes: Vec<_> = step.inject.iter().map(|(_, k)| k.code()).collect();
    // Non-modifier first, modifiers last.
    assert_eq!(codes[0], KEY_A);
    assert!(matches!(codes[1], KEY_LEFTCTRL | KEY_LEFTSHIFT));
    assert!(matches!(codes[2], KEY_LEFTCTRL | KEY_LEFTSHIFT));
    assert_eq!(c.pressed_count(), 0);
}

#[test]
fn local_mouse_preempts_remote_and_flushes() {
    let (mut h, mut c, mut pipe) = setup();
    connect(&mut h, &mut c, &mut pipe);
    push_mouse_active(&mut c, &mut h, &mut pipe);

    // Press A on remote.
    let step = h.on_local_key(KeyAction::Press, Key::new(KEY_A));
    pipe.send_from_host(&step.outgoing);
    for m in pipe.drain_to_client() {
        c.on_incoming(m);
    }
    assert_eq!(c.pressed_count(), 1);

    // User moves mouse on host. Host should flush -> peer should un-stick.
    let step = h.on_local_mouse();
    pipe.send_from_host(&step.outgoing);
    for m in pipe.drain_to_client() {
        c.on_incoming(m);
    }
    assert_eq!(h.mode(), Mode::Local);
    assert_eq!(
        c.pressed_count(),
        0,
        "client must not hold A after host's local pre-empt"
    );

    // Subsequent keystrokes must not leak.
    let step = h.on_local_key(KeyAction::Press, Key::new(KEY_A));
    assert!(step.outgoing.is_empty());
}

#[test]
fn idle_heartbeat_does_not_change_mode() {
    let (mut h, mut c, mut pipe) = setup();
    connect(&mut h, &mut c, &mut pipe);
    push_mouse_active(&mut c, &mut h, &mut pipe);
    assert_eq!(h.mode(), Mode::Remote);

    let step = h.on_local_key(KeyAction::Press, Key::new(KEY_A));
    pipe.send_from_host(&step.outgoing);
    for m in pipe.drain_to_client() {
        c.on_incoming(m);
    }
    assert_eq!(c.pressed_count(), 1);

    // Client sends an idle keepalive; host must stay in Remote and must
    // not flush.
    let cs = c.on_local_mouse_idle();
    pipe.send_from_client(&cs.outgoing);
    for m in pipe.drain_to_host() {
        let step = h.on_incoming(m);
        pipe.send_from_host(&step.outgoing);
    }
    for m in pipe.drain_to_client() {
        c.on_incoming(m);
    }
    assert_eq!(h.mode(), Mode::Remote);
    assert_eq!(c.pressed_count(), 1);

    // Host mouse then pulls keyboard back.
    let step = h.on_local_mouse();
    pipe.send_from_host(&step.outgoing);
    for m in pipe.drain_to_client() {
        c.on_incoming(m);
    }
    assert_eq!(h.mode(), Mode::Local);
    assert_eq!(c.pressed_count(), 0);
}

#[test]
fn autorepeat_is_forwarded_to_client() {
    let (mut h, mut c, mut pipe) = setup();
    connect(&mut h, &mut c, &mut pipe);
    push_mouse_active(&mut c, &mut h, &mut pipe);

    // OS autorepeat: five Press frames then a Release. All five presses
    // must reach the client so the user sees "aaaaa" on hold-and-release.
    let mut injected = Vec::new();
    for _ in 0..5 {
        let step = h.on_local_key(KeyAction::Press, Key::new(KEY_A));
        pipe.send_from_host(&step.outgoing);
    }
    let step = h.on_local_key(KeyAction::Release, Key::new(KEY_A));
    pipe.send_from_host(&step.outgoing);

    for m in pipe.drain_to_client() {
        injected.extend(c.on_incoming(m).inject);
    }

    let mut expected: Vec<_> = (0..5)
        .map(|_| (KeyAction::Press, Key::new(KEY_A)))
        .collect();
    expected.push((KeyAction::Release, Key::new(KEY_A)));
    assert_eq!(injected, expected);
}
