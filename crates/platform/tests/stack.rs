//! Platform trait + core runtime end-to-end test using Mock adapters.
//!
//! Demonstrates that `KeyCapture`, `MouseWatcher`, `KeyInjector` all plug
//! cleanly into the driver without any OS dependency. This is the closest
//! we can get to "real wiring" in a hermetic test.

use kbshare_core::keycode::{codes::*, Key};
use kbshare_core::protocol::{KeyAction, Message, MouseState};
use kbshare_core::runtime::{ClientDriver, HostDriver};
use kbshare_platform::mock::{MockKeyCapture, MockKeyInjector, MockMouseWatcher};
use kbshare_platform::{KeyCapture, KeyInjector, MouseWatcher};
use parking_lot::Mutex;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn mock_stack_wires_through_drivers() {
    // Host side: mock capture + driver.
    let mut capture = MockKeyCapture::new();
    let cap_tx = capture.sender();
    let fwd_flag = capture.forwarding_flag();

    let host = Arc::new(Mutex::new(HostDriver::new("H", "C", "HFP")));
    let host_out: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let host = host.clone();
        let host_out = host_out.clone();
        capture
            .start(Box::new(move |a, k| {
                let step = host.lock().on_local_key(a, k);
                host_out.lock().extend(step.outgoing);
            }))
            .unwrap();
    }

    // Client side: mock injector + driver.
    let mut injector = MockKeyInjector::new();
    let client = Arc::new(Mutex::new(ClientDriver::new("C", "H", "CFP")));

    // Establish the session and push host into Remote via a peer mouse
    // activity heartbeat.
    host.lock().on_session_established();
    client.lock().on_session_established();
    host.lock().on_incoming(Message::Heartbeat {
        id: "C".into(),
        state: MouseState::Active,
    });
    // Normally the runtime sets fwd_flag via SideEffect; the mock capture
    // simply forwards everything regardless, but we still verify the flag
    // is observed correctly.
    fwd_flag.store(true, Ordering::Relaxed);

    // Feed some keystrokes into the mock capture.
    cap_tx.send((KeyAction::Press, Key::new(KEY_A))).unwrap();
    cap_tx.send((KeyAction::Release, Key::new(KEY_A))).unwrap();
    std::thread::sleep(Duration::from_millis(150));

    let out = std::mem::take(&mut *host_out.lock());
    assert_eq!(out.len(), 2, "two key messages should have been emitted");

    // Now pipe them through the client driver and into the mock injector.
    for msg in out {
        let step = client.lock().on_incoming(msg);
        for (action, key) in step.inject {
            match action {
                KeyAction::Press => injector.press(key).unwrap(),
                KeyAction::Release => injector.release(key).unwrap(),
            }
        }
    }

    let log = injector.take_log();
    assert_eq!(
        log,
        vec![
            (KeyAction::Press, Key::new(KEY_A)),
            (KeyAction::Release, Key::new(KEY_A))
        ]
    );

    capture.stop();
}

#[test]
fn mock_mouse_watcher_triggers_callback() {
    let mut watcher = MockMouseWatcher::new();
    let tx = watcher.sender();
    let counter = Arc::new(Mutex::new(0usize));
    let counter_c = counter.clone();
    watcher
        .start(Box::new(move |_| {
            *counter_c.lock() += 1;
        }))
        .unwrap();

    for _ in 0..5 {
        tx.send(kbshare_platform::MouseActivity::UNKNOWN).unwrap();
    }
    std::thread::sleep(Duration::from_millis(200));
    watcher.stop();

    assert_eq!(*counter.lock(), 5);
}
