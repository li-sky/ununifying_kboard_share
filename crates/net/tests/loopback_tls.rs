//! TLS + TOFU + NDJSON end-to-end test over localhost TCP.
//!
//! Spins up a real TCP listener on 127.0.0.1, does a real rustls handshake
//! with self-signed certs, and then drives `HostDriver` + `ClientDriver`
//! through the actual wire. Nothing is mocked except the OS input layer.

use kbshare_core::codec::LineDecoder;
use kbshare_core::keycode::{codes::*, Key};
use kbshare_core::protocol::{KeyAction, Message};
use kbshare_core::runtime::{ClientDriver, HostDriver};
use kbshare_net::cert::{fingerprint_hex, load_or_create_cert};
use kbshare_net::session::{client_handshake, recv_message, send_message, server_handshake};
use kbshare_net::tls::{build_client_config, build_server_config};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn tmp_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "kbshare-net-it-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        name
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[test]
fn tls_tofu_then_end_to_end_keystroke() {
    let host_dir = tmp_path("host");
    let cli_dir = tmp_path("cli");

    let host_bundle = load_or_create_cert(
        &host_dir.join("cert.pem"),
        &host_dir.join("key.pem"),
        "host-it",
    )
    .unwrap();
    let cli_bundle = load_or_create_cert(
        &cli_dir.join("cert.pem"),
        &cli_dir.join("key.pem"),
        "client-it",
    )
    .unwrap();

    let host_fp = fingerprint_hex(&host_bundle.cert_der);
    let cli_fp = fingerprint_hex(&cli_bundle.cert_der);

    let server_cfg = build_server_config(&cli_bundle).unwrap();
    let client_cfg = build_client_config(&host_bundle).unwrap();

    // Bind an ephemeral port on localhost for the client side.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Client (receiver) thread.
    let (inject_tx, inject_rx) = mpsc::channel::<(KeyAction, Key)>();
    let server_cfg_c = server_cfg.clone();
    let cli_fp_c = cli_fp.clone();
    let client_thread = thread::spawn(move || {
        let (tcp, _addr) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let (mut stream, peer_fp_tls) = server_handshake(tcp, server_cfg_c).unwrap();
        assert!(peer_fp_tls.is_some(), "mTLS must present a client cert");

        let mut driver = ClientDriver::new("client-it", "host-it", cli_fp_c);
        let step = driver.on_session_established();
        for msg in &step.outgoing {
            send_message(&mut stream, msg).unwrap();
        }

        let mut decoder = LineDecoder::new();
        let mut verified = false;
        loop {
            match recv_message(&mut stream, &mut decoder) {
                Ok(Some(msg)) => {
                    if !verified {
                        if let Message::Hello {
                            id, fingerprint, ..
                        } = &msg
                        {
                            assert_eq!(id, "host-it");
                            assert_eq!(fingerprint.len(), 64);
                            verified = true;
                        }
                    }
                    let step = driver.on_incoming(msg);
                    for ev in step.inject {
                        inject_tx.send(ev).unwrap();
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    if e.to_string().to_lowercase().contains("timed out") {
                        continue;
                    }
                    break;
                }
            }
        }
    });

    // Host (sender) drives the connection.
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    tcp.set_nodelay(true).unwrap();
    let (mut stream, server_fp) = client_handshake(tcp, client_cfg, "client-it").unwrap();
    assert_eq!(
        server_fp, cli_fp,
        "TLS peer fingerprint must match client's cert"
    );

    let mut h = HostDriver::new("host-it", "client-it", host_fp);
    let step = h.on_session_established();
    for msg in &step.outgoing {
        send_message(&mut stream, msg).unwrap();
    }
    // Complete the application-level hello exchange before sending key data
    // or closing the socket. Otherwise the host can finish so quickly that
    // the receiver's first write races with teardown and sees BrokenPipe.
    let mut host_decoder = LineDecoder::new();
    loop {
        match recv_message(&mut stream, &mut host_decoder).unwrap() {
            Some(Message::Hello { id, .. }) => {
                assert_eq!(id, "client-it");
                break;
            }
            Some(_) | None => continue,
        }
    }

    // Push the host into Remote by reporting peer mouse activity.
    h.on_incoming(Message::Heartbeat {
        id: "client-it".into(),
        state: kbshare_core::protocol::MouseState::Active,
    });

    // Now type Ctrl+A and release both.
    for (action, code) in [
        (KeyAction::Press, KEY_LEFTCTRL),
        (KeyAction::Press, KEY_A),
        (KeyAction::Release, KEY_A),
        (KeyAction::Release, KEY_LEFTCTRL),
    ] {
        let step = h.on_local_key(action, Key::new(code));
        for msg in &step.outgoing {
            send_message(&mut stream, msg).unwrap();
        }
    }

    // Close the connection; client thread will exit, returning us all the
    // injections it observed.
    drop(stream);
    client_thread.join().unwrap();

    let mut got = Vec::new();
    while let Ok(ev) = inject_rx.try_recv() {
        got.push(ev);
    }
    let expected: Vec<_> = [
        (KeyAction::Press, KEY_LEFTCTRL),
        (KeyAction::Press, KEY_A),
        (KeyAction::Release, KEY_A),
        (KeyAction::Release, KEY_LEFTCTRL),
    ]
    .iter()
    .map(|(a, c)| (*a, Key::new(*c)))
    .collect();
    assert_eq!(got, expected);

    let _ = std::fs::remove_dir_all(&host_dir);
    let _ = std::fs::remove_dir_all(&cli_dir);
}

#[test]
fn handshake_retries_short_read_timeouts() {
    let host_dir = tmp_path("host-timeout");
    let cli_dir = tmp_path("cli-timeout");

    let host_bundle = load_or_create_cert(
        &host_dir.join("cert.pem"),
        &host_dir.join("key.pem"),
        "host-timeout",
    )
    .unwrap();
    let cli_bundle = load_or_create_cert(
        &cli_dir.join("cert.pem"),
        &cli_dir.join("key.pem"),
        "client-timeout",
    )
    .unwrap();

    let host_fp = fingerprint_hex(&host_bundle.cert_der);
    let cli_fp = fingerprint_hex(&cli_bundle.cert_der);

    let server_cfg = build_server_config(&cli_bundle).unwrap();
    let client_cfg = build_client_config(&host_bundle).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        tcp.set_nodelay(true).unwrap();

        thread::sleep(Duration::from_millis(30));

        let (_stream, peer_fp) = server_handshake(tcp, server_cfg).unwrap();
        assert_eq!(peer_fp.as_deref(), Some(host_fp.as_str()));
    });

    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    tcp.set_nodelay(true).unwrap();

    let (_stream, server_fp) = client_handshake(tcp, client_cfg, "client-timeout").unwrap();
    assert_eq!(server_fp, cli_fp);

    server.join().unwrap();

    let _ = std::fs::remove_dir_all(&host_dir);
    let _ = std::fs::remove_dir_all(&cli_dir);
}
