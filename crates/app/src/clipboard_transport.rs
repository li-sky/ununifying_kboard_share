//! Bounded transport worker. No OS clipboard access or image encoding here.
use super::*;
use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError, TrySendError};

const QUEUE_DEPTH: usize = 16;
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const PEER_TIMEOUT: Duration = Duration::from_secs(15);

/// Drive rustls records explicitly so blocked writes never prevent reading.
/// StreamOwned's blocking complete_io path cannot provide this guarantee.
pub(super) struct TlsIo {
    conn: rustls::Connection,
    tcp: TcpStream,
}
impl TlsIo {
    pub(super) fn new(mut conn: rustls::Connection, tcp: TcpStream) -> Result<Self> {
        tcp.set_nonblocking(true)?;
        conn.set_buffer_limit(Some(64 * 1024));
        Ok(Self { conn, tcp })
    }
}
impl Write for TlsIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.conn.writer().write(bytes)? {
            0 if !bytes.is_empty() => Err(ErrorKind::WouldBlock.into()),
            n => Ok(n),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            if self.conn.write_tls(&mut self.tcp)? == 0 {
                return Err(ErrorKind::WriteZero.into());
            }
        }
        Ok(())
    }
}
impl Read for TlsIo {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self.flush() {
            Err(error) if !is_transient_socket_error(&error) => return Err(error),
            _ => {}
        }
        match self.conn.reader().read(bytes) {
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            result => return result,
        }
        self.conn.read_tls(&mut self.tcp)?;
        self.conn
            .process_new_packets()
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        self.conn.reader().read(bytes)
    }
}

struct PendingFrame {
    bytes: Vec<u8>,
    offset: usize,
    last_progress: Instant,
}
impl PendingFrame {
    fn new(message: &ClipboardMessage) -> Result<Self> {
        let mut bytes = serde_json::to_vec(message)?;
        if bytes.len() > MAX_FRAME_BYTES {
            bail!("clipboard frame exceeds limit");
        }
        bytes.push(b'\n');
        Ok(Self {
            bytes,
            offset: 0,
            last_progress: Instant::now(),
        })
    }
    fn advance(&mut self, io: &mut dyn ClipboardIo) -> Result<bool> {
        if self.last_progress.elapsed() >= WRITE_STALL_TIMEOUT {
            bail!("clipboard write progress deadline exceeded");
        }
        if self.offset < self.bytes.len() {
            match io.write(&self.bytes[self.offset..]) {
                Ok(0) => bail!("clipboard write returned zero"),
                Ok(n) => {
                    self.offset += n;
                    self.last_progress = Instant::now();
                }
                Err(e) if is_transient_socket_error(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        match io.flush() {
            Ok(()) => Ok(self.offset == self.bytes.len()),
            Err(e) if is_transient_socket_error(&e) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

pub(super) struct SessionLink {
    outgoing: Sender<ClipboardMessage>,
    incoming: Receiver<ClipboardMessage>,
    stopped: Arc<AtomicBool>,
}
pub(super) struct Endpoint {
    outgoing: Receiver<ClipboardMessage>,
    incoming: Sender<ClipboardMessage>,
    stopped: Arc<AtomicBool>,
}
#[cfg(test)]
impl Endpoint {
    pub(super) fn drain(&self) -> Vec<ClipboardMessage> {
        self.outgoing.try_iter().collect()
    }
}

pub(super) fn channel() -> (SessionLink, Endpoint) {
    let (out_tx, out_rx) = bounded(QUEUE_DEPTH);
    let (in_tx, in_rx) = bounded(QUEUE_DEPTH);
    let stopped = Arc::new(AtomicBool::new(false));
    (
        SessionLink {
            outgoing: out_tx,
            incoming: in_rx,
            stopped: stopped.clone(),
        },
        Endpoint {
            outgoing: out_rx,
            incoming: in_tx,
            stopped,
        },
    )
}
impl SessionLink {
    pub(super) fn send(&self, message: ClipboardMessage) -> Result<()> {
        self.outgoing
            .send_timeout(message, WRITE_STALL_TIMEOUT)
            .map_err(|_| anyhow!("clipboard transport stopped or send queue stalled"))
    }
    pub(super) fn has_send_capacity(&self) -> bool {
        !self.outgoing.is_full()
    }
    pub(super) fn try_receive(&self) -> Result<Option<ClipboardMessage>> {
        match self.incoming.try_recv() {
            Ok(message) => Ok(Some(message)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => bail!("clipboard network worker stopped"),
        }
    }
    pub(super) fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }
}

struct Deadlines {
    started: Instant,
    last_rx: Instant,
    verified: bool,
}
impl Deadlines {
    fn check(&self, now: Instant) -> Result<()> {
        if !self.verified && now.duration_since(self.started) >= HELLO_TIMEOUT {
            bail!("clipboard Hello deadline exceeded");
        }
        if self.verified && now.duration_since(self.last_rx) >= PEER_TIMEOUT {
            bail!("clipboard peer heartbeat timed out");
        }
        Ok(())
    }
}

pub(super) fn run(
    config: &ClipboardConfig,
    mut stream: Box<dyn ClipboardIo>,
    peer_fp: Option<String>,
    trust: &TrustStore,
    shutdown: &AtomicBool,
    endpoint: Endpoint,
    clock: u64,
) -> Result<()> {
    let mut writing = Some(PendingFrame::new(&ClipboardMessage::Hello {
        id: config.local_id.clone(),
        fingerprint: config.our_fingerprint.clone(),
        version: CLIPBOARD_PROTOCOL_VERSION,
        clock,
    })?);
    let mut deadlines = Deadlines {
        started: Instant::now(),
        last_rx: Instant::now(),
        verified: false,
    };
    let mut last_tx = Instant::now();
    let mut decoder = FrameDecoder::default();
    let mut buffer = [0u8; 32768];
    let mut pending = None;
    while !shutdown.load(Ordering::Relaxed) && !endpoint.stopped.load(Ordering::Relaxed) {
        deadlines.check(Instant::now())?;
        if writing.is_none() {
            let message = if deadlines.verified && last_tx.elapsed() >= HEARTBEAT_INTERVAL {
                Some(ClipboardMessage::Heartbeat {
                    id: config.local_id.clone(),
                })
            } else {
                match endpoint.outgoing.try_recv() {
                    Ok(message) => Some(message),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => return Ok(()),
                }
            };
            if let Some(message) = message {
                writing = Some(PendingFrame::new(&message)?);
            }
        }
        if let Some(frame) = writing.as_mut() {
            if frame.advance(stream.as_mut())? {
                writing = None;
                last_tx = Instant::now();
            }
        }
        // Backpressure bounds memory while a clipboard backend is busy.
        if let Some(message) = pending.take() {
            match endpoint.incoming.try_send(message) {
                Ok(()) => {}
                Err(TrySendError::Full(message)) => {
                    pending = Some(message);
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(TrySendError::Disconnected(_)) => return Ok(()),
            }
        }
        if let Some(message) = decoder.next()? {
            deadlines.last_rx = Instant::now();
            if !deadlines.verified {
                verify_hello(config, trust, peer_fp.as_deref(), &message)?;
                deadlines.verified = true;
                pending = Some(message);
            } else if let ClipboardMessage::Heartbeat { id } = &message {
                if id != &config.remote_id {
                    bail!("clipboard heartbeat from unexpected peer");
                }
            } else {
                pending = Some(message);
            }
            continue;
        }
        match stream.read(&mut buffer) {
            Ok(0) => bail!("clipboard peer closed the connection"),
            Ok(read) => {
                // Large frames can take longer than one heartbeat interval on
                // slow links. Receiving bytes is still evidence of liveness.
                deadlines.last_rx = Instant::now();
                decoder.push(&buffer[..read]);
            }
            Err(error) if is_transient_socket_error(&error) => {
                std::thread::sleep(if writing.is_some() || !endpoint.outgoing.is_empty() {
                    Duration::from_millis(1)
                } else {
                    IDLE_SLEEP
                });
            }
            Err(error) => return Err(error).context("read clipboard TLS stream"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn silent_hello_and_missing_heartbeat_have_deadlines() {
        let now = Instant::now();
        let mut deadlines = Deadlines {
            started: now,
            last_rx: now,
            verified: false,
        };
        assert!(deadlines
            .check(now + HELLO_TIMEOUT)
            .unwrap_err()
            .to_string()
            .contains("Hello"));
        deadlines.verified = true;
        assert!(deadlines.check(now + HELLO_TIMEOUT).is_ok());
        assert!(deadlines
            .check(now + PEER_TIMEOUT)
            .unwrap_err()
            .to_string()
            .contains("heartbeat"));
    }
}

#[cfg(test)]
pub(super) fn write_test_frame(io: &mut dyn ClipboardIo, message: &ClipboardMessage) -> Result<()> {
    let mut frame = PendingFrame::new(message)?;
    while !frame.advance(io)? {}
    Ok(())
}

#[cfg(test)]
mod tls_tests {
    use super::*;

    #[test]
    fn tls_transfers_large_frames_in_both_directions_without_blocking_reads() {
        let a = super::super::state_tests::config("alpha", "beta");
        let b = super::super::state_tests::config("beta", "alpha");
        let a_trust = TrustStore::load(a.trust_store.clone()).unwrap();
        a_trust.learn("beta", &b.our_fingerprint).unwrap();
        let b_trust = TrustStore::load(b.trust_store.clone()).unwrap();
        b_trust.learn("alpha", &a.our_fingerprint).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stopped = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let (a_link, a_endpoint) = channel();
            let (b_link, b_endpoint) = channel();
            let b_thread = scope.spawn(|| {
                let (tcp, _) = listener.accept().unwrap();
                prepare_tcp(&tcp).unwrap();
                let (stream, fp) = server_handshake(tcp, b.server_tls.clone()).unwrap();
                let io = TlsIo::new(rustls::Connection::Server(stream.conn), stream.sock).unwrap();
                run(&b, Box::new(io), fp, &b_trust, &stopped, b_endpoint, 0)
            });
            let a_thread = scope.spawn(|| {
                let tcp = TcpStream::connect(address).unwrap();
                prepare_tcp(&tcp).unwrap();
                let (stream, fp) = client_handshake(tcp, a.client_tls.clone(), "beta").unwrap();
                let io = TlsIo::new(rustls::Connection::Client(stream.conn), stream.sock).unwrap();
                run(
                    &a,
                    Box::new(io),
                    Some(fp),
                    &a_trust,
                    &stopped,
                    a_endpoint,
                    0,
                )
            });
            // Always stop the workers even if an assertion fails.
            struct Stop<'a>(&'a AtomicBool);
            impl Drop for Stop<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Relaxed);
                }
            }
            let guard = Stop(&stopped);
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut hellos = [false; 2];
            while !hellos.iter().all(|v| *v) {
                for (i, link) in [&a_link, &b_link].iter().enumerate() {
                    if let Some(ClipboardMessage::Hello { .. }) = link.try_receive().unwrap() {
                        hellos[i] = true;
                    }
                }
                assert!(Instant::now() < deadline, "Hello exchange stalled");
                std::thread::sleep(Duration::from_millis(1));
            }
            // The application does no work here; the transport still services heartbeats.
            std::thread::sleep(Duration::from_millis(1100));
            for index in 0..8 {
                for (id, link) in [("alpha", &a_link), ("beta", &b_link)] {
                    link.send(ClipboardMessage::Text {
                        id: id.into(),
                        revision: Revision {
                            counter: index,
                            origin: id.into(),
                        },
                        content: TextContent {
                            text: "x".repeat(MAX_CLIPBOARD_BYTES),
                            html: None,
                            rtf: None,
                        },
                    })
                    .unwrap();
                }
            }
            let mut received = [0; 2];
            while received != [8, 8] {
                for (i, link) in [&a_link, &b_link].iter().enumerate() {
                    while let Some(message) = link.try_receive().unwrap() {
                        if let ClipboardMessage::Text {
                            revision, content, ..
                        } = message
                        {
                            assert_eq!(revision.counter, received[i]);
                            assert_eq!(content.text.len(), MAX_CLIPBOARD_BYTES);
                            received[i] += 1;
                        }
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "bidirectional TLS stalled: {received:?}"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            drop(guard);
            // One side can observe the other's close during simultaneous shutdown.
            for result in [a_thread.join().unwrap(), b_thread.join().unwrap()] {
                if let Err(error) = result {
                    assert!(
                        error.to_string().contains("closed")
                            || error.to_string().contains("end of file"),
                        "{error:#}"
                    );
                }
            }
        });
        std::fs::remove_dir_all(a.trust_store.parent().unwrap()).unwrap();
        std::fs::remove_dir_all(b.trust_store.parent().unwrap()).unwrap();
    }
}

#[cfg(test)]
mod heartbeat_test {
    use super::*;
    use parking_lot::Mutex;
    struct RecordingIo {
        read: io::Cursor<Vec<u8>>,
        written: Arc<Mutex<Vec<u8>>>,
    }
    impl Read for RecordingIo {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            match self.read.read(bytes)? {
                0 => Err(ErrorKind::WouldBlock.into()),
                n => Ok(n),
            }
        }
    }
    impl Write for RecordingIo {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.written.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn heartbeats_continue_while_application_does_not_poll() {
        let config = super::super::state_tests::config("alpha", "beta");
        let trust = TrustStore::load(config.trust_store.clone()).unwrap();
        trust.learn("beta", "peer-fp").unwrap();
        let mut hello = serde_json::to_vec(&ClipboardMessage::Hello {
            id: "beta".into(),
            fingerprint: "peer-fp".into(),
            version: CLIPBOARD_PROTOCOL_VERSION,
            clock: 0,
        })
        .unwrap();
        hello.push(b'\n');
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = RecordingIo {
            read: io::Cursor::new(hello),
            written: written.clone(),
        };
        let (_application, endpoint) = channel();
        let stopped = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                run(
                    &config,
                    Box::new(io),
                    Some("peer-fp".into()),
                    &trust,
                    &stopped,
                    endpoint,
                    0,
                )
            });
            let until = Instant::now() + Duration::from_secs(3);
            let mut heartbeat_seen = false;
            while Instant::now() < until {
                let mut decoder = FrameDecoder::default();
                decoder.push(&written.lock());
                while let Some(message) = decoder.next().unwrap() {
                    if matches!(message, ClipboardMessage::Heartbeat { .. }) {
                        heartbeat_seen = true;
                    }
                }
                if heartbeat_seen {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            stopped.store(true, Ordering::Relaxed);
            worker.join().unwrap().unwrap();
            assert!(
                heartbeat_seen,
                "application inactivity suppressed network heartbeats"
            );
        });
        std::fs::remove_dir_all(config.trust_store.parent().unwrap()).unwrap();
    }
}
