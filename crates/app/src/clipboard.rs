//! Clipboard synchronization over a dedicated TLS connection.
//!
//! This channel deliberately does not share a socket, lock, or thread with
//! keyboard forwarding. Clipboard access can block in a compositor and large
//! text payloads can take time to encrypt; neither is allowed onto the
//! latency-sensitive keyboard path.

#[path = "clipboard_files.rs"]
mod files;

use anyhow::{anyhow, bail, Context, Result};
use clipboard_rs::{Clipboard, ClipboardContext};
use files::{FileTransferMessage, FileTransfers};
use kbshare_net::registry::RegistryClient;
use kbshare_net::session::{client_handshake, server_handshake};
use kbshare_net::trust::{AutoTrustPolicy, TrustDecision, TrustStore};
use rustls::{ClientConfig, ServerConfig};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CLIPBOARD_PROTOCOL_VERSION: u32 = 2;
const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;
// JSON may encode one control byte as a six-byte `\u00xx` escape.
const MAX_FRAME_BYTES: usize = MAX_CLIPBOARD_BYTES * 6 + 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const IO_TIMEOUT: Duration = Duration::from_millis(20);
const IDLE_SLEEP: Duration = Duration::from_millis(20);
const RETAINED_FILE_TRANSFERS: usize = 3;

#[derive(Clone)]
pub struct ClipboardConfig {
    pub enabled: bool,
    pub local_id: String,
    pub remote_id: String,
    pub keyboard_port: u16,
    pub port: u16,
    pub fallback_remote_ips: Vec<String>,
    pub vps_base_url: Option<String>,
    pub reconnect_secs: u64,
    pub trust_store: PathBuf,
    pub trust_policy: AutoTrustPolicy,
    pub our_fingerprint: String,
    pub client_tls: Arc<ClientConfig>,
    pub server_tls: Arc<ServerConfig>,
}

trait ClipboardIo: Read + Write {}
impl<T: Read + Write> ClipboardIo for T {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClipboardMessage {
    Hello {
        id: String,
        fingerprint: String,
        version: u32,
    },
    Text {
        id: String,
        sequence: u64,
        text: String,
    },
    Files {
        id: String,
        message: FileTransferMessage,
    },
}

#[derive(Default)]
struct FrameDecoder {
    bytes: Vec<u8>,
}

struct ClipboardState {
    clipboard: ClipboardContext,
    last_observed: Option<ClipboardSnapshot>,
    sequence: u64,
    transfers: FileTransfers,
    received_directories: VecDeque<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClipboardSnapshot {
    Text(String),
    Files(Vec<PathBuf>),
}

impl ClipboardState {
    fn open(peer_id: &str) -> Result<Self> {
        let clipboard =
            ClipboardContext::new().map_err(|error| anyhow!("open system clipboard: {error}"))?;
        let last_observed = observe_clipboard(&clipboard);
        Ok(Self {
            clipboard,
            last_observed,
            sequence: 0,
            transfers: FileTransfers::new(peer_id),
            received_directories: VecDeque::new(),
        })
    }

    fn retain_received_directory(&mut self, directory: PathBuf) {
        self.received_directories.push_back(directory);
        while self.received_directories.len() > RETAINED_FILE_TRANSFERS {
            if let Some(old) = self.received_directories.pop_front() {
                let _ = std::fs::remove_dir_all(old);
            }
        }
    }

    fn on_session_lost(&mut self) {
        let was_sending_files = self.transfers.cancel_outbound("session lost").is_some();
        self.transfers.cancel_inbound();
        if was_sending_files {
            // Re-observe and resend after reconnect. A partially transferred
            // file set must start again with a fresh offer.
            self.last_observed = None;
        }
    }
}

impl FrameDecoder {
    fn push(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn next(&mut self) -> Result<Option<ClipboardMessage>> {
        let Some(end) = self.bytes.iter().position(|byte| *byte == b'\n') else {
            if self.bytes.len() > MAX_FRAME_BYTES {
                bail!("clipboard frame exceeds {MAX_FRAME_BYTES} encoded bytes");
            }
            return Ok(None);
        };
        if end > MAX_FRAME_BYTES {
            bail!("clipboard frame exceeds {MAX_FRAME_BYTES} encoded bytes");
        }
        let line = self.bytes.drain(..=end).collect::<Vec<_>>();
        if line.len() == 1 {
            return self.next();
        }
        serde_json::from_slice(&line[..line.len() - 1])
            .context("decode clipboard message")
            .map(Some)
    }
}

pub fn start(config: ClipboardConfig, shutdown: Arc<AtomicBool>) -> Result<Option<JoinHandle<()>>> {
    if !config.enabled {
        tracing::info!("clipboard sharing disabled");
        return Ok(None);
    }
    if config.port == config.keyboard_port {
        // Treat a bad clipboard setting as a clipboard-only failure. In
        // particular, never let this listener claim the keyboard port first.
        tracing::warn!(
            port = config.port,
            "clipboard port equals keyboard port; clipboard sharing disabled"
        );
        return Ok(None);
    }
    let handle = std::thread::Builder::new()
        .name("clipboard-tls".into())
        .spawn(move || {
            if let Err(error) = run(config, &shutdown) {
                // Clipboard is an optional, isolated service. Its failure must
                // never terminate keyboard forwarding.
                tracing::warn!(error = %error, "clipboard service stopped");
            }
        })?;
    Ok(Some(handle))
}

fn run(config: ClipboardConfig, shutdown: &Arc<AtomicBool>) -> Result<()> {
    let trust = TrustStore::load(config.trust_store.clone())?;
    // Keep one clipboard object alive across network reconnects. This matters
    // on X11/Wayland, where clipboard ownership can be tied to its lifetime.
    let mut clipboard = ClipboardState::open(&config.remote_id)?;
    if config.local_id < config.remote_id {
        run_dialer(&config, &trust, &mut clipboard, shutdown)
    } else {
        run_listener(&config, &trust, &mut clipboard, shutdown)
    }
}

fn run_dialer(
    config: &ClipboardConfig,
    trust: &TrustStore,
    clipboard: &mut ClipboardState,
    shutdown: &Arc<AtomicBool>,
) -> Result<()> {
    while !shutdown.load(Ordering::Relaxed) {
        let addresses = resolve_peer_addresses(config);
        if addresses.is_empty() {
            tracing::warn!("no clipboard peer address discovered");
        }
        for address in addresses {
            if shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }
            let result = (|| -> Result<()> {
                let socket = address
                    .parse()
                    .with_context(|| format!("parse clipboard peer address {address}"))?;
                let tcp = TcpStream::connect_timeout(&socket, Duration::from_secs(5))?;
                prepare_tcp(&tcp)?;
                let (stream, peer_fingerprint) =
                    client_handshake(tcp, config.client_tls.clone(), &config.remote_id)?;
                run_session(
                    config,
                    Box::new(stream),
                    Some(peer_fingerprint),
                    trust,
                    clipboard,
                    shutdown,
                )
            })();
            clipboard.on_session_lost();
            if let Err(error) = result {
                tracing::warn!(%address, error = %error, "clipboard TLS session ended");
            }
        }
        sleep_or_stop(Duration::from_secs(config.reconnect_secs.max(1)), shutdown);
    }
    Ok(())
}

fn run_listener(
    config: &ClipboardConfig,
    trust: &TrustStore,
    clipboard: &mut ClipboardState,
    shutdown: &Arc<AtomicBool>,
) -> Result<()> {
    let address = format!("0.0.0.0:{}", config.port);
    let listener =
        TcpListener::bind(&address).with_context(|| format!("bind clipboard TLS {address}"))?;
    listener.set_nonblocking(true)?;
    tracing::info!(%address, "clipboard TLS listener ready");
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((tcp, peer)) => {
                prepare_tcp(&tcp)?;
                let result = (|| -> Result<()> {
                    let (stream, peer_fingerprint) =
                        server_handshake(tcp, config.server_tls.clone())?;
                    run_session(
                        config,
                        Box::new(stream),
                        peer_fingerprint,
                        trust,
                        clipboard,
                        shutdown,
                    )
                })();
                clipboard.on_session_lost();
                if let Err(error) = result {
                    tracing::warn!(%peer, error = %error, "clipboard TLS session ended");
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => tracing::warn!(error = %error, "clipboard accept failed"),
        }
    }
    Ok(())
}

fn run_session(
    config: &ClipboardConfig,
    mut stream: Box<dyn ClipboardIo>,
    tls_peer_fingerprint: Option<String>,
    trust: &TrustStore,
    clipboard: &mut ClipboardState,
    shutdown: &Arc<AtomicBool>,
) -> Result<()> {
    send(
        &mut stream,
        &ClipboardMessage::Hello {
            id: config.local_id.clone(),
            fingerprint: config.our_fingerprint.clone(),
            version: CLIPBOARD_PROTOCOL_VERSION,
        },
    )?;

    let mut verified = false;
    let mut decoder = FrameDecoder::default();
    let mut buffer = [0_u8; 8192];
    let mut last_poll = Instant::now()
        .checked_sub(POLL_INTERVAL)
        .unwrap_or_else(Instant::now);

    tracing::info!("clipboard TLS session connected");
    while !shutdown.load(Ordering::Relaxed) {
        match stream.read(&mut buffer) {
            Ok(0) => bail!("clipboard peer closed the connection"),
            Ok(read) => {
                decoder.push(&buffer[..read]);
                while let Some(message) = decoder.next()? {
                    if !verified {
                        verify_hello(config, trust, tls_peer_fingerprint.as_deref(), &message)?;
                        verified = true;
                        continue;
                    }
                    handle_incoming(&mut stream, config, clipboard, message)?;
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => return Err(error).context("read clipboard TLS stream"),
        }

        if verified {
            if last_poll.elapsed() >= POLL_INTERVAL {
                last_poll = Instant::now();
                if let Some(current) = observe_clipboard(&clipboard.clipboard) {
                    if clipboard.last_observed.as_ref() != Some(&current) {
                        if let Some(cancel) =
                            clipboard.transfers.cancel_outbound("clipboard changed")
                        {
                            send_file_message(&mut stream, config, cancel)?;
                        }
                        send_clipboard_change(&mut stream, config, clipboard, current)?;
                    }
                }
            }

            match clipboard.transfers.next_outbound() {
                Ok(Some(message)) => {
                    let completed = matches!(message, FileTransferMessage::Complete { .. });
                    send_file_message(&mut stream, config, message)?;
                    if completed {
                        tracing::info!("clipboard file transfer sent; waiting for peer validation");
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(error = %error, "clipboard file transfer aborted");
                    if let Some(cancel) = clipboard
                        .transfers
                        .cancel_outbound("source file changed or became unavailable")
                    {
                        send_file_message(&mut stream, config, cancel)?;
                    }
                }
            }
        }
        if !clipboard.transfers.has_outbound() {
            std::thread::sleep(IDLE_SLEEP);
        }
    }
    Ok(())
}

fn handle_incoming(
    stream: &mut Box<dyn ClipboardIo>,
    config: &ClipboardConfig,
    clipboard: &mut ClipboardState,
    message: ClipboardMessage,
) -> Result<()> {
    match message {
        ClipboardMessage::Text { id, text, .. } if id == config.remote_id => {
            if text.len() > MAX_CLIPBOARD_BYTES {
                bail!("received clipboard text exceeds {MAX_CLIPBOARD_BYTES} bytes");
            }
            clipboard.transfers.cancel_inbound();
            let snapshot = ClipboardSnapshot::Text(text.clone());
            if clipboard.last_observed.as_ref() != Some(&snapshot) {
                clipboard
                    .clipboard
                    .set_text(text)
                    .map_err(|error| anyhow!("write system clipboard: {error}"))?;
                clipboard.last_observed = Some(snapshot);
                tracing::info!("applied clipboard text received from peer");
            }
            Ok(())
        }
        ClipboardMessage::Files { id, message } if id == config.remote_id => {
            let is_offer = matches!(&message, FileTransferMessage::Offer { .. });
            let is_accepted = matches!(&message, FileTransferMessage::Accepted { .. });
            match clipboard.transfers.receive(message) {
                Ok(Some(received)) => {
                    let transfer_id = received.transfer_id;
                    let directory = received.directory;
                    let paths = received.paths;
                    let clipboard_paths = paths
                        .iter()
                        .map(|path| clipboard_file_value(path))
                        .collect::<Vec<_>>();
                    if let Err(error) = clipboard.clipboard.set_files(clipboard_paths) {
                        let _ = std::fs::remove_dir_all(&directory);
                        return Err(anyhow!("write received files to system clipboard: {error}"));
                    }
                    clipboard.last_observed = Some(ClipboardSnapshot::Files(paths.clone()));
                    clipboard.retain_received_directory(directory);
                    send_file_message(
                        stream,
                        config,
                        FileTransferMessage::Accepted { transfer_id },
                    )?;
                    tracing::info!(
                        files = paths.len(),
                        "received clipboard files are ready to paste"
                    );
                }
                Ok(None) => {
                    if is_offer {
                        tracing::info!("receiving clipboard files from peer");
                    } else if is_accepted {
                        tracing::info!("peer validated clipboard file transfer");
                    }
                }
                Err(error) => {
                    clipboard.transfers.cancel_inbound();
                    return Err(error).context("receive clipboard files");
                }
            }
            Ok(())
        }
        ClipboardMessage::Hello { .. } => bail!("unexpected second clipboard Hello"),
        ClipboardMessage::Text { .. } | ClipboardMessage::Files { .. } => {
            bail!("clipboard message came from an unexpected peer")
        }
    }
}

fn send_clipboard_change(
    stream: &mut Box<dyn ClipboardIo>,
    config: &ClipboardConfig,
    clipboard: &mut ClipboardState,
    current: ClipboardSnapshot,
) -> Result<()> {
    match &current {
        ClipboardSnapshot::Text(text) => {
            if text.len() <= MAX_CLIPBOARD_BYTES {
                clipboard.sequence = clipboard.sequence.wrapping_add(1);
                send(
                    stream,
                    &ClipboardMessage::Text {
                        id: config.local_id.clone(),
                        sequence: clipboard.sequence,
                        text: text.clone(),
                    },
                )?;
                tracing::info!(bytes = text.len(), "sent local clipboard text to peer");
            } else {
                tracing::warn!(
                    bytes = text.len(),
                    limit = MAX_CLIPBOARD_BYTES,
                    "clipboard text is too large to share"
                );
            }
        }
        ClipboardSnapshot::Files(paths) => {
            clipboard.sequence = clipboard.sequence.wrapping_add(1);
            let transfer_id = new_transfer_id(clipboard.sequence);
            match clipboard
                .transfers
                .begin_outbound(transfer_id, paths.clone())
            {
                Ok(offer) => {
                    send_file_message(stream, config, offer)?;
                    tracing::info!(
                        files = paths.len(),
                        transfer_id,
                        "sending clipboard files to peer"
                    );
                }
                Err(error) => {
                    tracing::warn!(error = %error, "clipboard files cannot be shared");
                }
            }
        }
    }
    clipboard.last_observed = Some(current);
    Ok(())
}

fn send_file_message(
    stream: &mut Box<dyn ClipboardIo>,
    config: &ClipboardConfig,
    message: FileTransferMessage,
) -> Result<()> {
    send(
        stream,
        &ClipboardMessage::Files {
            id: config.local_id.clone(),
            message,
        },
    )
}

fn observe_clipboard(clipboard: &ClipboardContext) -> Option<ClipboardSnapshot> {
    if let Ok(files) = clipboard.get_files() {
        let paths = files
            .iter()
            .filter_map(|file| clipboard_file_path(file))
            .collect::<Vec<_>>();
        if !paths.is_empty() {
            return Some(ClipboardSnapshot::Files(paths));
        }
    }
    clipboard.get_text().ok().map(ClipboardSnapshot::Text)
}

fn clipboard_file_path(value: &str) -> Option<PathBuf> {
    if value.starts_with("file://") {
        return url::Url::parse(value).ok()?.to_file_path().ok();
    }
    Some(PathBuf::from(value))
}

fn clipboard_file_value(path: &Path) -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(url) = url::Url::from_file_path(path) {
            return url.to_string();
        }
    }
    path.to_string_lossy().into_owned()
}

fn new_transfer_id(sequence: u64) -> u64 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    time ^ sequence.rotate_left(17) ^ u64::from(std::process::id())
}

fn verify_hello(
    config: &ClipboardConfig,
    trust: &TrustStore,
    tls_peer_fingerprint: Option<&str>,
    message: &ClipboardMessage,
) -> Result<()> {
    let ClipboardMessage::Hello {
        id,
        fingerprint,
        version,
    } = message
    else {
        bail!("first clipboard message must be Hello");
    };
    if id != &config.remote_id {
        bail!("clipboard peer id {id} != configured {}", config.remote_id);
    }
    if *version != CLIPBOARD_PROTOCOL_VERSION {
        bail!("clipboard protocol version {version} != local {CLIPBOARD_PROTOCOL_VERSION}");
    }
    if tls_peer_fingerprint != Some(fingerprint.as_str()) {
        bail!("clipboard Hello fingerprint does not match TLS certificate");
    }
    match trust.evaluate(id, fingerprint) {
        TrustDecision::KnownAndMatches => Ok(()),
        TrustDecision::Unknown
            if matches!(config.trust_policy, AutoTrustPolicy::TrustOnFirstUse) =>
        {
            trust.learn(id, fingerprint)
        }
        TrustDecision::Unknown => Err(anyhow!("unknown clipboard peer fingerprint {fingerprint}")),
        TrustDecision::Mismatch { expected, actual } => Err(anyhow!(
            "clipboard peer fingerprint mismatch: expected {expected}, got {actual}"
        )),
    }
}

fn send(stream: &mut Box<dyn ClipboardIo>, message: &ClipboardMessage) -> Result<()> {
    let mut bytes = serde_json::to_vec(message)?;
    if bytes.len() > MAX_FRAME_BYTES {
        bail!("clipboard frame exceeds {MAX_FRAME_BYTES} encoded bytes");
    }
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn resolve_peer_addresses(config: &ClipboardConfig) -> Vec<String> {
    if let Some(base_url) = &config.vps_base_url {
        if let Ok(entry) = RegistryClient::new(base_url).lookup(&config.remote_id) {
            if !entry.ips.is_empty() {
                // Discovery records the keyboard port. Clipboard uses the
                // locally configured dedicated port on the same addresses.
                return entry
                    .ips
                    .into_iter()
                    .map(|ip| format!("{ip}:{}", config.port))
                    .collect();
            }
        }
    }
    config
        .fallback_remote_ips
        .iter()
        .map(|ip| format!("{ip}:{}", config.port))
        .collect()
}

fn prepare_tcp(tcp: &TcpStream) -> Result<()> {
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(IO_TIMEOUT))?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(())
}

fn sleep_or_stop(total: Duration, shutdown: &AtomicBool) {
    let mut remaining = total;
    while remaining > Duration::ZERO && !shutdown.load(Ordering::Relaxed) {
        let duration = remaining.min(Duration::from_millis(200));
        std::thread::sleep(duration);
        remaining = remaining.saturating_sub(duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_handles_fragmented_clipboard_text() {
        let message = ClipboardMessage::Text {
            id: "alpha".into(),
            sequence: 4,
            text: "line one\n第二行".into(),
        };
        let mut wire = serde_json::to_vec(&message).unwrap();
        wire.push(b'\n');
        let mut decoder = FrameDecoder::default();
        for chunk in wire.chunks(3) {
            decoder.push(chunk);
        }
        assert_eq!(decoder.next().unwrap(), Some(message));
    }

    #[test]
    fn decoder_rejects_oversized_unterminated_frames() {
        let mut decoder = FrameDecoder::default();
        decoder.push(&vec![b'x'; MAX_FRAME_BYTES + 2]);
        assert!(decoder.next().is_err());
    }

    #[test]
    fn clipboard_messages_escape_embedded_newlines() {
        let message = ClipboardMessage::Text {
            id: "alpha".into(),
            sequence: 1,
            text: "a\nb".into(),
        };
        let encoded = serde_json::to_vec(&message).unwrap();
        assert!(!encoded.contains(&b'\n'));
    }

    #[test]
    fn file_offer_roundtrips_through_clipboard_envelope() {
        let message = ClipboardMessage::Files {
            id: "alpha".into(),
            message: FileTransferMessage::Offer {
                transfer_id: 7,
                files: vec![files::FileMeta {
                    name: "report.txt".into(),
                    size: 42,
                }],
            },
        };
        let encoded = serde_json::to_vec(&message).unwrap();
        assert_eq!(
            serde_json::from_slice::<ClipboardMessage>(&encoded).unwrap(),
            message
        );
    }
}
