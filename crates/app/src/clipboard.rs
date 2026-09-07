//! Clipboard synchronization over a dedicated TLS connection.
//!
//! This channel deliberately does not share a socket, lock, or thread with
//! keyboard forwarding. Clipboard access can block in a compositor and large
//! text payloads can take time to encrypt; neither is allowed onto the
//! latency-sensitive keyboard path.

#[path = "clipboard_files.rs"]
mod files;
#[path = "clipboard_transport.rs"]
mod transport;
use sha2::{Digest, Sha256};
use transport::SessionLink;

use anyhow::{anyhow, bail, Context, Result};
use clipboard_rs::{
    common::RustImage, Clipboard, ClipboardContent, ClipboardContext, ContentFormat, RustImageData,
};
use files::{FileTransferMessage, FileTransfers, TransferPurpose};
use kbshare_net::registry::RegistryClient;
use kbshare_net::session::{client_handshake, server_handshake};
use kbshare_net::trust::{AutoTrustPolicy, TrustDecision, TrustStore};
use rustls::{ClientConfig, ServerConfig};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CLIPBOARD_PROTOCOL_VERSION: u32 = 4;
const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;
// JSON may encode one control byte as a six-byte `\u00xx` escape.
const MAX_FRAME_BYTES: usize = MAX_CLIPBOARD_BYTES * 6 + 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const IMAGE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const IO_TIMEOUT: Duration = Duration::from_millis(1);
const RETRY_INTERVAL: Duration = Duration::from_secs(2);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_SLEEP: Duration = Duration::from_millis(20);
const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(10);
const RETAINED_FILE_TRANSFERS: usize = 3;

#[derive(Clone)]
pub struct ClipboardConfig {
    pub enabled: bool,
    pub status: Arc<AtomicU8>,
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

trait ClipboardIo: Read + Write + Send {}
impl<T: Read + Write + Send> ClipboardIo for T {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClipboardMessage {
    Hello {
        id: String,
        fingerprint: String,
        version: u32,
        #[serde(default)]
        clock: u64,
    },
    Text {
        id: String,
        revision: Revision,
        content: TextContent,
    },
    Heartbeat {
        id: String,
    },
    Applied {
        id: String,
        revision: Revision,
    },
    Transfer {
        id: String,
        revision: Revision,
        message: FileTransferMessage,
    },
}

/// Lamport clock plus origin gives concurrent updates one deterministic order.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct Revision {
    counter: u64,
    origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TextContent {
    text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    html: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rtf: Option<String>,
}
impl TextContent {
    fn size(&self) -> usize {
        self.text.len()
            + self.html.as_ref().map_or(0, String::len)
            + self.rtf.as_ref().map_or(0, String::len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshot {
    path: PathBuf,
    size: Option<u64>,
    modified: Option<SystemTime>,
}
fn file_snapshot(path: PathBuf) -> FileSnapshot {
    let metadata = path.metadata().ok();
    FileSnapshot {
        size: metadata.as_ref().map(|m| m.len()),
        modified: metadata.and_then(|m| m.modified().ok()),
        path,
    }
}

#[derive(Debug, Clone)]
struct ImageSnapshot {
    png: Vec<u8>,
    digest: [u8; 32],
}
impl PartialEq for ImageSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}
impl Eq for ImageSnapshot {}
fn validate_png_size(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 24 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" || &bytes[12..16] != b"IHDR" {
        bail!("invalid clipboard PNG header");
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into()?);
    let height = u32::from_be_bytes(bytes[20..24].try_into()?);
    if width == 0 || height == 0 || u64::from(width) * u64::from(height) > 32 * 1024 * 1024 {
        bail!("clipboard image exceeds pixel limit");
    }
    Ok(())
}

fn image_digest(image: &RustImageData) -> Result<[u8; 32]> {
    let (width, height) = image.get_size();
    if u64::from(width) * u64::from(height) > 32 * 1024 * 1024 {
        bail!("clipboard image exceeds pixel limit");
    }
    let pixels = image
        .to_rgba8()
        .map_err(|e| anyhow!("read image pixels: {e}"))?;
    let mut hash = Sha256::new();
    hash.update(pixels.width().to_le_bytes());
    hash.update(pixels.height().to_le_bytes());
    hash.update(pixels.as_raw());
    Ok(hash.finalize().into())
}

#[derive(Default)]
struct FrameDecoder {
    bytes: Vec<u8>,
}

struct ClipboardState {
    clipboard: Box<dyn Clipboard>,
    last_observed: Option<ClipboardSnapshot>,
    sequence: u64,
    revision: Revision,
    pending: bool,
    last_attempt: Option<Instant>,
    inbound_revision: Option<(u64, Revision)>,
    transfers: FileTransfers,
    received_directories: VecDeque<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClipboardSnapshot {
    Text(TextContent),
    Image(ImageSnapshot),
    Files(Vec<FileSnapshot>),
}

impl ClipboardState {
    fn open(peer_id: &str) -> Result<Self> {
        let clipboard =
            ClipboardContext::new().map_err(|error| anyhow!("open system clipboard: {error}"))?;
        let last_observed = observe_clipboard(&clipboard, true, None);
        Ok(Self {
            clipboard: Box::new(clipboard),
            last_observed,
            sequence: 0,
            revision: Revision::default(),
            pending: false,
            last_attempt: None,
            inbound_revision: None,
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
        self.transfers.cancel_outbound("session lost");
        self.transfers.cancel_inbound();
        self.inbound_revision = None;
        self.last_attempt = None;
        // Keep the pending revision until the peer confirms application.
    }
}

impl FrameDecoder {
    fn push(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn next(&mut self) -> Result<Option<ClipboardMessage>> {
        let blanks = self.bytes.iter().take_while(|byte| **byte == b'\n').count();
        self.bytes.drain(..blanks);
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
        serde_json::from_slice(&line[..line.len() - 1])
            .context("decode clipboard message")
            .map(Some)
    }
}

pub fn start(config: ClipboardConfig, shutdown: Arc<AtomicBool>) -> Result<Option<JoinHandle<()>>> {
    config
        .status
        .store(kbshare_tray::CLIPBOARD_DISABLED, Ordering::Relaxed);
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
    config
        .status
        .store(kbshare_tray::CLIPBOARD_DISCONNECTED, Ordering::Relaxed);
    let handle = std::thread::Builder::new()
        .name("clipboard-tls".into())
        .spawn(move || {
            let status = config.status.clone();
            if let Err(error) = run(config, &shutdown) {
                status.store(kbshare_tray::CLIPBOARD_FAILED, Ordering::Relaxed);
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
                    Box::new(transport::TlsIo::new(
                        rustls::Connection::Client(stream.conn),
                        stream.sock,
                    )?),
                    Some(peer_fingerprint),
                    trust,
                    clipboard,
                    shutdown,
                )
            })();
            config
                .status
                .store(kbshare_tray::CLIPBOARD_DISCONNECTED, Ordering::Relaxed);
            clipboard.on_session_lost();
            if let Err(error) = result {
                tracing::warn!(%address, error = %format!("{error:#}"), "clipboard TLS session ended");
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
                        Box::new(transport::TlsIo::new(
                            rustls::Connection::Server(stream.conn),
                            stream.sock,
                        )?),
                        peer_fingerprint,
                        trust,
                        clipboard,
                        shutdown,
                    )
                })();
                config
                    .status
                    .store(kbshare_tray::CLIPBOARD_DISCONNECTED, Ordering::Relaxed);
                clipboard.on_session_lost();
                if let Err(error) = result {
                    tracing::warn!(%peer, error = %format!("{error:#}"), "clipboard TLS session ended");
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
    stream: Box<dyn ClipboardIo>,
    tls_peer_fingerprint: Option<String>,
    trust: &TrustStore,
    clipboard: &mut ClipboardState,
    shutdown: &Arc<AtomicBool>,
) -> Result<()> {
    // Only this worker touches TLS. Clipboard APIs and PNG work stay on the
    // caller thread, so they cannot delay network heartbeats.
    std::thread::scope(|scope| {
        let (mut link, endpoint) = transport::channel();
        let clock = clipboard.sequence;
        let worker = scope.spawn(move || {
            transport::run(
                config,
                stream,
                tls_peer_fingerprint,
                trust,
                shutdown,
                endpoint,
                clock,
            )
        });
        let result = drive_clipboard(config, &mut link, clipboard, shutdown);
        link.stop();
        let network = worker
            .join()
            .map_err(|_| anyhow!("clipboard network worker panicked"))?;
        network.and(result)
    })
}

fn drive_clipboard(
    config: &ClipboardConfig,
    link: &mut SessionLink,
    clipboard: &mut ClipboardState,
    shutdown: &AtomicBool,
) -> Result<()> {
    // The network worker forwards Hello only after identity verification.
    let mut verified = false;
    let mut last_poll = Instant::now() - POLL_INTERVAL;
    let mut last_image_poll = Instant::now() - IMAGE_POLL_INTERVAL;
    while !shutdown.load(Ordering::Relaxed) {
        if verified && last_poll.elapsed() >= POLL_INTERVAL {
            let include_image = last_image_poll.elapsed() >= IMAGE_POLL_INTERVAL;
            if include_image {
                last_image_poll = Instant::now();
            }
            poll_local(link, config, clipboard, include_image)?;
            last_poll = Instant::now();
        }
        for _ in 0..8 {
            let Some(message) = link.try_receive()? else {
                break;
            };
            if let ClipboardMessage::Hello { clock, .. } = message {
                if verified {
                    bail!("unexpected second clipboard Hello");
                }
                clipboard.sequence = clipboard.sequence.max(clock);
                verified = true;
                config
                    .status
                    .store(kbshare_tray::CLIPBOARD_READY, Ordering::Relaxed);
                tracing::info!("clipboard peer verified; synchronization ready");
                continue;
            }
            // Re-observe immediately before applying remote content so an
            // unpolled local copy participates in conflict resolution.
            if matches!(
                &message,
                ClipboardMessage::Text { .. }
                    | ClipboardMessage::Transfer {
                        message: FileTransferMessage::Offer { .. }
                            | FileTransferMessage::Complete { .. },
                        ..
                    }
            ) {
                poll_local(link, config, clipboard, true)?;
            }
            handle_incoming(link, config, clipboard, message)?;
        }
        if verified {
            if clipboard.transfers.has_outbound() || clipboard.transfers.inbound_id().is_some() {
                config
                    .status
                    .store(kbshare_tray::CLIPBOARD_TRANSFERRING, Ordering::Relaxed);
            }
            if clipboard
                .transfers
                .expired(Instant::now(), TRANSFER_TIMEOUT)
            {
                bail!("clipboard transfer made no progress or received no acknowledgement for 30 seconds");
            }
            if clipboard.pending
                && !clipboard.transfers.has_outbound()
                && clipboard
                    .last_attempt
                    .map_or(true, |t| t.elapsed() >= RETRY_INTERVAL)
            {
                if let Some(current) = clipboard.last_observed.clone() {
                    clipboard.last_attempt = Some(Instant::now());
                    send_clipboard_change(link, config, clipboard, current)?;
                }
            }
            // Bounded batches avoid one socket read timeout for every chunk.
            for _ in 0..8 {
                if !link.has_send_capacity() {
                    break;
                }
                match clipboard.transfers.next_outbound() {
                    Ok(Some(message)) => {
                        send_transfer_message(link, config, clipboard.revision.clone(), message)?
                    }
                    Ok(None) => break,
                    Err(error) => {
                        tracing::warn!(error = %error, "clipboard transfer failed; will retry current copy");
                        if let Some(cancel) = clipboard
                            .transfers
                            .cancel_outbound("source changed or unreadable")
                        {
                            send_transfer_message(
                                link,
                                config,
                                clipboard.revision.clone(),
                                cancel,
                            )?;
                        }
                        clipboard.last_attempt = Some(Instant::now());
                        break;
                    }
                }
            }
        }
        std::thread::sleep(if clipboard.transfers.is_sending() {
            Duration::from_millis(1)
        } else {
            IDLE_SLEEP
        });
    }
    Ok(())
}

fn poll_local(
    link: &mut SessionLink,
    config: &ClipboardConfig,
    clipboard: &mut ClipboardState,
    include_image: bool,
) -> Result<()> {
    let Some(current) = observe_clipboard(
        clipboard.clipboard.as_ref(),
        include_image,
        clipboard.last_observed.as_ref(),
    ) else {
        return Ok(());
    };
    if clipboard.last_observed.as_ref() == Some(&current) {
        return Ok(());
    }
    clipboard.sequence = clipboard
        .sequence
        .max(clipboard.revision.counter)
        .saturating_add(1);
    clipboard.revision = Revision {
        counter: clipboard.sequence,
        origin: config.local_id.clone(),
    };
    clipboard.last_observed = Some(current);
    clipboard.pending = true;
    clipboard.last_attempt = None;
    cancel_transfers(link, config, clipboard, "newer local clipboard copy")
}

fn cancel_transfers(
    link: &mut SessionLink,
    config: &ClipboardConfig,
    clipboard: &mut ClipboardState,
    reason: &str,
) -> Result<()> {
    if let Some(cancel) = clipboard.transfers.cancel_outbound(reason) {
        send_transfer_message(link, config, clipboard.revision.clone(), cancel)?;
    }
    if let Some(id) = clipboard.transfers.inbound_id() {
        clipboard.transfers.cancel_inbound();
        send_transfer_message(
            link,
            config,
            clipboard.revision.clone(),
            FileTransferMessage::Cancel {
                transfer_id: id,
                reason: reason.into(),
            },
        )?;
    }
    clipboard.inbound_revision = None;
    Ok(())
}

fn handle_incoming(
    stream: &mut SessionLink,
    config: &ClipboardConfig,
    clipboard: &mut ClipboardState,
    message: ClipboardMessage,
) -> Result<()> {
    match message {
        ClipboardMessage::Applied { id, revision } if id == config.remote_id => {
            if revision == clipboard.revision {
                clipboard.pending = false;
                config
                    .status
                    .store(kbshare_tray::CLIPBOARD_READY, Ordering::Relaxed);
            }
            Ok(())
        }
        ClipboardMessage::Heartbeat { .. } => Ok(()),
        ClipboardMessage::Text {
            id,
            revision,
            content,
        } if id == config.remote_id => {
            if content.size() > MAX_CLIPBOARD_BYTES {
                bail!("received clipboard text exceeds limit");
            }
            if revision.origin != id {
                bail!("clipboard revision origin mismatch");
            }
            clipboard.sequence = clipboard.sequence.max(revision.counter);
            if revision < clipboard.revision {
                return Ok(());
            }
            if revision > clipboard.revision {
                cancel_transfers(stream, config, clipboard, "newer remote copy")?;
                let mut formats = vec![ClipboardContent::Text(content.text.clone())];
                if let Some(html) = &content.html {
                    formats.push(ClipboardContent::Html(html.clone()));
                }
                if let Some(rtf) = &content.rtf {
                    formats.push(ClipboardContent::Rtf(rtf.clone()));
                }
                clipboard
                    .clipboard
                    .set(formats)
                    .map_err(|e| anyhow!("write system clipboard: {e}"))?;
                clipboard.last_observed =
                    observe_clipboard(clipboard.clipboard.as_ref(), false, None)
                        .or(Some(ClipboardSnapshot::Text(content)));
                clipboard.revision = revision.clone();
                clipboard.pending = false;
                config
                    .status
                    .store(kbshare_tray::CLIPBOARD_READY, Ordering::Relaxed);
            }
            send(
                stream,
                &ClipboardMessage::Applied {
                    id: config.local_id.clone(),
                    revision,
                },
            )
        }
        ClipboardMessage::Transfer {
            id,
            revision,
            message,
        } if id == config.remote_id => {
            let transfer_id = message.transfer_id();
            if matches!(&message, FileTransferMessage::Offer { .. }) {
                if revision.origin != id {
                    bail!("clipboard revision origin mismatch");
                }
                clipboard.sequence = clipboard.sequence.max(revision.counter);
                if revision < clipboard.revision {
                    clipboard.transfers.reject_inbound(transfer_id);
                    return send_transfer_message(
                        stream,
                        config,
                        clipboard.revision.clone(),
                        FileTransferMessage::Cancel {
                            transfer_id,
                            reason: "superseded clipboard revision".into(),
                        },
                    );
                }
                cancel_transfers(stream, config, clipboard, "incoming clipboard offer")?;
                clipboard.revision = revision.clone();
                clipboard.pending = false;
                clipboard.inbound_revision = Some((transfer_id, revision.clone()));
            }
            let active_acceptance = matches!(
                &message,
                FileTransferMessage::Accepted { .. } | FileTransferMessage::Cancel { .. }
            ) && clipboard.transfers.outbound_id() == Some(transfer_id);
            let is_offer = matches!(&message, FileTransferMessage::Offer { .. });
            let is_accepted = matches!(&message, FileTransferMessage::Accepted { .. });
            match clipboard.transfers.receive(message) {
                Ok(Some(received)) => {
                    let transfer_id = received.transfer_id;
                    let purpose = received.purpose;
                    let directory = received.directory;
                    let paths = received.paths;
                    if clipboard.inbound_revision.as_ref()
                        != Some(&(transfer_id, clipboard.revision.clone()))
                    {
                        let _ = std::fs::remove_dir_all(&directory);
                        return send_transfer_message(
                            stream,
                            config,
                            clipboard.revision.clone(),
                            FileTransferMessage::Cancel {
                                transfer_id,
                                reason: "clipboard changed before transfer completion".into(),
                            },
                        );
                    }
                    match purpose {
                        TransferPurpose::Files => {
                            let clipboard_paths = paths
                                .iter()
                                .map(|path| clipboard_file_value(path))
                                .collect::<Vec<_>>();
                            if let Err(error) = clipboard.clipboard.set_files(clipboard_paths) {
                                let _ = std::fs::remove_dir_all(&directory);
                                return Err(anyhow!(
                                    "write received files to system clipboard: {error}"
                                ));
                            }
                            clipboard.last_observed = Some(ClipboardSnapshot::Files(
                                paths.iter().cloned().map(file_snapshot).collect(),
                            ));
                            clipboard.retain_received_directory(directory);
                            tracing::info!(
                                files = paths.len(),
                                "received clipboard files are ready to paste"
                            );
                        }
                        TransferPurpose::Image => {
                            let result = (|| -> Result<ImageSnapshot> {
                                let path = paths
                                    .first()
                                    .context("received clipboard image has no payload")?;
                                let png = std::fs::read(path).with_context(|| {
                                    format!("read received clipboard image {}", path.display())
                                })?;
                                validate_png_size(&png)?;
                                let image = RustImageData::from_bytes(&png).map_err(|error| {
                                    anyhow!("decode received clipboard image: {error}")
                                })?;
                                let digest = image_digest(&image)?;
                                clipboard.clipboard.set_image(image).map_err(|error| {
                                    anyhow!("write received image to system clipboard: {error}")
                                })?;
                                Ok(ImageSnapshot { png, digest })
                            })();
                            let _ = std::fs::remove_dir_all(&directory);
                            let png = result?;
                            clipboard.last_observed = Some(ClipboardSnapshot::Image(png));
                            tracing::info!("applied clipboard image received from peer");
                        }
                    }
                    clipboard.inbound_revision = None;
                    config
                        .status
                        .store(kbshare_tray::CLIPBOARD_READY, Ordering::Relaxed);
                    send_transfer_message(
                        stream,
                        config,
                        revision.clone(),
                        FileTransferMessage::Accepted { transfer_id },
                    )?;
                }
                Ok(None) => {
                    if active_acceptance {
                        clipboard.pending = false;
                        config.status.store(
                            if is_accepted {
                                kbshare_tray::CLIPBOARD_READY
                            } else {
                                kbshare_tray::CLIPBOARD_FAILED
                            },
                            Ordering::Relaxed,
                        );
                    }
                    if is_offer {
                        tracing::info!("receiving clipboard payload from peer");
                    } else if is_accepted {
                        tracing::info!("peer validated clipboard payload");
                    }
                }
                Err(error) => {
                    clipboard.transfers.cancel_inbound();
                    clipboard.transfers.reject_inbound(transfer_id);
                    clipboard.inbound_revision = None;
                    config
                        .status
                        .store(kbshare_tray::CLIPBOARD_FAILED, Ordering::Relaxed);
                    tracing::warn!(error = %error, transfer_id, "clipboard payload rejected");
                    send_transfer_message(
                        stream,
                        config,
                        revision,
                        FileTransferMessage::Cancel {
                            transfer_id,
                            reason: "payload validation or storage failed".into(),
                        },
                    )?;
                }
            }
            Ok(())
        }
        ClipboardMessage::Hello { .. } => bail!("unexpected second clipboard Hello"),
        ClipboardMessage::Text { .. }
        | ClipboardMessage::Applied { .. }
        | ClipboardMessage::Transfer { .. } => {
            bail!("clipboard message came from an unexpected peer")
        }
    }
}

fn send_clipboard_change(
    stream: &mut SessionLink,
    config: &ClipboardConfig,
    clipboard: &mut ClipboardState,
    current: ClipboardSnapshot,
) -> Result<()> {
    match &current {
        ClipboardSnapshot::Text(text) => {
            if text.size() <= MAX_CLIPBOARD_BYTES {
                send(
                    stream,
                    &ClipboardMessage::Text {
                        id: config.local_id.clone(),
                        revision: clipboard.revision.clone(),
                        content: text.clone(),
                    },
                )?;
                tracing::info!(bytes = text.size(), "sent local clipboard text to peer");
            } else {
                config
                    .status
                    .store(kbshare_tray::CLIPBOARD_FAILED, Ordering::Relaxed);
                tracing::warn!(
                    bytes = text.size(),
                    limit = MAX_CLIPBOARD_BYTES,
                    "clipboard text is too large to share"
                );
            }
        }
        ClipboardSnapshot::Image(image) => {
            let transfer_id = new_transfer_id(clipboard.sequence);
            match clipboard
                .transfers
                .begin_image_outbound(transfer_id, &image.png)
            {
                Ok(offer) => {
                    send_transfer_message(stream, config, clipboard.revision.clone(), offer)?;
                    tracing::info!(
                        bytes = image.png.len(),
                        transfer_id,
                        "sending clipboard image to peer"
                    );
                }
                Err(error) => {
                    config
                        .status
                        .store(kbshare_tray::CLIPBOARD_FAILED, Ordering::Relaxed);
                    tracing::warn!(error = %error, "clipboard image cannot be shared");
                }
            }
        }
        ClipboardSnapshot::Files(paths) => {
            let transfer_id = new_transfer_id(clipboard.sequence);
            match clipboard
                .transfers
                .begin_outbound(transfer_id, paths.iter().map(|f| f.path.clone()).collect())
            {
                Ok(offer) => {
                    send_transfer_message(stream, config, clipboard.revision.clone(), offer)?;
                    tracing::info!(
                        files = paths.len(),
                        transfer_id,
                        "sending clipboard files to peer"
                    );
                }
                Err(error) => {
                    config
                        .status
                        .store(kbshare_tray::CLIPBOARD_FAILED, Ordering::Relaxed);
                    tracing::warn!(error = %error, "clipboard files cannot be shared");
                }
            }
        }
    }
    Ok(())
}

fn send_transfer_message(
    stream: &mut SessionLink,
    config: &ClipboardConfig,
    revision: Revision,
    message: FileTransferMessage,
) -> Result<()> {
    send(
        stream,
        &ClipboardMessage::Transfer {
            id: config.local_id.clone(),
            revision,
            message,
        },
    )
}

fn observe_clipboard(
    clipboard: &dyn Clipboard,
    include_image: bool,
    previous: Option<&ClipboardSnapshot>,
) -> Option<ClipboardSnapshot> {
    if let Ok(files) = clipboard.get_files() {
        let paths = files
            .iter()
            .filter_map(|file| clipboard_file_path(file))
            .collect::<Vec<_>>();
        if !paths.is_empty() {
            return Some(ClipboardSnapshot::Files(
                paths.into_iter().map(file_snapshot).collect(),
            ));
        }
    }
    let has_image = clipboard.has(ContentFormat::Image);
    if include_image {
        match clipboard.get_image() {
            Ok(image) => {
                let digest = image_digest(&image).ok()?;
                if let Some(ClipboardSnapshot::Image(old)) = previous {
                    if old.digest == digest {
                        return Some(ClipboardSnapshot::Image(old.clone()));
                    }
                }
                let png = image.to_png().ok()?;
                return Some(ClipboardSnapshot::Image(ImageSnapshot {
                    png: png.get_bytes().to_vec(),
                    digest,
                }));
            }
            Err(_) if has_image => return None,
            Err(_) => {}
        }
    } else if has_image {
        // Do not send a secondary text representation while an image is
        // waiting for the lower-frequency image poll.
        return None;
    }
    let text = clipboard.get_text().ok();
    let html = clipboard.get_html().ok();
    let rtf = clipboard.get_rich_text().ok();
    if text.is_none() && html.is_none() && rtf.is_none() {
        return None;
    }
    Some(ClipboardSnapshot::Text(TextContent {
        text: text.unwrap_or_default(),
        html,
        rtf,
    }))
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
        ..
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

fn send(stream: &mut SessionLink, message: &ClipboardMessage) -> Result<()> {
    stream.send(message.clone())
}

fn is_transient_socket_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    ) || error.raw_os_error() == Some(10035)
}

fn resolve_peer_addresses(config: &ClipboardConfig) -> Vec<String> {
    let mut addresses = Vec::new();
    if let Some(base_url) = &config.vps_base_url {
        if let Ok(entry) = RegistryClient::new(base_url).lookup(&config.remote_id) {
            if !entry.ips.is_empty() {
                // Discovery records the keyboard port. Clipboard uses the
                // locally configured dedicated port on the same addresses.
                addresses.extend(
                    entry
                        .ips
                        .into_iter()
                        .map(|ip| format!("{ip}:{}", config.port)),
                );
            }
        }
    }
    for ip in &config.fallback_remote_ips {
        let address = format!("{ip}:{}", config.port);
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses
}

fn prepare_tcp(tcp: &TcpStream) -> Result<()> {
    // The listener itself is nonblocking so the service can observe shutdown.
    // Normalize accepted sockets before handing them to rustls; Winsock reports
    // transient I/O on a nonblocking stream as WSAEWOULDBLOCK (10035).
    tcp.set_nonblocking(false)?;
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

    #[derive(Default)]
    struct FlakyClipboardIo {
        bytes: Vec<u8>,
        write_attempts: usize,
        flush_attempts: usize,
    }

    impl Read for FlakyClipboardIo {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(ErrorKind::WouldBlock))
        }
    }

    impl Write for FlakyClipboardIo {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.write_attempts += 1;
            match self.write_attempts {
                1 => Err(io::Error::from_raw_os_error(10035)),
                3 => Err(io::Error::from(ErrorKind::WouldBlock)),
                _ => {
                    let written = bytes.len().min(3);
                    self.bytes.extend_from_slice(&bytes[..written]);
                    Ok(written)
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_attempts += 1;
            if self.flush_attempts == 1 {
                Err(io::Error::from_raw_os_error(10035))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn decoder_handles_fragmented_clipboard_text() {
        let message = ClipboardMessage::Text {
            id: "alpha".into(),
            revision: Revision {
                counter: 4,
                origin: "alpha".into(),
            },
            content: TextContent {
                text: "line one\n第二行".into(),
                html: None,
                rtf: None,
            },
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
            revision: Revision {
                counter: 1,
                origin: "alpha".into(),
            },
            content: TextContent {
                text: "a\nb".into(),
                html: None,
                rtf: None,
            },
        };
        let encoded = serde_json::to_vec(&message).unwrap();
        assert!(!encoded.contains(&b'\n'));
    }

    #[test]
    fn clipboard_writer_retries_windows_would_block_without_losing_bytes() {
        let mut stream = FlakyClipboardIo::default();
        let message = ClipboardMessage::Heartbeat { id: "peer".into() };
        transport::write_test_frame(&mut stream, &message).unwrap();
        let mut expected = serde_json::to_vec(&message).unwrap();
        expected.push(b'\n');
        assert_eq!(stream.bytes, expected);
        assert!(stream.write_attempts > 3);
        assert!(stream.flush_attempts >= 2);
    }

    #[test]
    fn file_offer_roundtrips_through_clipboard_envelope() {
        let message = ClipboardMessage::Transfer {
            id: "alpha".into(),
            revision: Revision {
                counter: 1,
                origin: "alpha".into(),
            },
            message: FileTransferMessage::Offer {
                transfer_id: 7,
                purpose: TransferPurpose::Files,
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

    #[test]
    fn image_offer_roundtrips_through_clipboard_envelope() {
        let message = ClipboardMessage::Transfer {
            id: "alpha".into(),
            revision: Revision {
                counter: 1,
                origin: "alpha".into(),
            },
            message: FileTransferMessage::Offer {
                transfer_id: 8,
                purpose: TransferPurpose::Image,
                files: vec![files::FileMeta {
                    name: "clipboard.png".into(),
                    size: 1024,
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

#[cfg(test)]
#[path = "clipboard_tests.rs"]
mod state_tests;
