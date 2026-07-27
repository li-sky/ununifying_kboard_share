//! Minimal blocking TLS session helpers.
//!
//! `client_handshake` and `server_handshake` perform a full rustls handshake
//! on top of a connected `TcpStream` and return a byte-stream plus the peer's
//! SHA-256 fingerprint. The binaries layer NDJSON on top using
//! `kbshare_core::codec`.

use anyhow::{anyhow, Context, Result};
use kbshare_core::codec::{encode_line, LineDecoder};
use kbshare_core::protocol::Message;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cert::fingerprint_hex;

pub type ClientStream = StreamOwned<ClientConnection, TcpStream>;
pub type ServerStream = StreamOwned<ServerConnection, TcpStream>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn client_handshake(
    tcp: TcpStream,
    config: Arc<ClientConfig>,
    sni: &str,
) -> Result<(ClientStream, String)> {
    let name =
        ServerName::try_from(sni.to_string()).map_err(|e| anyhow!("invalid SNI {sni}: {e}"))?;
    let mut conn = ClientConnection::new(config, name).context("new client conn")?;
    // Drive handshake to completion before creating the stream so that we
    // can inspect the peer certificates.
    let fp = drive_client_handshake(&mut conn, &tcp)?;
    Ok((StreamOwned::new(conn, tcp), fp))
}

pub fn server_handshake(
    tcp: TcpStream,
    config: Arc<ServerConfig>,
) -> Result<(ServerStream, Option<String>)> {
    let mut conn = ServerConnection::new(config).context("new server conn")?;
    let fp = drive_server_handshake(&mut conn, &tcp)?;
    Ok((StreamOwned::new(conn, tcp), fp))
}

fn drive_client_handshake(conn: &mut ClientConnection, tcp: &TcpStream) -> Result<String> {
    let mut tcp = tcp;
    let started_at = Instant::now();
    while conn.is_handshaking() {
        if conn.wants_write() {
            conn.write_tls(&mut tcp).context("write_tls")?;
        }
        if conn.wants_read() {
            let n = read_tls_with_retry(|| conn.read_tls(&mut tcp), &started_at)?;
            if n == 0 {
                return Err(anyhow!("peer closed during handshake"));
            }
            conn.process_new_packets().context("process packets")?;
        }
    }
    // Flush any trailing handshake bytes.
    while conn.wants_write() {
        conn.write_tls(&mut tcp).ok();
    }
    let peer_certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow!("peer presented no certificate"))?;
    let der = peer_certs
        .first()
        .ok_or_else(|| anyhow!("empty peer cert chain"))?;
    Ok(fingerprint_hex(der.as_ref()))
}

fn drive_server_handshake(conn: &mut ServerConnection, tcp: &TcpStream) -> Result<Option<String>> {
    let mut tcp = tcp;
    let started_at = Instant::now();
    while conn.is_handshaking() {
        if conn.wants_read() {
            let n = read_tls_with_retry(|| conn.read_tls(&mut tcp), &started_at)?;
            if n == 0 {
                return Err(anyhow!("peer closed during handshake"));
            }
            conn.process_new_packets().context("process packets")?;
        }
        if conn.wants_write() {
            conn.write_tls(&mut tcp).context("write_tls")?;
        }
    }
    while conn.wants_write() {
        conn.write_tls(&mut tcp).ok();
    }
    let peer_certs = conn.peer_certificates();
    let fp = peer_certs
        .and_then(|c| c.first())
        .map(|der| fingerprint_hex(der.as_ref()));
    Ok(fp)
}

fn read_tls_with_retry<F>(mut read_once: F, started_at: &Instant) -> Result<usize>
where
    F: FnMut() -> io::Result<usize>,
{
    loop {
        match read_once() {
            Ok(n) => return Ok(n),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                if started_at.elapsed() >= HANDSHAKE_TIMEOUT {
                    return Err(anyhow!(
                        "handshake timed out after {} ms waiting for TLS data",
                        HANDSHAKE_TIMEOUT.as_millis()
                    ));
                }
            }
            Err(err) => return Err(err).context("read_tls"),
        }
    }
}

/// Helper: read one complete NDJSON line from a stream into a Message.
pub fn recv_message<S: Read>(stream: &mut S, decoder: &mut LineDecoder) -> Result<Option<Message>> {
    // Fast path: already buffered.
    if let Some(msg) = decoder.next_message()? {
        return Ok(Some(msg));
    }
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Ok(None), // EOF
            Ok(n) => {
                decoder.extend(&buf[..n]);
                if let Some(msg) = decoder.next_message()? {
                    return Ok(Some(msg));
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Helper: encode and write one message, flushing the stream.
pub fn send_message<S: Write>(stream: &mut S, msg: &Message) -> Result<()> {
    let bytes = encode_line(msg)?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

/// Reason a session terminated. Reported back to the binary for logging.
#[derive(Debug)]
pub enum SessionEnd {
    Eof,
    Error(anyhow::Error),
}

/// Convenience: drive a simple read loop, calling `on_message` for each
/// decoded message until EOF or error.
pub fn run_client_session<S, F>(mut stream: S, mut on_message: F) -> SessionEnd
where
    S: Read,
    F: FnMut(Message),
{
    let mut decoder = LineDecoder::new();
    loop {
        match recv_message(&mut stream, &mut decoder) {
            Ok(Some(msg)) => on_message(msg),
            Ok(None) => return SessionEnd::Eof,
            Err(e) => return SessionEnd::Error(e),
        }
    }
}

pub fn run_server_session<S, F>(stream: S, on_message: F) -> SessionEnd
where
    S: Read,
    F: FnMut(Message),
{
    run_client_session(stream, on_message)
}
