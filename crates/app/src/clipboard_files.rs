//! Streaming file-transfer state for the clipboard TLS channel.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const EAGER_FILE_BYTES: u64 = 10 * 1024 * 1024;

pub const MAX_FILES: usize = 32;
pub const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_IMAGE_BYTES: usize = 64 * 1024 * 1024;
pub const FILE_CHUNK_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferPurpose {
    Files,
    Image,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileTransferMessage {
    Offer {
        transfer_id: u64,
        purpose: TransferPurpose,
        files: Vec<FileMeta>,
    },
    Request {
        transfer_id: u64,
    },
    Chunk {
        transfer_id: u64,
        file_index: u32,
        offset: u64,
        data: String,
    },
    FileEnd {
        transfer_id: u64,
        file_index: u32,
        sha256: String,
    },
    Complete {
        transfer_id: u64,
    },
    Accepted {
        transfer_id: u64,
    },
    Cancel {
        transfer_id: u64,
        reason: String,
    },
}

impl FileTransferMessage {
    pub fn transfer_id(&self) -> u64 {
        match self {
            Self::Offer { transfer_id, .. }
            | Self::Request { transfer_id }
            | Self::Chunk { transfer_id, .. }
            | Self::FileEnd { transfer_id, .. }
            | Self::Complete { transfer_id }
            | Self::Accepted { transfer_id }
            | Self::Cancel { transfer_id, .. } => *transfer_id,
        }
    }
}

fn create_private_root(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn retire(ids: &mut VecDeque<u64>, id: u64) {
    if !ids.contains(&id) {
        ids.push_back(id);
    }
    while ids.len() > 256 {
        ids.pop_front();
    }
}

pub struct FileTransfers {
    root: PathBuf,
    outbound: Option<OutboundTransfer>,
    inbound: Option<InboundTransfer>,
    deferred_inbound: Option<(u64, TransferPurpose, Vec<FileMeta>)>,
    retired_inbound: VecDeque<u64>,
    retired_outbound: VecDeque<u64>,
    last_inbound_progress: Instant,
    last_outbound_progress: Instant,
}

impl Drop for FileTransfers {
    fn drop(&mut self) {
        self.cancel_inbound();
        let _ = std::fs::remove_dir_all(&self.root);
        if let Some(parent) = self.root.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

impl FileTransfers {
    pub fn new(peer_id: &str) -> Self {
        let instance = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        Self {
            root: std::env::temp_dir()
                .join(format!(
                    "kbshare-clipboard-{}-{instance:x}",
                    std::process::id()
                ))
                .join(portable_name(peer_id)),
            outbound: None,
            inbound: None,
            deferred_inbound: None,
            retired_inbound: VecDeque::new(),
            retired_outbound: VecDeque::new(),
            last_inbound_progress: Instant::now(),
            last_outbound_progress: Instant::now(),
        }
    }

    pub fn has_outbound(&self) -> bool {
        self.outbound.is_some()
    }

    pub fn is_sending(&self) -> bool {
        self.outbound
            .as_ref()
            .is_some_and(|transfer| transfer.requested && !transfer.complete_sent)
    }

    pub fn outbound_id(&self) -> Option<u64> {
        self.outbound.as_ref().map(|t| t.id)
    }
    pub fn inbound_id(&self) -> Option<u64> {
        self.inbound
            .as_ref()
            .map(|t| t.id)
            .or_else(|| self.deferred_inbound.as_ref().map(|t| t.0))
    }

    pub fn cancel_outbound(&mut self, reason: &str) -> Option<FileTransferMessage> {
        let transfer = self.outbound.take()?;
        retire(&mut self.retired_outbound, transfer.id);
        Some(FileTransferMessage::Cancel {
            transfer_id: transfer.id,
            reason: reason.into(),
        })
    }

    pub fn cancel_inbound(&mut self) {
        if let Some((id, _, _)) = self.deferred_inbound.take() {
            retire(&mut self.retired_inbound, id);
        }
        if let Some(transfer) = self.inbound.take() {
            retire(&mut self.retired_inbound, transfer.id);
            let directory = transfer.directory.clone();
            drop(transfer);
            let _ = std::fs::remove_dir_all(directory);
        }
    }

    pub fn reject_inbound(&mut self, id: u64) {
        retire(&mut self.retired_inbound, id);
    }

    pub fn expired(&self, now: Instant, timeout: Duration) -> bool {
        (self.inbound.is_some() && now.duration_since(self.last_inbound_progress) >= timeout)
            || (self.outbound.as_ref().is_some_and(|t| t.requested)
                && now.duration_since(self.last_outbound_progress) >= timeout)
    }

    pub fn begin_outbound(
        &mut self,
        transfer_id: u64,
        paths: Vec<PathBuf>,
    ) -> Result<FileTransferMessage> {
        self.begin_outbound_paths(transfer_id, TransferPurpose::Files, paths, None)
    }

    pub fn begin_image_outbound(
        &mut self,
        transfer_id: u64,
        png: &[u8],
    ) -> Result<FileTransferMessage> {
        if png.is_empty() {
            bail!("clipboard image is empty");
        }
        if png.len() > MAX_IMAGE_BYTES {
            bail!("clipboard image exceeds the {} byte limit", MAX_IMAGE_BYTES);
        }

        create_private_root(&self.root)
            .with_context(|| format!("create clipboard root {}", self.root.display()))?;
        let directory = self.root.join(format!("outbound-{transfer_id:016x}"));
        std::fs::create_dir(&directory)
            .with_context(|| format!("create clipboard image transfer {}", directory.display()))?;
        let path = directory.join("clipboard.png");
        if let Err(error) = std::fs::write(&path, png) {
            let _ = std::fs::remove_dir_all(&directory);
            return Err(error).with_context(|| format!("write clipboard image {}", path.display()));
        }

        match self.begin_outbound_paths(
            transfer_id,
            TransferPurpose::Image,
            vec![path],
            Some(directory.clone()),
        ) {
            Ok(offer) => Ok(offer),
            Err(error) => {
                let _ = std::fs::remove_dir_all(directory);
                Err(error)
            }
        }
    }

    fn begin_outbound_paths(
        &mut self,
        transfer_id: u64,
        purpose: TransferPurpose,
        paths: Vec<PathBuf>,
        cleanup_directory: Option<PathBuf>,
    ) -> Result<FileTransferMessage> {
        let mut transfer = OutboundTransfer::new(transfer_id, paths, cleanup_directory)?;
        transfer.requested = !needs_request(purpose, &transfer.files);
        let offer = FileTransferMessage::Offer {
            transfer_id,
            purpose,
            files: transfer.files.clone(),
        };
        self.cancel_outbound("superseded");
        self.last_outbound_progress = Instant::now();
        self.outbound = Some(transfer);
        Ok(offer)
    }

    pub fn deferred_inbound(&self) -> Option<(u64, &[FileMeta])> {
        self.deferred_inbound
            .as_ref()
            .map(|(id, _, files)| (*id, files.as_slice()))
    }

    pub fn waiting_for_request(&self) -> bool {
        self.outbound.as_ref().is_some_and(|t| !t.requested) || self.deferred_inbound.is_some()
    }

    pub fn request_inbound(&mut self, id: u64) -> Result<Option<FileTransferMessage>> {
        let Some((offer_id, purpose, files)) = self.deferred_inbound.as_ref() else {
            return Ok(None);
        };
        if *offer_id != id {
            return Ok(None);
        }
        let transfer = InboundTransfer::create(&self.root, id, *purpose, files.clone())?;
        self.inbound = Some(transfer);
        self.deferred_inbound = None;
        self.last_inbound_progress = Instant::now();
        Ok(Some(FileTransferMessage::Request { transfer_id: id }))
    }

    pub fn next_outbound(&mut self) -> Result<Option<FileTransferMessage>> {
        let Some(transfer) = self.outbound.as_mut() else {
            return Ok(None);
        };
        let message = transfer.next_message()?;
        if message.is_some() {
            self.last_outbound_progress = Instant::now();
        }
        Ok(message)
    }

    pub fn receive(&mut self, message: FileTransferMessage) -> Result<Option<ReceivedFiles>> {
        match message {
            FileTransferMessage::Offer {
                transfer_id,
                purpose,
                files,
            } => {
                if self.retired_inbound.contains(&transfer_id) {
                    return Ok(None);
                }
                self.cancel_inbound();
                self.last_inbound_progress = Instant::now();
                validate_manifest(purpose, &files)?;
                if needs_request(purpose, &files) {
                    self.deferred_inbound = Some((transfer_id, purpose, files));
                    return Ok(None);
                }
                self.inbound = Some(InboundTransfer::create(
                    &self.root,
                    transfer_id,
                    purpose,
                    files,
                )?);
                Ok(None)
            }
            FileTransferMessage::Cancel { transfer_id, .. } => {
                if self.inbound_id() == Some(transfer_id) {
                    self.cancel_inbound();
                }
                if self
                    .outbound
                    .as_ref()
                    .is_some_and(|transfer| transfer.id == transfer_id)
                {
                    self.cancel_outbound("peer cancelled");
                }
                Ok(None)
            }
            FileTransferMessage::Request { transfer_id } => {
                if self.retired_outbound.contains(&transfer_id) {
                    return Ok(None);
                }
                let transfer = self
                    .outbound
                    .as_mut()
                    .context("file request without an offer")?;
                if transfer.id != transfer_id {
                    bail!("file request does not match offer");
                }
                if !transfer.requested {
                    transfer.requested = true;
                    self.last_outbound_progress = Instant::now();
                }
                Ok(None)
            }
            FileTransferMessage::Accepted { transfer_id } => {
                if self.retired_outbound.contains(&transfer_id) {
                    return Ok(None);
                }
                let transfer = self
                    .outbound
                    .as_ref()
                    .context("received file acceptance without an outbound transfer")?;
                if transfer.id != transfer_id || !transfer.complete_sent {
                    bail!("file acceptance does not match the completed outbound transfer");
                }
                retire(&mut self.retired_outbound, transfer_id);
                self.outbound = None;
                Ok(None)
            }
            message => {
                if self.retired_inbound.contains(&message.transfer_id()) {
                    return Ok(None);
                }
                let transfer = self
                    .inbound
                    .as_mut()
                    .context("received file data without an active offer")?;
                let complete = transfer.receive(message)?;
                self.last_inbound_progress = Instant::now();
                if complete {
                    let transfer = self.inbound.take().expect("inbound transfer exists");
                    retire(&mut self.retired_inbound, transfer.id);
                    Ok(Some(ReceivedFiles {
                        transfer_id: transfer.id,
                        purpose: transfer.purpose,
                        directory: transfer.directory,
                        paths: transfer.files.into_iter().map(|file| file.path).collect(),
                    }))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

pub struct ReceivedFiles {
    pub transfer_id: u64,
    pub purpose: TransferPurpose,
    pub directory: PathBuf,
    pub paths: Vec<PathBuf>,
}

struct OutboundTransfer {
    id: u64,
    files: Vec<FileMeta>,
    paths: Vec<PathBuf>,
    modified: Vec<Option<std::time::SystemTime>>,
    cleanup_directory: Option<PathBuf>,
    file_index: usize,
    open_file: Option<File>,
    offset: u64,
    hasher: Sha256,
    complete_sent: bool,
    requested: bool,
}

impl Drop for OutboundTransfer {
    fn drop(&mut self) {
        self.open_file.take();
        if let Some(directory) = self.cleanup_directory.take() {
            let _ = std::fs::remove_dir_all(directory);
        }
    }
}

impl OutboundTransfer {
    fn new(id: u64, paths: Vec<PathBuf>, cleanup_directory: Option<PathBuf>) -> Result<Self> {
        if paths.is_empty() {
            bail!("clipboard contains no transferable files");
        }
        if paths.len() > MAX_FILES {
            bail!("clipboard contains more than {MAX_FILES} files");
        }

        let mut names = HashSet::new();
        let mut files = Vec::with_capacity(paths.len());
        let mut normalized = Vec::with_capacity(paths.len());
        let mut modified = Vec::new();
        let mut total = 0_u64;
        for path in paths {
            let path = path
                .canonicalize()
                .with_context(|| format!("resolve clipboard file {}", path.display()))?;
            let metadata = path
                .metadata()
                .with_context(|| format!("inspect clipboard file {}", path.display()))?;
            if !metadata.is_file() {
                bail!(
                    "clipboard entry {} is not a regular file; directories are not yet supported",
                    path.display()
                );
            }
            total = total
                .checked_add(metadata.len())
                .context("clipboard file sizes overflowed")?;
            if total > MAX_TOTAL_BYTES {
                bail!("clipboard files exceed the {} byte limit", MAX_TOTAL_BYTES);
            }
            let original = path
                .file_name()
                .and_then(|name| name.to_str())
                .context("clipboard file name is not valid UTF-8")?;
            let name = unique_name(portable_name(original), &mut names);
            files.push(FileMeta {
                name,
                size: metadata.len(),
            });
            modified.push(metadata.modified().ok());
            normalized.push(path);
        }

        Ok(Self {
            id,
            files,
            paths: normalized,
            modified,
            cleanup_directory,
            file_index: 0,
            open_file: None,
            offset: 0,
            hasher: Sha256::new(),
            complete_sent: false,
            requested: true,
        })
    }

    fn next_message(&mut self) -> Result<Option<FileTransferMessage>> {
        if !self.requested {
            return Ok(None);
        }
        if self.file_index >= self.paths.len() {
            return if self.complete_sent {
                Ok(None)
            } else {
                self.complete_sent = true;
                Ok(Some(FileTransferMessage::Complete {
                    transfer_id: self.id,
                }))
            };
        }
        let metadata = self.paths[self.file_index].metadata()?;
        if metadata.len() != self.files[self.file_index].size
            || metadata.modified().ok() != self.modified[self.file_index]
        {
            bail!("clipboard file changed while it was being transferred");
        }
        if self.open_file.is_none() {
            self.open_file = Some(
                File::open(&self.paths[self.file_index])
                    .with_context(|| format!("open {}", self.paths[self.file_index].display()))?,
            );
            self.offset = 0;
            self.hasher = Sha256::new();
        }

        let mut bytes = vec![0_u8; FILE_CHUNK_BYTES];
        let read = self
            .open_file
            .as_mut()
            .expect("outbound file is open")
            .read(&mut bytes)?;
        if read != 0 {
            bytes.truncate(read);
            let offset = self.offset;
            self.offset = self.offset.saturating_add(read as u64);
            if self.offset > self.files[self.file_index].size {
                bail!("clipboard file grew while it was being transferred");
            }
            self.hasher.update(&bytes);
            return Ok(Some(FileTransferMessage::Chunk {
                transfer_id: self.id,
                file_index: self.file_index as u32,
                offset,
                data: BASE64.encode(bytes),
            }));
        }

        if self.offset != self.files[self.file_index].size {
            bail!("clipboard file shrank while it was being transferred");
        }
        self.open_file = None;
        let sha256 = hex::encode(self.hasher.clone().finalize());
        let file_index = self.file_index as u32;
        self.file_index += 1;
        Ok(Some(FileTransferMessage::FileEnd {
            transfer_id: self.id,
            file_index,
            sha256,
        }))
    }
}

struct InboundTransfer {
    id: u64,
    purpose: TransferPurpose,
    directory: PathBuf,
    files: Vec<InboundFile>,
    current_file: usize,
}

struct InboundFile {
    meta: FileMeta,
    path: PathBuf,
    file: File,
    received: u64,
    hasher: Sha256,
}

impl InboundTransfer {
    fn create(
        root: &Path,
        id: u64,
        purpose: TransferPurpose,
        files: Vec<FileMeta>,
    ) -> Result<Self> {
        validate_manifest(purpose, &files)?;
        create_private_root(root)
            .with_context(|| format!("create clipboard root {}", root.display()))?;
        let directory = root.join(format!("{id:016x}"));
        std::fs::create_dir(&directory)
            .with_context(|| format!("create clipboard transfer {}", directory.display()))?;

        let result = files
            .into_iter()
            .map(|meta| {
                let path = directory.join(&meta.name);
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .with_context(|| format!("create received file {}", path.display()))?;
                Ok(InboundFile {
                    meta,
                    path,
                    file,
                    received: 0,
                    hasher: Sha256::new(),
                })
            })
            .collect::<Result<Vec<_>>>();
        match result {
            Ok(files) => Ok(Self {
                id,
                purpose,
                directory,
                files,
                current_file: 0,
            }),
            Err(error) => {
                let _ = std::fs::remove_dir_all(&directory);
                Err(error)
            }
        }
    }

    fn receive(&mut self, message: FileTransferMessage) -> Result<bool> {
        match message {
            FileTransferMessage::Chunk {
                transfer_id,
                file_index,
                offset,
                data,
            } => {
                self.verify_position(transfer_id, file_index)?;
                let bytes = BASE64.decode(data).context("decode clipboard file chunk")?;
                if bytes.len() > FILE_CHUNK_BYTES {
                    bail!("clipboard file chunk exceeds {FILE_CHUNK_BYTES} bytes");
                }
                let file = &mut self.files[self.current_file];
                if offset != file.received {
                    bail!(
                        "clipboard file chunk offset {offset} != expected {}",
                        file.received
                    );
                }
                let new_size = file
                    .received
                    .checked_add(bytes.len() as u64)
                    .context("received clipboard file size overflowed")?;
                if new_size > file.meta.size {
                    bail!("received clipboard file exceeds its declared size");
                }
                file.file.write_all(&bytes)?;
                file.hasher.update(&bytes);
                file.received = new_size;
                Ok(false)
            }
            FileTransferMessage::FileEnd {
                transfer_id,
                file_index,
                sha256,
            } => {
                self.verify_position(transfer_id, file_index)?;
                let file = &mut self.files[self.current_file];
                if file.received != file.meta.size {
                    bail!(
                        "received {} bytes for {}, expected {}",
                        file.received,
                        file.meta.name,
                        file.meta.size
                    );
                }
                let actual = hex::encode(file.hasher.clone().finalize());
                if !actual.eq_ignore_ascii_case(&sha256) {
                    bail!("SHA-256 mismatch for {}", file.meta.name);
                }
                file.file.flush()?;
                self.current_file += 1;
                Ok(false)
            }
            FileTransferMessage::Complete { transfer_id } => {
                if transfer_id != self.id {
                    bail!("file transfer id does not match active transfer");
                }
                if self.current_file != self.files.len() {
                    bail!("file transfer completed before all files arrived");
                }
                Ok(true)
            }
            FileTransferMessage::Offer { .. }
            | FileTransferMessage::Request { .. }
            | FileTransferMessage::Accepted { .. }
            | FileTransferMessage::Cancel { .. } => {
                bail!("unexpected file-transfer control message")
            }
        }
    }

    fn verify_position(&self, transfer_id: u64, file_index: u32) -> Result<()> {
        if transfer_id != self.id {
            bail!("file transfer id does not match active transfer");
        }
        if file_index as usize != self.current_file || self.current_file >= self.files.len() {
            bail!("file transfer index is out of sequence");
        }
        Ok(())
    }
}

fn needs_request(purpose: TransferPurpose, files: &[FileMeta]) -> bool {
    purpose == TransferPurpose::Files
        && files.iter().map(|f| f.size).sum::<u64>() >= EAGER_FILE_BYTES
}

fn validate_manifest(purpose: TransferPurpose, files: &[FileMeta]) -> Result<()> {
    if files.is_empty() || files.len() > MAX_FILES {
        bail!("invalid clipboard file count");
    }
    if purpose == TransferPurpose::Image
        && (files.len() != 1
            || files[0].name != "clipboard.png"
            || files[0].size > MAX_IMAGE_BYTES as u64)
    {
        bail!("invalid clipboard image manifest");
    }
    let mut total = 0_u64;
    let mut names = HashSet::new();
    for file in files {
        if file.name != portable_name(&file.name)
            || file.name == "."
            || file.name == ".."
            || !names.insert(file.name.to_lowercase())
        {
            bail!("unsafe or duplicate clipboard file name");
        }
        total = total
            .checked_add(file.size)
            .context("clipboard manifest size overflowed")?;
        if total > MAX_TOTAL_BYTES {
            bail!("clipboard files exceed the {} byte limit", MAX_TOTAL_BYTES);
        }
    }
    Ok(())
}

fn portable_name(name: &str) -> String {
    let name = name
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
                )
            {
                '_'
            } else {
                character
            }
        })
        .collect::<String>();
    let trimmed = name.trim().trim_end_matches('.').trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        "file".to_string()
    } else {
        let bounded = truncate_utf8(trimmed, 200).trim_end_matches([' ', '.']);
        if is_windows_reserved_name(bounded) {
            format!("_{}", truncate_utf8(bounded, 199))
        } else {
            bounded.to_string()
        }
    }
}

fn truncate_utf8(value: &str, limit: usize) -> &str {
    let mut end = value.len().min(limit);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn is_windows_reserved_name(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn unique_name(name: String, used: &mut HashSet<String>) -> String {
    if used.insert(name.to_lowercase()) {
        return name;
    }
    let path = Path::new(&name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let extension = path.extension().and_then(|value| value.to_str());
    for suffix in 2..=MAX_FILES + 1 {
        let suffix = format!(" ({suffix})");
        let candidate = match extension {
            Some(extension) if extension.len() + suffix.len() + 1 < 200 => format!(
                "{}{}.{}",
                truncate_utf8(stem, 200 - extension.len() - suffix.len() - 1),
                suffix,
                extension
            ),
            _ => format!("{}{}", truncate_utf8(&name, 200 - suffix.len()), suffix),
        };
        if used.insert(candidate.to_lowercase()) {
            return candidate;
        }
    }
    unreachable!("MAX_FILES bounds unique-name generation")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, bytes: &[u8]) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "kbshare-file-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn eager_threshold_uses_total_bytes_and_excludes_images() {
        for (sizes, lazy) in [
            (vec![0], false),
            (vec![EAGER_FILE_BYTES - 1], false),
            (vec![EAGER_FILE_BYTES], true),
            (vec![EAGER_FILE_BYTES + 1], true),
            (vec![EAGER_FILE_BYTES / 2, EAGER_FILE_BYTES / 2], true),
        ] {
            let files = sizes
                .into_iter()
                .enumerate()
                .map(|(i, size)| FileMeta {
                    name: format!("{i}.bin"),
                    size,
                })
                .collect::<Vec<_>>();
            assert_eq!(needs_request(TransferPurpose::Files, &files), lazy);
            assert!(!needs_request(TransferPurpose::Image, &files));
        }
    }

    #[test]
    fn large_files_wait_without_io_or_deadline_then_stream_on_request() {
        let source = temp_file("large.bin", b"start");
        File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_len(EAGER_FILE_BYTES)
            .unwrap();
        let mut sender = FileTransfers::new("lazy-sender");
        let mut receiver = FileTransfers::new("lazy-receiver");
        receiver
            .receive(sender.begin_outbound(42, vec![source.clone()]).unwrap())
            .unwrap();
        assert!(sender.waiting_for_request());
        assert!(receiver.waiting_for_request());
        assert!(sender.next_outbound().unwrap().is_none());
        assert!(sender.outbound.as_ref().unwrap().open_file.is_none());
        assert!(!receiver.root.exists());
        let later = Instant::now() + Duration::from_secs(3600);
        assert!(!sender.expired(later, Duration::from_secs(30)));
        assert!(!receiver.expired(later, Duration::from_secs(30)));
        assert!(receiver.request_inbound(41).unwrap().is_none());
        let request = receiver.request_inbound(42).unwrap().unwrap();
        sender.receive(request.clone()).unwrap();
        assert!(!sender.waiting_for_request());
        assert!(!receiver.waiting_for_request());
        assert!(receiver.request_inbound(42).unwrap().is_none());
        assert!(sender.expired(later, Duration::from_secs(30)));
        assert!(receiver.expired(later, Duration::from_secs(30)));
        receiver
            .receive(sender.next_outbound().unwrap().unwrap())
            .unwrap();
        // A duplicate request must neither rewind the stream nor extend its deadline.
        let progress = sender.last_outbound_progress;
        sender.receive(request).unwrap();
        assert_eq!(sender.last_outbound_progress, progress);
        let received = loop {
            if let Some(received) = receiver
                .receive(sender.next_outbound().unwrap().unwrap())
                .unwrap()
            {
                break received;
            }
        };
        assert_eq!(
            std::fs::read(&received.paths[0]).unwrap(),
            std::fs::read(&source).unwrap()
        );
        sender
            .receive(FileTransferMessage::Accepted { transfer_id: 42 })
            .unwrap();
        assert!(!sender.has_outbound());
        std::fs::remove_dir_all(source.parent().unwrap()).unwrap();
    }

    #[test]
    fn superseded_lazy_offer_cannot_be_requested() {
        let source = temp_file("cancel.bin", b"");
        File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_len(EAGER_FILE_BYTES)
            .unwrap();
        let mut sender = FileTransfers::new("lazy-cancel-sender");
        let mut receiver = FileTransfers::new("lazy-cancel-receiver");
        receiver
            .receive(sender.begin_outbound(1, vec![source.clone()]).unwrap())
            .unwrap();
        receiver
            .receive(sender.cancel_outbound("new copy").unwrap())
            .unwrap();
        assert!(receiver.request_inbound(1).unwrap().is_none());
        sender.begin_outbound(2, vec![source.clone()]).unwrap();
        sender
            .receive(FileTransferMessage::Request { transfer_id: 1 })
            .unwrap();
        assert_eq!(sender.outbound_id(), Some(2));
        assert!(sender.next_outbound().unwrap().is_none());
        assert!(!receiver.root.exists());
        std::fs::remove_dir_all(source.parent().unwrap()).unwrap();
    }

    #[test]
    fn source_changed_while_waiting_is_rejected_when_requested() {
        let source = temp_file("changed.bin", b"");
        File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_len(EAGER_FILE_BYTES)
            .unwrap();
        let mut sender = FileTransfers::new("lazy-changed");
        sender.begin_outbound(1, vec![source.clone()]).unwrap();
        std::fs::write(&source, b"replacement").unwrap();
        assert!(sender.next_outbound().unwrap().is_none());
        sender
            .receive(FileTransferMessage::Request { transfer_id: 1 })
            .unwrap();
        assert!(sender
            .next_outbound()
            .unwrap_err()
            .to_string()
            .contains("changed"));
        std::fs::remove_dir_all(source.parent().unwrap()).unwrap();
    }

    #[test]
    fn late_acknowledgements_do_not_cancel_the_new_transfer() {
        let mut sender = FileTransfers::new("late-ack");
        sender.begin_image_outbound(1, b"old").unwrap();
        while sender.next_outbound().unwrap().is_some() {}
        sender.cancel_outbound("new copy");
        sender.begin_image_outbound(2, b"new").unwrap();
        sender
            .receive(FileTransferMessage::Accepted { transfer_id: 1 })
            .unwrap();
        assert_eq!(sender.outbound_id(), Some(2));
        sender
            .receive(FileTransferMessage::Cancel {
                transfer_id: 1,
                reason: "late cancellation".into(),
            })
            .unwrap();
        assert_eq!(sender.outbound_id(), Some(2));
    }

    #[test]
    fn completed_transfer_acceptance_is_idempotent() {
        let mut sender = FileTransfers::new("duplicate-ack");
        sender.begin_image_outbound(1, b"image").unwrap();
        while sender.next_outbound().unwrap().is_some() {}
        sender
            .receive(FileTransferMessage::Accepted { transfer_id: 1 })
            .unwrap();
        sender
            .receive(FileTransferMessage::Accepted { transfer_id: 1 })
            .unwrap();
        assert!(!sender.has_outbound());
    }

    #[test]
    fn stalled_transfer_and_missing_ack_expire() {
        let mut sender = FileTransfers::new("deadline");
        sender.begin_image_outbound(1, b"image").unwrap();
        assert!(sender.expired(
            Instant::now() + Duration::from_secs(31),
            Duration::from_secs(30)
        ));
        while sender.next_outbound().unwrap().is_some() {}
        assert!(sender.expired(
            Instant::now() + Duration::from_secs(31),
            Duration::from_secs(30)
        ));
    }

    #[test]
    fn filenames_are_unique_on_case_insensitive_destinations_and_bounded() {
        let mut used = HashSet::new();
        assert_eq!(unique_name("Report.txt".into(), &mut used), "Report.txt");
        assert_eq!(
            unique_name("report.txt".into(), &mut used),
            "report (2).txt"
        );
        assert!(validate_manifest(
            TransferPurpose::Files,
            &[
                FileMeta {
                    name: "Report.txt".into(),
                    size: 0
                },
                FileMeta {
                    name: "report.txt".into(),
                    size: 0
                },
            ]
        )
        .is_err());
        let name = portable_name(&"文件".repeat(100));
        assert!(name.len() <= 200);
        assert_eq!(portable_name(&name), name);
        let first = unique_name(name.clone(), &mut used);
        let second = unique_name(name, &mut used);
        assert_ne!(first, second);
        assert!(validate_manifest(
            TransferPurpose::Files,
            &[
                FileMeta {
                    name: first,
                    size: 0
                },
                FileMeta {
                    name: second,
                    size: 0
                },
            ]
        )
        .is_ok());
        let reserved = portable_name(&format!("CON.{}", "a".repeat(300)));
        assert!(reserved.len() <= 200);
        assert_eq!(portable_name(&reserved), reserved);
    }

    #[test]
    fn same_size_modified_source_is_rejected() {
        let path = temp_file("modified.bin", b"old");
        let mut sender = FileTransfers::new("modified-source");
        sender.begin_outbound(1, vec![path.clone()]).unwrap();
        std::fs::write(&path, b"new").unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1))
            .unwrap();
        assert!(sender
            .next_outbound()
            .unwrap_err()
            .to_string()
            .contains("changed"));
        sender.cancel_outbound("test complete");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn portable_names_remove_cross_platform_path_characters() {
        assert_eq!(portable_name("../bad:name?.txt"), ".._bad_name_.txt");
        assert_eq!(portable_name("..."), "file");
        assert_eq!(portable_name("CON.txt"), "_CON.txt");
    }

    #[test]
    fn streams_and_verifies_a_file() {
        let expected = (0..(FILE_CHUNK_BYTES * 2 + 731))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let source = temp_file("hello.bin", &expected);
        let mut sender = FileTransfers::new("receiver-test");
        let mut receiver = FileTransfers::new("sender-test");
        let offer = sender.begin_outbound(42, vec![source.clone()]).unwrap();
        receiver.receive(offer).unwrap();
        let received = loop {
            let message = sender.next_outbound().unwrap().unwrap();
            if let Some(received) = receiver.receive(message).unwrap() {
                break received;
            }
        };
        assert_eq!(received.paths.len(), 1);
        assert_eq!(std::fs::read(&received.paths[0]).unwrap(), expected);
        sender
            .receive(FileTransferMessage::Accepted {
                transfer_id: received.transfer_id,
            })
            .unwrap();
        assert!(!sender.has_outbound());
        let _ = std::fs::remove_dir_all(received.directory);
        let _ = std::fs::remove_dir_all(source.parent().unwrap());
    }

    #[test]
    fn rejects_manifest_path_traversal() {
        assert!(validate_manifest(
            TransferPurpose::Files,
            &[FileMeta {
                name: "../escape".into(),
                size: 1,
            }]
        )
        .is_err());
    }

    #[test]
    fn streams_image_payload_with_image_purpose() {
        let expected = (0..(FILE_CHUNK_BYTES + 137))
            .map(|index| (index % 239) as u8)
            .collect::<Vec<_>>();
        let mut sender = FileTransfers::new("receiver-image-test");
        let mut receiver = FileTransfers::new("sender-image-test");
        let offer = sender.begin_image_outbound(77, &expected).unwrap();
        assert!(matches!(
            offer,
            FileTransferMessage::Offer {
                purpose: TransferPurpose::Image,
                ..
            }
        ));
        receiver.receive(offer).unwrap();
        let received = loop {
            let message = sender.next_outbound().unwrap().unwrap();
            if let Some(received) = receiver.receive(message).unwrap() {
                break received;
            }
        };
        assert_eq!(received.purpose, TransferPurpose::Image);
        assert_eq!(received.paths.len(), 1);
        assert_eq!(std::fs::read(&received.paths[0]).unwrap(), expected);
        sender
            .receive(FileTransferMessage::Accepted {
                transfer_id: received.transfer_id,
            })
            .unwrap();
        assert!(!sender.has_outbound());
        let _ = std::fs::remove_dir_all(received.directory);
    }

    #[test]
    fn rejects_invalid_image_manifest() {
        assert!(validate_manifest(
            TransferPurpose::Image,
            &[FileMeta {
                name: "not-an-image.bin".into(),
                size: 1,
            }]
        )
        .is_err());
        assert!(validate_manifest(
            TransferPurpose::Image,
            &[FileMeta {
                name: "clipboard.png".into(),
                size: MAX_IMAGE_BYTES as u64 + 1,
            }]
        )
        .is_err());
    }

    #[test]
    fn rejects_file_with_wrong_hash() {
        let source = temp_file("tampered.txt", b"trusted bytes");
        let mut sender = FileTransfers::new("receiver-hash-test");
        let mut receiver = FileTransfers::new("sender-hash-test");
        let offer = sender.begin_outbound(99, vec![source.clone()]).unwrap();
        receiver.receive(offer).unwrap();
        let chunk = sender.next_outbound().unwrap().unwrap();
        receiver.receive(chunk).unwrap();
        let end = sender.next_outbound().unwrap().unwrap();
        let FileTransferMessage::FileEnd {
            transfer_id,
            file_index,
            ..
        } = end
        else {
            panic!("expected file end");
        };
        assert!(receiver
            .receive(FileTransferMessage::FileEnd {
                transfer_id,
                file_index,
                sha256: "00".repeat(32),
            })
            .is_err());
        receiver.cancel_inbound();
        let _ = std::fs::remove_dir_all(source.parent().unwrap());
    }
}
