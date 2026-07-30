//! Streaming file-transfer state for the clipboard TLS channel.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const MAX_FILES: usize = 32;
pub const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_IMAGE_BYTES: usize = 64 * 1024 * 1024;
const FILE_CHUNK_BYTES: usize = 128 * 1024;

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

pub struct FileTransfers {
    root: PathBuf,
    outbound: Option<OutboundTransfer>,
    inbound: Option<InboundTransfer>,
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
        }
    }

    pub fn has_outbound(&self) -> bool {
        self.outbound.is_some()
    }

    pub fn cancel_outbound(&mut self, reason: &str) -> Option<FileTransferMessage> {
        self.outbound
            .take()
            .map(|transfer| FileTransferMessage::Cancel {
                transfer_id: transfer.id,
                reason: reason.to_string(),
            })
    }

    pub fn cancel_inbound(&mut self) {
        if let Some(transfer) = self.inbound.take() {
            let directory = transfer.directory.clone();
            drop(transfer);
            let _ = std::fs::remove_dir_all(directory);
        }
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

        std::fs::create_dir_all(&self.root)
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
        let transfer = OutboundTransfer::new(transfer_id, paths, cleanup_directory)?;
        let offer = FileTransferMessage::Offer {
            transfer_id,
            purpose,
            files: transfer.files.clone(),
        };
        self.outbound = Some(transfer);
        Ok(offer)
    }

    pub fn next_outbound(&mut self) -> Result<Option<FileTransferMessage>> {
        let Some(transfer) = self.outbound.as_mut() else {
            return Ok(None);
        };
        transfer.next_message()
    }

    pub fn receive(&mut self, message: FileTransferMessage) -> Result<Option<ReceivedFiles>> {
        match message {
            FileTransferMessage::Offer {
                transfer_id,
                purpose,
                files,
            } => {
                self.cancel_inbound();
                self.inbound = Some(InboundTransfer::create(
                    &self.root,
                    transfer_id,
                    purpose,
                    files,
                )?);
                Ok(None)
            }
            FileTransferMessage::Cancel { transfer_id, .. } => {
                if self
                    .inbound
                    .as_ref()
                    .is_some_and(|transfer| transfer.id == transfer_id)
                {
                    self.cancel_inbound();
                }
                if self
                    .outbound
                    .as_ref()
                    .is_some_and(|transfer| transfer.id == transfer_id)
                {
                    self.outbound = None;
                }
                Ok(None)
            }
            FileTransferMessage::Accepted { transfer_id } => {
                let transfer = self
                    .outbound
                    .as_ref()
                    .context("received file acceptance without an outbound transfer")?;
                if transfer.id != transfer_id || !transfer.complete_sent {
                    bail!("file acceptance does not match the completed outbound transfer");
                }
                self.outbound = None;
                Ok(None)
            }
            message => {
                let transfer = self
                    .inbound
                    .as_mut()
                    .context("received file data without an active offer")?;
                let complete = transfer.receive(message)?;
                if complete {
                    let transfer = self.inbound.take().expect("inbound transfer exists");
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
    cleanup_directory: Option<PathBuf>,
    file_index: usize,
    open_file: Option<File>,
    offset: u64,
    hasher: Sha256,
    complete_sent: bool,
}

impl Drop for OutboundTransfer {
    fn drop(&mut self) {
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
            normalized.push(path);
        }

        Ok(Self {
            id,
            files,
            paths: normalized,
            cleanup_directory,
            file_index: 0,
            open_file: None,
            offset: 0,
            hasher: Sha256::new(),
            complete_sent: false,
        })
    }

    fn next_message(&mut self) -> Result<Option<FileTransferMessage>> {
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
        std::fs::create_dir_all(root)
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
            || !names.insert(file.name.clone())
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
    } else if is_windows_reserved_name(trimmed) {
        format!("_{trimmed}")
    } else {
        trimmed.to_string()
    }
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
    if used.insert(name.clone()) {
        return name;
    }
    let path = Path::new(&name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let extension = path.extension().and_then(|value| value.to_str());
    for suffix in 2..=MAX_FILES + 1 {
        let candidate = match extension {
            Some(extension) => format!("{stem} ({suffix}).{extension}"),
            None => format!("{stem} ({suffix})"),
        };
        if used.insert(candidate.clone()) {
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
