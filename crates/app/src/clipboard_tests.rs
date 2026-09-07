use super::*;
use parking_lot::Mutex;

#[derive(Default, Clone)]
struct FakeClipboard(Arc<Mutex<FakeContents>>);
#[derive(Default)]
struct FakeContents {
    text: Option<String>,
    html: Option<String>,
    rtf: Option<String>,
    files: Option<Vec<String>>,
}
type ClipResult<T> = clipboard_rs::Result<T>;
impl Clipboard for FakeClipboard {
    fn available_formats(&self) -> ClipResult<Vec<String>> {
        Ok(vec![])
    }
    fn has(&self, _: ContentFormat) -> bool {
        false
    }
    fn clear(&self) -> ClipResult<()> {
        *self.0.lock() = FakeContents::default();
        Ok(())
    }
    fn get_buffer(&self, _: &str) -> ClipResult<Vec<u8>> {
        Err("unsupported".into())
    }
    fn get_text(&self) -> ClipResult<String> {
        self.0.lock().text.clone().ok_or("empty".into())
    }
    fn get_html(&self) -> ClipResult<String> {
        self.0.lock().html.clone().ok_or("empty".into())
    }
    fn get_rich_text(&self) -> ClipResult<String> {
        self.0.lock().rtf.clone().ok_or("empty".into())
    }
    fn get_image(&self) -> ClipResult<RustImageData> {
        Err("empty".into())
    }
    fn get_files(&self) -> ClipResult<Vec<String>> {
        self.0.lock().files.clone().ok_or("empty".into())
    }
    fn get(&self, _: &[ContentFormat]) -> ClipResult<Vec<ClipboardContent>> {
        Err("unsupported".into())
    }
    fn set_buffer(&self, _: &str, _: Vec<u8>) -> ClipResult<()> {
        Err("unsupported".into())
    }
    fn set_text(&self, text: String) -> ClipResult<()> {
        self.set(vec![ClipboardContent::Text(text)])
    }
    fn set_html(&self, text: String) -> ClipResult<()> {
        self.set(vec![ClipboardContent::Html(text)])
    }
    fn set_rich_text(&self, text: String) -> ClipResult<()> {
        self.set(vec![ClipboardContent::Rtf(text)])
    }
    fn set_image(&self, _: RustImageData) -> ClipResult<()> {
        Err("unsupported".into())
    }
    fn set_files(&self, files: Vec<String>) -> ClipResult<()> {
        self.set(vec![ClipboardContent::Files(files)])
    }
    fn set(&self, contents: Vec<ClipboardContent>) -> ClipResult<()> {
        let mut current = self.0.lock();
        *current = FakeContents::default();
        for content in contents {
            match content {
                ClipboardContent::Text(value) => current.text = Some(value),
                ClipboardContent::Html(value) => current.html = Some(value),
                ClipboardContent::Rtf(value) => current.rtf = Some(value),
                ClipboardContent::Files(value) => current.files = Some(value),
                _ => {}
            }
        }
        Ok(())
    }
}

fn temp_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "clipboard-regression-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
pub(super) fn config(local: &str, remote: &str) -> ClipboardConfig {
    let directory = temp_dir();
    let bundle = kbshare_net::cert::load_or_create_cert(
        &directory.join("cert"),
        &directory.join("key"),
        local,
    )
    .unwrap();
    let config = ClipboardConfig {
        enabled: true,
        status: Arc::new(AtomicU8::new(kbshare_tray::CLIPBOARD_READY)),
        local_id: local.into(),
        remote_id: remote.into(),
        keyboard_port: 5005,
        port: 5006,
        fallback_remote_ips: vec![],
        vps_base_url: None,
        reconnect_secs: 1,
        trust_store: directory.join("trust"),
        trust_policy: AutoTrustPolicy::RequireKnown,
        our_fingerprint: kbshare_net::cert::fingerprint_hex(&bundle.cert_der),
        client_tls: kbshare_net::tls::build_client_config(&bundle).unwrap(),
        server_tls: kbshare_net::tls::build_server_config(&bundle).unwrap(),
    };
    std::fs::remove_dir_all(directory).unwrap();
    config
}
fn state(peer: &str) -> (ClipboardState, FakeClipboard) {
    let backend = FakeClipboard::default();
    backend.set_text("initial".into()).unwrap();
    let snapshot = observe_clipboard(&backend, true, None);
    (
        ClipboardState {
            clipboard: Box::new(backend.clone()),
            last_observed: snapshot,
            sequence: 0,
            revision: Revision::default(),
            pending: false,
            last_attempt: None,
            inbound_revision: None,
            transfers: FileTransfers::new(peer),
            received_directories: VecDeque::new(),
        },
        backend,
    )
}
fn text(id: &str, counter: u64, value: &str) -> ClipboardMessage {
    ClipboardMessage::Text {
        id: id.into(),
        revision: Revision {
            counter,
            origin: id.into(),
        },
        content: TextContent {
            text: value.into(),
            html: None,
            rtf: None,
        },
    }
}

#[test]
fn concurrent_copies_converge_and_stale_updates_are_ignored() {
    let a_cfg = config("alpha", "beta");
    let mut b_cfg = a_cfg.clone();
    b_cfg.local_id = "beta".into();
    b_cfg.remote_id = "alpha".into();
    let (mut a, a_clip) = state("beta");
    let (mut b, b_clip) = state("alpha");
    let (mut a_link, _a_net) = transport::channel();
    let (mut b_link, _b_net) = transport::channel();
    a_clip.set_text("A".into()).unwrap();
    b_clip.set_text("B".into()).unwrap();
    poll_local(&mut a_link, &a_cfg, &mut a, true).unwrap();
    poll_local(&mut b_link, &b_cfg, &mut b, true).unwrap();
    handle_incoming(&mut a_link, &a_cfg, &mut a, text("beta", 1, "B")).unwrap();
    handle_incoming(&mut b_link, &b_cfg, &mut b, text("alpha", 1, "A")).unwrap();
    assert_eq!(a_clip.get_text().unwrap(), "B");
    assert_eq!(b_clip.get_text().unwrap(), "B");
    assert_eq!(a.revision, b.revision);
    handle_incoming(&mut a_link, &a_cfg, &mut a, text("beta", 0, "old")).unwrap();
    assert_eq!(a_clip.get_text().unwrap(), "B");
}

#[test]
fn newer_local_copy_cancels_inbound_and_ignores_inflight_chunks() {
    let cfg = config("alpha", "beta");
    let (mut state, backend) = state("beta");
    let (mut link, network) = transport::channel();
    let mut sender = FileTransfers::new("alpha");
    let offer = sender.begin_image_outbound(42, b"old image").unwrap();
    let revision = Revision {
        counter: 1,
        origin: "beta".into(),
    };
    handle_incoming(
        &mut link,
        &cfg,
        &mut state,
        ClipboardMessage::Transfer {
            id: "beta".into(),
            revision: revision.clone(),
            message: offer,
        },
    )
    .unwrap();
    backend.set_text("new local copy".into()).unwrap();
    poll_local(&mut link, &cfg, &mut state, true).unwrap();
    assert!(state.transfers.inbound_id().is_none());
    assert!(network.drain().iter().any(|m| matches!(
        m,
        ClipboardMessage::Transfer {
            message: FileTransferMessage::Cancel {
                transfer_id: 42,
                ..
            },
            ..
        }
    )));
    while let Some(message) = sender.next_outbound().unwrap() {
        handle_incoming(
            &mut link,
            &cfg,
            &mut state,
            ClipboardMessage::Transfer {
                id: "beta".into(),
                revision: revision.clone(),
                message,
            },
        )
        .unwrap();
    }
    assert_eq!(backend.get_text().unwrap(), "new local copy");
    assert!(state.pending);
}

#[test]
fn failed_file_preparation_remains_retryable_and_same_path_changes_are_detected() {
    let cfg = config("alpha", "beta");
    let (mut state, backend) = state("beta");
    let (mut link, _network) = transport::channel();
    let directory = temp_dir();
    let path = directory.join("file.txt");
    backend
        .set_files(vec![path.to_string_lossy().into_owned()])
        .unwrap();
    poll_local(&mut link, &cfg, &mut state, true).unwrap();
    let snapshot = state.last_observed.clone().unwrap();
    send_clipboard_change(&mut link, &cfg, &mut state, snapshot).unwrap();
    assert!(state.pending);
    assert!(!state.transfers.has_outbound());
    std::fs::write(&path, b"new data").unwrap();
    let old_revision = state.revision.clone();
    poll_local(&mut link, &cfg, &mut state, true).unwrap();
    assert!(state.revision > old_revision);
    let snapshot = state.last_observed.clone().unwrap();
    send_clipboard_change(&mut link, &cfg, &mut state, snapshot).unwrap();
    assert!(state.transfers.has_outbound());
    state.transfers.cancel_outbound("test complete");
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn text_is_pending_until_applied_ack_even_across_reconnect() {
    let cfg = config("alpha", "beta");
    let (mut state, backend) = state("beta");
    let (mut link, _network) = transport::channel();
    backend.set_text("new".into()).unwrap();
    poll_local(&mut link, &cfg, &mut state, true).unwrap();
    let snapshot = state.last_observed.clone().unwrap();
    send_clipboard_change(&mut link, &cfg, &mut state, snapshot).unwrap();
    assert!(state.pending);
    let revision = state.revision.clone();
    state.on_session_lost();
    assert!(state.pending);
    assert_eq!(state.revision, revision);
    handle_incoming(
        &mut link,
        &cfg,
        &mut state,
        ClipboardMessage::Applied {
            id: "beta".into(),
            revision,
        },
    )
    .unwrap();
    assert!(!state.pending);
}

#[test]
fn html_and_rtf_are_applied_together_with_plain_text() {
    let cfg = config("alpha", "beta");
    let (mut state, backend) = state("beta");
    let (mut link, _network) = transport::channel();
    let content = TextContent {
        text: "hello".into(),
        html: Some("<b>hello</b>".into()),
        rtf: Some("{\\rtf1 hello}".into()),
    };
    handle_incoming(
        &mut link,
        &cfg,
        &mut state,
        ClipboardMessage::Text {
            id: "beta".into(),
            revision: Revision {
                counter: 1,
                origin: "beta".into(),
            },
            content: content.clone(),
        },
    )
    .unwrap();
    assert_eq!(backend.get_html().unwrap(), content.html.unwrap());
    assert_eq!(backend.get_rich_text().unwrap(), content.rtf.unwrap());
    assert_eq!(backend.get_text().unwrap(), "hello");
    poll_local(&mut link, &cfg, &mut state, true).unwrap();
    assert!(!state.pending);
}

#[test]
fn oversized_png_dimensions_are_rejected_before_decoding() {
    let mut header = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    header.extend(u32::MAX.to_be_bytes());
    header.extend(u32::MAX.to_be_bytes());
    assert!(validate_png_size(&header).is_err());
}

#[test]
fn image_comparison_uses_pixels_instead_of_png_encoding() {
    let original = include_bytes!("../../tray/src/icon_local.png").to_vec();
    let image = RustImageData::from_bytes(&original).unwrap();
    let reencoded = image.to_png().unwrap().get_bytes().to_vec();
    let restored = RustImageData::from_bytes(&reencoded).unwrap();
    let first = ImageSnapshot {
        png: original,
        digest: image_digest(&image).unwrap(),
    };
    let second = ImageSnapshot {
        png: reencoded,
        digest: image_digest(&restored).unwrap(),
    };
    assert_eq!(first, second);
    validate_png_size(&second.png).unwrap();
}
