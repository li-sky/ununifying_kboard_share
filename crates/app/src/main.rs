//! Unified kbshare peer. Every machine can capture, inject, listen, and connect.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use kbshare_core::codec::LineDecoder;
use kbshare_core::protocol::Message;
use kbshare_core::runtime::{ClientDriver, ClientStep, HostDriver, Step};
use kbshare_core::state::{Mode, SideEffect};
use kbshare_net::cert::{fingerprint_hex, load_or_create_cert};
use kbshare_net::registry::{NodeReport, RegistryClient};
use kbshare_net::session::{client_handshake, recv_message, server_handshake};
use kbshare_net::tls::{build_client_config, build_server_config};
use kbshare_net::trust::{AutoTrustPolicy, TrustDecision, TrustStore};
use kbshare_platform::{default_capture, default_injector, default_mouse_watcher, MouseActivity};
use kbshare_tray::{TrayConfig, TrayExit, MODE_LOCAL, MODE_REMOTE};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(about = "Share one keyboard and mouse between kbshare peers")]
struct Args {
    #[arg(short, long, default_value = "config.json")]
    config: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    local_id: String,
    remote_id: String,
    #[serde(default = "default_tcp_port")]
    tcp_port: u16,
    #[serde(default = "default_cert")]
    cert_file: PathBuf,
    #[serde(default = "default_key")]
    key_file: PathBuf,
    #[serde(default = "default_trust")]
    trust_store: PathBuf,
    #[serde(default)]
    fallback_remote_ips: Vec<String>,
    #[serde(default)]
    vps_base_url: Option<String>,
    #[serde(default = "default_reconnect_secs")]
    reconnect_secs: u64,
    #[serde(default = "default_heartbeat_secs")]
    heartbeat_secs: f32,
    #[serde(default = "default_idle_secs")]
    idle_after_secs: f32,
    #[serde(default)]
    auto_trust_first_seen: bool,
    #[serde(default)]
    flow_lite: kbshare_flow::FlowLiteConfig,
}

fn default_tcp_port() -> u16 { 5005 }
fn default_cert() -> PathBuf { PathBuf::from("certs/kbshare_cert.pem") }
fn default_key() -> PathBuf { PathBuf::from("certs/kbshare_key.pem") }
fn default_trust() -> PathBuf { PathBuf::from("trust.json") }
fn default_reconnect_secs() -> u64 { 3 }
fn default_heartbeat_secs() -> f32 { 1.0 }
fn default_idle_secs() -> f32 { 3.0 }

#[derive(Debug, Clone)]
struct RuntimePaths {
    config_path: PathBuf,
    config_dir: PathBuf,
    log_dir: PathBuf,
    log_file: PathBuf,
}

trait PeerIo: Read + Write + Send {}
impl<T: Read + Write + Send> PeerIo for T {}
type SharedStream = Arc<Mutex<Box<dyn PeerIo>>>;
type SharedInjector = Arc<Mutex<Box<dyn kbshare_platform::KeyInjector>>>;

struct SessionCtx {
    outbound: HostDriver,
    inbound: ClientDriver,
    stream: SharedStream,
}
type SessionSlot = Arc<Mutex<Option<SessionCtx>>>;

fn main() -> Result<()> {
    let args = Args::parse();
    let paths = resolve_runtime_paths(&args.config)?;
    let _log_guard = init_logging(&paths.log_file)?;
    if let Err(error) = run(paths) {
        tracing::error!(error = %error, "kbshare exited");
        return Err(error);
    }
    Ok(())
}

fn run(paths: RuntimePaths) -> Result<()> {
    let mut cfg = load_config(&paths.config_path)?;
    resolve_config_paths(&mut cfg, &paths.config_dir);
    cfg.flow_lite
        .ensure_layout(&cfg.local_id, &cfg.remote_id, kbshare_flow::FlowRole::Host);

    let bundle = load_or_create_cert(&cfg.cert_file, &cfg.key_file, &cfg.local_id)?;
    let our_fp = fingerprint_hex(&bundle.cert_der);
    tracing::info!(id = %cfg.local_id, peer = %cfg.remote_id, fingerprint = %our_fp, "kbshare peer starting");

    let mode_flag = Arc::new(AtomicU8::new(MODE_LOCAL));
    let session_active = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::new(AtomicBool::new(false));
    let tray_cfg = TrayConfig {
        app_name: "kbshare".to_string(),
        local_id: cfg.local_id.clone(),
        fingerprint: our_fp.clone(),
        config_path: Some(paths.config_path.clone()),
        config_dir: Some(paths.config_dir.clone()),
        log_dir: Some(paths.log_dir.clone()),
    };

    let client_tls = build_client_config(&bundle)?;
    let server_tls = build_server_config(&bundle)?;
    let engine_shutdown = shutdown.clone();
    let engine_mode = mode_flag.clone();
    let engine_session = session_active.clone();
    let engine_config = paths.config_path.clone();
    let engine = std::thread::Builder::new().name("peer-engine".into()).spawn(move || {
        let result = run_engine(cfg, our_fp, client_tls, server_tls, engine_config, engine_mode, engine_session, engine_shutdown.clone());
        if let Err(error) = &result {
            tracing::error!(error = %error, "peer engine exited");
            engine_shutdown.store(true, Ordering::Relaxed);
        }
        result
    })?;

    let tray_exit = kbshare_tray::run_tray(tray_cfg, mode_flag, session_active, shutdown.clone())?;
    shutdown.store(true, Ordering::Relaxed);
    let engine_result = engine.join().map_err(|_| anyhow!("peer engine thread panicked"))?;
    match tray_exit {
        TrayExit::ReloadConfig(path) => {
            relaunch_with_config(&path)?;
            Ok(())
        }
        TrayExit::Quit => engine_result,
    }
}

#[allow(clippy::too_many_arguments)]
fn run_engine(
    cfg: Config,
    our_fp: String,
    client_tls: Arc<rustls::ClientConfig>,
    server_tls: Arc<rustls::ServerConfig>,
    config_path: PathBuf,
    mode_flag: Arc<AtomicU8>,
    session_active: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let trust = Arc::new(TrustStore::load(cfg.trust_store.clone())?);
    let policy = if cfg.auto_trust_first_seen {
        AutoTrustPolicy::TrustOnFirstUse
    } else {
        AutoTrustPolicy::RequireKnown
    };
    let flow = Arc::new(Mutex::new(cfg.flow_lite.clone()));
    let slot: SessionSlot = Arc::new(Mutex::new(None));
    let injector: SharedInjector = Arc::new(Mutex::new(default_injector()?));
    let mouse_tick = Arc::new(AtomicBool::new(false));

    let mut capture = default_capture()?;
    let forwarding = capture.forwarding_flag();
    {
        let slot = slot.clone();
        capture.start(Box::new(move |action, key| {
            let mut guard = slot.lock();
            if let Some(ctx) = guard.as_mut() {
                let step = ctx.outbound.on_local_key(action, key);
                if let Err(error) = send_host_step(&ctx.stream, &step) {
                    tracing::warn!(error = %error, "send key failed");
                }
            }
        }))?;
    }

    let mut mouse = default_mouse_watcher()?;
    {
        let slot = slot.clone();
        let flow = flow.clone();
        let forwarding = forwarding.clone();
        let mode_flag = mode_flag.clone();
        let injector = injector.clone();
        let mouse_tick = mouse_tick.clone();
        let local_id = cfg.local_id.clone();
        let remote_id = cfg.remote_id.clone();
        mouse.start(Box::new(move |activity| {
            let mut guard = slot.lock();
            let Some(ctx) = guard.as_mut() else { return; };
            let flow_config = flow.lock().clone();
            let target = flow_config.target_for_peer(&local_id, &remote_id);
            if flow_config.enabled
                && ctx.outbound.mode() == Mode::Local
                && target.map(|target| activity_hits_edge(activity, target.edge, flow_config.edge_px.max(0))).unwrap_or(false)
            {
                let target = target.expect("edge target checked");
                match kbshare_flow::switch_host(flow_config.slot, target.host_index) {
                    Ok(_) => {
                        mouse_tick.store(false, Ordering::Relaxed);
                        let step = ctx.outbound.on_flow_departure();
                        apply_host_effects(&step, &forwarding, &mode_flag);
                        let _ = send_host_step(&ctx.stream, &step);
                    }
                    Err(error) => tracing::warn!(error = %error, "Flow-lite switch failed"),
                }
                return;
            }

            let host_step = ctx.outbound.on_local_mouse();
            apply_host_effects(&host_step, &forwarding, &mode_flag);
            let _ = send_host_step(&ctx.stream, &host_step);
            if !mouse_tick.swap(true, Ordering::Relaxed) {
                let client_step = ctx.inbound.on_local_mouse_active();
                let _ = apply_client_step(&ctx.stream, &injector, &client_step);
            }
        }))?;
    }

    {
        let slot = slot.clone();
        let injector = injector.clone();
        let mouse_tick = mouse_tick.clone();
        let shutdown = shutdown.clone();
        let interval = Duration::from_secs_f32(cfg.heartbeat_secs.max(0.05));
        std::thread::Builder::new().name("peer-heartbeat".into()).spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(interval);
                let mut guard = slot.lock();
                if let Some(ctx) = guard.as_mut() {
                    let active = mouse_tick.swap(false, Ordering::Relaxed)
                        && ctx.outbound.mode() == Mode::Local;
                    let step = if active { ctx.inbound.on_local_mouse_active() } else { ctx.inbound.on_local_mouse_idle() };
                    let _ = apply_client_step(&ctx.stream, &injector, &step);
                }
            }
        })?;
    }

    if cfg.local_id < cfg.remote_id {
        run_dialer(&cfg, &our_fp, client_tls, &trust, policy, &slot, &injector, &forwarding, &mode_flag, &session_active, &shutdown, &flow, &config_path)
    } else {
        run_listener(&cfg, &our_fp, server_tls, &trust, policy, &slot, &injector, &forwarding, &mode_flag, &session_active, &shutdown, &flow, &config_path)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_dialer(
    cfg: &Config,
    our_fp: &str,
    tls: Arc<rustls::ClientConfig>,
    trust: &TrustStore,
    policy: AutoTrustPolicy,
    slot: &SessionSlot,
    injector: &SharedInjector,
    forwarding: &Arc<AtomicBool>,
    mode_flag: &Arc<AtomicU8>,
    session_active: &Arc<AtomicBool>,
    shutdown: &Arc<AtomicBool>,
    flow: &Arc<Mutex<kbshare_flow::FlowLiteConfig>>,
    config_path: &Path,
) -> Result<()> {
    while !shutdown.load(Ordering::Relaxed) {
        let mut attempted = false;
        for addr in resolve_peer_addrs(cfg) {
            attempted = true;
            if shutdown.load(Ordering::Relaxed) { return Ok(()); }
            let result = (|| -> Result<()> {
                let socket = addr.parse().with_context(|| format!("parse peer address {addr}"))?;
                let tcp = TcpStream::connect_timeout(&socket, Duration::from_secs(5))?;
                prepare_tcp(&tcp)?;
                let (stream, peer_fp) = client_handshake(tcp, tls.clone(), &cfg.remote_id)?;
                run_session(cfg, our_fp, Box::new(stream), Some(peer_fp), trust, policy, slot, injector, forwarding, mode_flag, session_active, shutdown, flow, config_path)
            })();
            if let Err(error) = result {
                tracing::warn!(%addr, error = %error, "peer session ended");
            }
        }
        if !attempted { tracing::warn!("no peer address discovered; waiting"); }
        sleep_or_stop(Duration::from_secs(cfg.reconnect_secs), shutdown);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_listener(
    cfg: &Config,
    our_fp: &str,
    tls: Arc<rustls::ServerConfig>,
    trust: &TrustStore,
    policy: AutoTrustPolicy,
    slot: &SessionSlot,
    injector: &SharedInjector,
    forwarding: &Arc<AtomicBool>,
    mode_flag: &Arc<AtomicU8>,
    session_active: &Arc<AtomicBool>,
    shutdown: &Arc<AtomicBool>,
    flow: &Arc<Mutex<kbshare_flow::FlowLiteConfig>>,
    config_path: &Path,
) -> Result<()> {
    let bind = format!("0.0.0.0:{}", cfg.tcp_port);
    let listener = TcpListener::bind(&bind).with_context(|| format!("bind {bind}"))?;
    listener.set_nonblocking(true)?;
    report_local_node(cfg);
    tracing::info!(%bind, "waiting for peer");
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((tcp, address)) => {
                prepare_tcp(&tcp)?;
                tracing::info!(%address, "peer connected");
                let result = (|| -> Result<()> {
                    let (stream, _) = server_handshake(tcp, tls.clone())?;
                    run_session(cfg, our_fp, Box::new(stream), None, trust, policy, slot, injector, forwarding, mode_flag, session_active, shutdown, flow, config_path)
                })();
                if let Err(error) = result { tracing::warn!(error = %error, "peer session ended"); }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => tracing::warn!(error = %error, "accept failed"),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_session(
    cfg: &Config,
    our_fp: &str,
    stream: Box<dyn PeerIo>,
    tls_peer_fp: Option<String>,
    trust: &TrustStore,
    policy: AutoTrustPolicy,
    slot: &SessionSlot,
    injector: &SharedInjector,
    forwarding: &Arc<AtomicBool>,
    mode_flag: &Arc<AtomicU8>,
    session_active: &Arc<AtomicBool>,
    shutdown: &Arc<AtomicBool>,
    flow: &Arc<Mutex<kbshare_flow::FlowLiteConfig>>,
    config_path: &Path,
) -> Result<()> {
    let stream: SharedStream = Arc::new(Mutex::new(stream));
    let mut outbound = HostDriver::new(&cfg.local_id, &cfg.remote_id, our_fp);
    let mut inbound = ClientDriver::new(&cfg.local_id, &cfg.remote_id, our_fp);
    let hello = outbound.on_session_established();
    let _ = inbound.on_session_established();
    apply_host_effects(&hello, forwarding, mode_flag);
    send_host_step(&stream, &hello)?;
    send_one(&stream, &Message::FlowLayout { id: cfg.local_id.clone(), layout: flow.lock().layout.clone() })?;
    *slot.lock() = Some(SessionCtx { outbound, inbound, stream: stream.clone() });
    session_active.store(true, Ordering::Relaxed);

    let mut verified = false;
    let mut decoder = LineDecoder::new();
    let result = loop {
        if shutdown.load(Ordering::Relaxed) { break Ok(()); }
        let incoming = {
            let mut reader = stream.lock();
            match recv_message(&mut *reader, &mut decoder) {
                Ok(message) => message,
                Err(error) if is_timeout(&error) => None,
                Err(error) => break Err(error),
            }
        };
        let Some(message) = incoming else { continue; };
        if !verified {
            let Message::Hello { id, fingerprint, .. } = &message else {
                break Err(anyhow!("first peer message must be Hello"));
            };
            if id != &cfg.remote_id { break Err(anyhow!("peer id {id} != configured {}", cfg.remote_id)); }
            if tls_peer_fp.as_ref().is_some_and(|actual| actual != fingerprint) {
                break Err(anyhow!("peer Hello fingerprint does not match TLS certificate"));
            }
            verify_trust(trust, policy, id, fingerprint)?;
            verified = true;
        }

        if let Message::FlowLayout { id, layout } = &message {
            if id != &cfg.remote_id { continue; }
            match kbshare_flow::reconcile_layout(&mut flow.lock().layout, layout) {
                kbshare_flow::LayoutReconcile::AppliedRemote => kbshare_flow::persist_layout(config_path, layout)?,
                kbshare_flow::LayoutReconcile::SendLocal(layout) => send_one(&stream, &Message::FlowLayout { id: cfg.local_id.clone(), layout })?,
                kbshare_flow::LayoutReconcile::Equal => {}
            }
            continue;
        }

        let mut guard = slot.lock();
        let Some(ctx) = guard.as_mut() else { break Ok(()); };
        let host_step = ctx.outbound.on_incoming(message.clone());
        apply_host_effects(&host_step, forwarding, mode_flag);
        send_host_step(&ctx.stream, &host_step)?;
        let client_step = ctx.inbound.on_incoming(message);
        apply_client_step(&ctx.stream, injector, &client_step)?;
    };

    if let Some(ctx) = slot.lock().as_mut() {
        let host_step = ctx.outbound.on_session_lost();
        apply_host_effects(&host_step, forwarding, mode_flag);
        let _ = send_host_step(&ctx.stream, &host_step);
        let client_step = ctx.inbound.on_session_lost();
        let _ = apply_client_step(&ctx.stream, injector, &client_step);
    }
    *slot.lock() = None;
    session_active.store(false, Ordering::Relaxed);
    forwarding.store(false, Ordering::Relaxed);
    mode_flag.store(MODE_LOCAL, Ordering::Relaxed);
    result
}

fn verify_trust(trust: &TrustStore, policy: AutoTrustPolicy, id: &str, fingerprint: &str) -> Result<()> {
    match trust.evaluate(id, fingerprint) {
        TrustDecision::KnownAndMatches => Ok(()),
        TrustDecision::Unknown if matches!(policy, AutoTrustPolicy::TrustOnFirstUse) => trust.learn(id, fingerprint),
        TrustDecision::Unknown => Err(anyhow!("unknown peer fingerprint {fingerprint}")),
        TrustDecision::Mismatch { expected, actual } => Err(anyhow!("peer fingerprint mismatch: expected {expected}, got {actual}")),
    }
}

fn resolve_peer_addrs(cfg: &Config) -> Vec<String> {
    if let Some(base) = &cfg.vps_base_url {
        if let Ok(entry) = RegistryClient::new(base).lookup(&cfg.remote_id) {
            if !entry.ips.is_empty() {
                let port = entry.tcp_port.unwrap_or(cfg.tcp_port);
                return entry.ips.into_iter().map(|ip| format!("{ip}:{port}")).collect();
            }
        }
    }
    cfg.fallback_remote_ips.iter().map(|ip| format!("{ip}:{}", cfg.tcp_port)).collect()
}

fn report_local_node(cfg: &Config) {
    let Some(base) = &cfg.vps_base_url else { return; };
    let ips = local_ip().into_iter().collect::<Vec<_>>();
    if ips.is_empty() { tracing::warn!("could not determine local IP for discovery report"); return; }
    let report = NodeReport { node_id: cfg.local_id.clone(), ips, tcp_port: Some(cfg.tcp_port), udp_port: None, event: "online".into() };
    if let Err(error) = RegistryClient::new(base).report(&report) {
        tracing::warn!(error = %error, "cloud discovery report failed");
    }
}

fn local_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

fn prepare_tcp(tcp: &TcpStream) -> Result<()> {
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(Duration::from_millis(10)))?;
    Ok(())
}

fn send_one(stream: &SharedStream, message: &Message) -> Result<()> {
    let line = kbshare_core::codec::encode_line(message)?;
    let mut writer = stream.lock();
    writer.write_all(&line)?;
    Ok(())
}

fn send_host_step(stream: &SharedStream, step: &Step) -> Result<()> {
    for message in &step.outgoing { send_one(stream, message)?; }
    Ok(())
}

fn apply_client_step(stream: &SharedStream, injector: &SharedInjector, step: &ClientStep) -> Result<()> {
    for message in &step.outgoing { send_one(stream, message)?; }
    for (action, key) in &step.inject {
        let mut injector = injector.lock();
        match action {
            kbshare_core::protocol::KeyAction::Press => injector.press(*key)?,
            kbshare_core::protocol::KeyAction::Release => injector.release(*key)?,
        }
    }
    Ok(())
}

fn apply_host_effects(step: &Step, forwarding: &Arc<AtomicBool>, mode_flag: &Arc<AtomicU8>) {
    for effect in &step.effects {
        match effect {
            SideEffect::StartForwardingKeyboard => forwarding.store(true, Ordering::Relaxed),
            SideEffect::ResumeLocalKeyboard => forwarding.store(false, Ordering::Relaxed),
            SideEffect::Notify(mode) => mode_flag.store(if *mode == Mode::Remote { MODE_REMOTE } else { MODE_LOCAL }, Ordering::Relaxed),
            _ => {}
        }
    }
}

fn activity_hits_edge(activity: MouseActivity, edge: kbshare_flow::FlowEdge, threshold: i32) -> bool {
    match edge {
        kbshare_flow::FlowEdge::Left => activity.at_left_edge(threshold),
        kbshare_flow::FlowEdge::Right => activity.at_right_edge(threshold),
        kbshare_flow::FlowEdge::Top => activity.at_top_edge(threshold),
        kbshare_flow::FlowEdge::Bottom => activity.at_bottom_edge(threshold),
    }
}

fn sleep_or_stop(total: Duration, shutdown: &AtomicBool) {
    let mut left = total;
    while left > Duration::ZERO && !shutdown.load(Ordering::Relaxed) {
        let chunk = Duration::from_millis(200).min(left);
        std::thread::sleep(chunk);
        left = left.saturating_sub(chunk);
    }
}

fn is_timeout(error: &anyhow::Error) -> bool {
    let message = error.to_string().to_lowercase();
    message.contains("timed out") || message.contains("would block")
}

fn resolve_runtime_paths(config_arg: &Path) -> Result<RuntimePaths> {
    let config_path = if config_arg.is_absolute() { config_arg.to_path_buf() } else { std::env::current_dir()?.join(config_arg) };
    let config_dir = config_path.parent().map(Path::to_path_buf).unwrap_or(std::env::current_dir()?);
    let log_dir = if config_dir.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.starts_with("runtime_")) {
        config_dir.parent().unwrap_or(&config_dir).join("logs")
    } else {
        config_dir.join("logs")
    };
    Ok(RuntimePaths { log_file: log_dir.join("kbshare.log"), config_path, config_dir, log_dir })
}

fn resolve_config_paths(cfg: &mut Config, config_dir: &Path) {
    for path in [&mut cfg.cert_file, &mut cfg.key_file, &mut cfg.trust_store] {
        if path.is_relative() { *path = config_dir.join(&*path); }
    }
}

fn load_config(path: &Path) -> Result<Config> {
    let bytes = std::fs::read(path).with_context(|| format!("read config {}", path.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn init_logging(log_file: &Path) -> Result<tracing_appender::non_blocking::WorkerGuard> {
    let log_dir = log_file.parent().ok_or_else(|| anyhow!("missing log directory"))?;
    std::fs::create_dir_all(log_dir)?;
    let name = log_file.file_name().and_then(|name| name.to_str()).ok_or_else(|| anyhow!("invalid log filename"))?;
    let appender = tracing_appender::rolling::never(log_dir, name);
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .with_writer(writer)
        .with_ansi(false)
        .init();
    Ok(guard)
}

fn relaunch_with_config(config_path: &Path) -> Result<()> {
    let exe = std::env::current_exe()?;
    let mut command = Command::new(exe);
    command.arg("--config").arg(config_path);
    if let Some(dir) = config_path.parent() { command.current_dir(dir); }
    command.spawn()?;
    Ok(())
}
