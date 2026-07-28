use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;

pub enum EditorEvent {
    Saved(PathBuf),
    Failed(String),
}

pub fn launch(
    config_path: PathBuf,
    app_name: String,
    session_active: Arc<AtomicBool>,
) -> Result<Receiver<EditorEvent>> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("bind local editor")?;
    let address = listener.local_addr()?;
    let token = format!(
        "{:x}{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let route = format!("/{token}");
    let url = format!("http://{address}{route}");
    let (sender, receiver) = mpsc::channel();

    std::thread::Builder::new()
        .name("config-editor".into())
        .spawn(move || {
            if let Err(error) = serve(
                listener,
                &route,
                &config_path,
                &app_name,
                &sender,
                &session_active,
            ) {
                let _ = sender.send(EditorEvent::Failed(format!("{error:#}")));
            }
        })?;
    tracing::info!(%url, "configuration editor opened");
    #[cfg(debug_assertions)]
    eprintln!("configuration editor: {url}");
    open::that_detached(&url).with_context(|| format!("open {url}"))?;
    Ok(receiver)
}

fn serve(
    listener: TcpListener,
    route: &str,
    config_path: &Path,
    app_name: &str,
    sender: &Sender<EditorEvent>,
    session_active: &Arc<AtomicBool>,
) -> Result<()> {
    let bytes = std::fs::read(config_path)
        .with_context(|| format!("read config {}", config_path.display()))?;
    let config: Value = serde_json::from_slice(&bytes).context("parse current config")?;
    let page = render_page(&config, app_name, route)?;

    for incoming in listener.incoming() {
        let mut stream = incoming.context("accept editor connection")?;
        match read_request(&mut stream) {
            Ok(request) if request.method == "GET" && request.path == route => {
                respond(
                    &mut stream,
                    200,
                    "text/html; charset=utf-8",
                    page.as_bytes(),
                )?;
            }
            Ok(request) if request.method == "POST" && request.path == format!("{route}/save") => {
                match save_config(config_path, &request.body) {
                    Ok(()) => {
                        respond(&mut stream, 200, "application/json", br#"{"ok":true}"#)?;
                        let _ = sender.send(EditorEvent::Saved(config_path.to_path_buf()));
                        return Ok(());
                    }
                    Err(error) => {
                        let body =
                            serde_json::json!({ "ok": false, "error": format!("{error:#}") });
                        respond(
                            &mut stream,
                            400,
                            "application/json",
                            serde_json::to_string(&body)?.as_bytes(),
                        )?;
                    }
                }
            }
            Ok(request)
                if request.method == "GET" && request.path == format!("{route}/inspect") =>
            {
                match kbshare_flow::inspect() {
                    Ok(devices) => {
                        let body = serde_json::json!({
                            "ok": true,
                            "devices": devices.into_iter().map(|device| {
                                let is_mouse = device.is_mouse();
                                serde_json::json!({
                                    "name": device.name.unwrap_or_else(|| "Logitech device".into()),
                                    "product_id": format!("{:04x}", device.product_id),
                                    "connection": format!("{:?}", device.connection).to_lowercase(),
                                    "slot": device.slot,
                                    "host_count": device.host_count,
                                    "current_host": device.current_host,
                                    "fingerprint": device.fingerprint.map(hex_fingerprint),
                                    "is_mouse": is_mouse,
                                })
                            }).collect::<Vec<_>>()
                        });
                        respond(
                            &mut stream,
                            200,
                            "application/json",
                            serde_json::to_string(&body)?.as_bytes(),
                        )?;
                    }
                    Err(error) => {
                        let body = serde_json::json!({
                            "ok": false,
                            "error": format!("{error:#}")
                        });
                        respond(
                            &mut stream,
                            200,
                            "application/json",
                            serde_json::to_string(&body)?.as_bytes(),
                        )?;
                    }
                }
            }
            Ok(request)
                if request.method == "POST" && request.path == format!("{route}/certificate") =>
            {
                let result = (|| -> Result<Value> {
                    let payload: Value = serde_json::from_slice(&request.body)?;
                    let local_id = required_string(&payload, "local_id")?;
                    let cert_file = payload["cert_file"].as_str().unwrap_or("certs/cert.pem");
                    let key_file = payload["key_file"].as_str().unwrap_or("certs/key.pem");
                    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
                    let cert_path = resolve_editor_path(config_dir, cert_file);
                    let key_path = resolve_editor_path(config_dir, key_file);
                    let existed = cert_path.exists() && key_path.exists();
                    let bundle =
                        kbshare_net::cert::load_or_create_cert(&cert_path, &key_path, local_id)?;
                    Ok(serde_json::json!({
                        "ok": true,
                        "created": !existed,
                        "cert_file": cert_file,
                        "key_file": key_file,
                        "fingerprint": kbshare_net::cert::fingerprint_hex(&bundle.cert_der),
                    }))
                })();
                respond_json_result(&mut stream, result)?;
            }
            Ok(request)
                if request.method == "POST" && request.path == format!("{route}/register") =>
            {
                let result = (|| -> Result<Value> {
                    let payload: Value = serde_json::from_slice(&request.body)?;
                    let local_id = required_string(&payload, "local_id")?;
                    let base_url = required_string(&payload, "vps_base_url")?;
                    let tcp_port = payload["tcp_port"]
                        .as_u64()
                        .filter(|port| (1..=u16::MAX as u64).contains(port))
                        .context("tcp_port must be between 1 and 65535")?
                        as u16;
                    let ip = local_ip().context("could not determine this machine's local IP")?;
                    let report = kbshare_net::registry::NodeReport {
                        node_id: local_id.to_string(),
                        ips: vec![ip.clone()],
                        tcp_port: Some(tcp_port),
                        udp_port: None,
                        event: "online".into(),
                    };
                    kbshare_net::registry::RegistryClient::new(base_url)
                        .report(&report)
                        .with_context(|| format!("register {local_id}"))?;
                    save_config(config_path, &request.body)?;
                    Ok(serde_json::json!({
                        "ok": true,
                        "node_id": local_id,
                        "ips": [ip],
                        "tcp_port": tcp_port,
                    }))
                })();
                let registered = result.is_ok();
                respond_json_result(&mut stream, result)?;
                if registered {
                    let _ = sender.send(EditorEvent::Saved(config_path.to_path_buf()));
                    return Ok(());
                }
            }
            Ok(request) if request.method == "POST" && request.path == format!("{route}/nodes") => {
                let result = (|| -> Result<Value> {
                    let payload: Value = serde_json::from_slice(&request.body)?;
                    let base_url = required_string(&payload, "base_url")?;
                    let nodes = kbshare_net::registry::RegistryClient::new(base_url)
                        .list()
                        .context("list registered nodes")?;
                    Ok(serde_json::json!({ "ok": true, "nodes": nodes }))
                })();
                respond_json_result(&mut stream, result)?;
            }
            Ok(request) if request.method == "GET" && request.path == format!("{route}/status") => {
                let body = serde_json::json!({
                    "ok": true,
                    "connected": session_active.load(Ordering::Relaxed),
                });
                respond(
                    &mut stream,
                    200,
                    "application/json",
                    serde_json::to_string(&body)?.as_bytes(),
                )?;
            }
            Ok(_) => respond(&mut stream, 404, "text/plain", b"Not found")?,
            Err(error) => {
                let _ = respond(
                    &mut stream,
                    400,
                    "text/plain",
                    format!("Bad request: {error}").as_bytes(),
                );
            }
        }
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{key} is required"))
}

fn local_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

fn hex_fingerprint(value: [u8; 16]) -> String {
    value
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn resolve_editor_path(config_dir: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        config_dir.join(path)
    }
}

fn respond_json_result(stream: &mut TcpStream, result: Result<Value>) -> Result<()> {
    let (status, body) = match result {
        Ok(value) => (200, value),
        Err(error) => (
            400,
            serde_json::json!({ "ok": false, "error": format!("{error:#}") }),
        ),
    };
    respond(
        stream,
        status,
        "application/json",
        serde_json::to_string(&body)?.as_bytes(),
    )
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<Request> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            bail!("connection closed before headers");
        }
        data.extend_from_slice(&buffer[..read]);
        if data.len() > 1_048_576 {
            bail!("request is too large");
        }
        if let Some(index) = data.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };

    let headers = std::str::from_utf8(&data[..header_end]).context("headers are not UTF-8")?;
    let mut lines = headers.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    let method = request_line.next().unwrap_or_default().to_string();
    let path = request_line.next().unwrap_or_default().to_string();
    let content_length = lines
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
        })
        .unwrap_or(0);
    if content_length > 1_048_576 {
        bail!("request body is too large");
    }
    while data.len() < header_end + content_length {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            bail!("connection closed before request body");
        }
        data.extend_from_slice(&buffer[..read]);
    }
    Ok(Request {
        method,
        path,
        body: data[header_end..header_end + content_length].to_vec(),
    })
}

fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self' 'unsafe-inline'\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    Ok(())
}

fn save_config(path: &Path, body: &[u8]) -> Result<()> {
    let value: Value = serde_json::from_slice(body).context("invalid JSON")?;
    if !value.is_object() {
        bail!("configuration root must be a JSON object");
    }
    if value
        .get("local_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        bail!("local_id must not be empty");
    }
    let port = value
        .get("tcp_port")
        .and_then(Value::as_u64)
        .unwrap_or(5005);
    if port == 0 || port > u16::MAX as u64 {
        bail!("tcp_port must be between 1 and 65535");
    }
    validate_layout(&value)?;

    let backup = path.with_extension("json.bak");
    if path.exists() {
        std::fs::copy(path, &backup)
            .with_context(|| format!("create backup {}", backup.display()))?;
    }
    let mut output = serde_json::to_vec_pretty(&value)?;
    output.push(b'\n');
    std::fs::write(path, output).with_context(|| format!("write config {}", path.display()))
}

fn validate_layout(config: &Value) -> Result<()> {
    let Some(devices) = config
        .pointer("/flow_lite/layout/devices")
        .and_then(Value::as_array)
    else {
        return Ok(());
    };
    let mut ids = std::collections::HashSet::new();
    for device in devices {
        let id = device["id"].as_str().unwrap_or_default().trim();
        if id.is_empty() {
            bail!("every Flow layout device needs an ID");
        }
        if !ids.insert(id) {
            bail!("duplicate Flow layout device ID: {id}");
        }
        let host_index = device["host_index"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("device {id} needs an Easy-Switch channel"))?;
        if host_index > 2 {
            bail!("device {id} Easy-Switch channel must be between 0 and 2");
        }
        for coordinate in ["x", "y"] {
            let value = device[coordinate]
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("device {id} needs coordinate {coordinate}"))?;
            if !(0..=1000).contains(&value) {
                bail!("device {id} coordinate {coordinate} must be between 0 and 1000");
            }
        }
    }
    Ok(())
}

fn render_page(config: &Value, app_name: &str, route: &str) -> Result<String> {
    let initial = serde_json::to_string(config)?.replace('<', "\\u003c");
    let local_id = config["local_id"].as_str().unwrap_or("");
    let remote_id = config["remote_id"].as_str().unwrap_or("");
    let role = if remote_id.is_empty() {
        "registered"
    } else if local_id < remote_id {
        "host"
    } else {
        "client"
    };
    Ok(PAGE_V2
        .replace("__INITIAL_CONFIG__", &initial)
        .replace("__APP_NAME__", app_name)
        .replace("__ROLE__", role)
        .replace("__SAVE_ROUTE__", &format!("{route}/save"))
        .replace("__INSPECT_ROUTE__", &format!("{route}/inspect"))
        .replace("__CERTIFICATE_ROUTE__", &format!("{route}/certificate"))
        .replace("__REGISTER_ROUTE__", &format!("{route}/register"))
        .replace("__NODES_ROUTE__", &format!("{route}/nodes"))
        .replace("__STATUS_ROUTE__", &format!("{route}/status")))
}

#[allow(dead_code)]
const PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>__APP_NAME__ configuration</title>
  <style>
    :root { --ink:#17202a; --muted:#66717d; --line:#d8dee5; --paper:#f7f8fa; --white:#fff; --accent:#087e8b; --accent2:#ff5a5f; --ok:#18794e; }
    * { box-sizing:border-box; }
    body { margin:0; color:var(--ink); background-color:var(--paper); background-image:radial-gradient(#ccd3da 0.7px,transparent 0.7px); background-size:18px 18px; font-family:"Aptos","Segoe UI Variable",sans-serif; letter-spacing:0; }
    button,input,textarea { font:inherit; letter-spacing:0; }
    .shell { width:100%; min-width:0; min-height:100vh; display:grid; grid-template-rows:auto 1fr auto; }
    .shell > * { min-width:0; }
    header { background:var(--ink); color:white; padding:22px clamp(20px,5vw,64px); display:flex; align-items:end; justify-content:space-between; gap:20px; }
    .brand { font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif; font-size:28px; font-weight:600; }
    .role { color:#9fe1e8; font-size:13px; text-transform:uppercase; }
    .header-actions { display:flex; align-items:center; gap:14px; }
    .guide-button { border:1px solid #7e929f; border-radius:4px; background:transparent; color:white; padding:9px 13px; cursor:pointer; }
    .guide-button:hover { border-color:#9fe1e8; color:#9fe1e8; }
    main { width:min(980px,calc(100% - 32px)); margin:32px auto; background:var(--white); border:1px solid var(--line); box-shadow:0 18px 50px rgba(23,32,42,.10); }
    nav { display:flex; width:100%; max-width:100%; overflow-x:auto; border-bottom:1px solid var(--line); background:#eef1f4; }
    .tab { border:0; border-right:1px solid var(--line); background:transparent; padding:15px 20px; color:var(--muted); cursor:pointer; white-space:nowrap; }
    .tab[aria-selected="true"] { color:var(--ink); background:white; box-shadow:inset 0 3px var(--accent); }
    .panel { display:none; padding:28px; }
    .panel.active { display:block; animation:appear .18s ease-out; }
    @keyframes appear { from { opacity:0; transform:translateY(4px); } }
    h2 { margin:0 0 22px; font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif; font-size:22px; font-weight:600; }
    .grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:18px 22px; }
    label { display:grid; gap:7px; color:var(--muted); font-size:13px; }
    input,textarea { width:100%; border:1px solid #bcc5ce; border-radius:4px; background:white; color:var(--ink); padding:10px 11px; outline:none; }
    input:focus,textarea:focus { border-color:var(--accent); box-shadow:0 0 0 3px rgba(8,126,139,.14); }
    textarea { min-height:390px; resize:vertical; font-family:"Cascadia Code",Consolas,monospace; font-size:13px; line-height:1.55; }
    .wide { grid-column:1/-1; }
    .chip-input { display:flex; flex-wrap:wrap; gap:6px; align-items:center; border:1px solid #bcc5ce; border-radius:4px; background:white; padding:6px 8px; min-height:42px; cursor:text; }
    .chip-input:focus-within { border-color:var(--accent); box-shadow:0 0 0 3px rgba(8,126,139,.14); }
    .chip { display:inline-flex; align-items:center; gap:4px; background:#e8f0f2; color:var(--ink); border-radius:3px; padding:4px 8px; font-size:13px; }
    .chip-remove { border:none; background:none; cursor:pointer; color:var(--muted); font-size:16px; line-height:1; padding:0; }
    .chip-remove:hover { color:#c0392b; }
    .chip-input input { border:none; box-shadow:none; flex:1; min-width:120px; padding:4px 0; background:transparent; }
    .chip-input input:focus { box-shadow:none; border:none; }
    .toggle { display:flex; align-items:center; gap:10px; min-height:42px; color:var(--ink); }
    .toggle input { appearance:none; width:42px; height:23px; padding:0; border-radius:12px; background:#aab3bc; position:relative; cursor:pointer; }
    .toggle input::after { content:""; position:absolute; width:17px; height:17px; border-radius:50%; background:white; top:2px; left:3px; transition:.16s; }
    .toggle input:checked { background:var(--accent); }
    .toggle input:checked::after { transform:translateX(18px); }
    .layout-head { display:flex; align-items:center; justify-content:space-between; gap:14px; margin:26px 0 12px; }
    .layout-head h3 { margin:0; font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif; font-size:18px; }
    .layout-version { color:var(--muted); font-size:12px; }
    .connection-indicator { color:var(--muted); font-size:12px; margin-left:8px; }
    .connection-indicator.ok { color:#2a7; }
    .add-device:disabled { opacity:.5; cursor:not-allowed; }
    .add-device,.remove-device { border:1px solid #aeb8c2; border-radius:4px; background:white; color:var(--ink); padding:8px 12px; cursor:pointer; }
    .add-device:hover { border-color:var(--accent); color:var(--accent); }
    .remove-device { color:#b4232b; border-color:#e0b5b8; }
    .layout-canvas { position:relative; width:100%; height:330px; overflow:hidden; border:1px solid #bfc8d1; background-color:#f1f4f6; background-image:linear-gradient(#dce2e7 1px,transparent 1px),linear-gradient(90deg,#dce2e7 1px,transparent 1px); background-size:32px 32px; touch-action:none; user-select:none; }
    .device-node { position:absolute; width:164px; min-height:82px; transform:translate(-50%,-50%); border:2px solid #8794a0; border-radius:6px; background:white; box-shadow:0 7px 18px rgba(23,32,42,.12); padding:12px; text-align:left; cursor:grab; color:var(--ink); }
    .device-node:active { cursor:grabbing; }
    .device-node.selected { border-color:var(--accent); box-shadow:0 0 0 3px rgba(8,126,139,.16),0 9px 22px rgba(23,32,42,.14); }
    .device-node.local { border-left:6px solid var(--accent); }
    .device-node.peer { border-left:6px solid #f0a202; }
    .device-name { display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-weight:700; }
    .device-meta { display:flex; align-items:center; justify-content:space-between; gap:8px; margin-top:9px; color:var(--muted); font-size:11px; }
    .device-status { display:inline-flex; align-items:center; gap:5px; }
    .device-status::before { content:""; width:7px; height:7px; border-radius:50%; background:#9aa4ae; }
    .device-node.local .device-status::before { background:var(--accent); }
    .device-node.peer .device-status::before { background:#f0a202; }
    .device-editor { margin-top:16px; padding-top:18px; border-top:1px solid var(--line); }
    .device-editor[hidden] { display:none; }
    .device-editor-actions { display:flex; justify-content:flex-end; align-items:end; }
    .wizard { position:fixed; inset:0; z-index:50; display:grid; place-items:center; padding:22px; background:rgba(12,19,25,.72); }
    .wizard[hidden] { display:none; }
    .wizard-window { width:min(900px,100%); max-height:calc(100vh - 44px); display:grid; grid-template-rows:auto auto minmax(0,1fr) auto; overflow:hidden; background:white; border:1px solid #93a0aa; box-shadow:0 28px 80px rgba(0,0,0,.32); }
    .wizard-header { padding:22px 28px 16px; border-bottom:1px solid var(--line); }
    .wizard-header h1 { margin:0; font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif; font-size:25px; font-weight:600; }
    .wizard-header p { margin:7px 0 0; color:var(--muted); }
    .wizard-progress { display:grid; grid-template-columns:repeat(6,1fr); background:#edf1f3; border-bottom:1px solid var(--line); }
    .wizard-progress span { padding:10px 7px; overflow:hidden; text-align:center; text-overflow:ellipsis; white-space:nowrap; color:var(--muted); font-size:12px; border-right:1px solid var(--line); }
    .wizard-progress span.active { color:var(--ink); background:white; box-shadow:inset 0 3px var(--accent); font-weight:700; }
    .wizard-body { overflow:auto; padding:28px; }
    .wizard-step { display:none; }
    .wizard-step.active { display:block; animation:appear .18s ease-out; }
    .wizard-step h2 { margin-bottom:10px; }
    .wizard-copy { margin:0 0 22px; max-width:680px; color:var(--muted); line-height:1.65; }
    .choice-row { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }
    .choice { padding:16px; border:1px solid var(--line); background:#f7f9fa; }
    .choice strong { display:block; margin-bottom:5px; }
    .detect-row { display:flex; align-items:center; gap:12px; margin-bottom:18px; }
    .detect-button { border:0; border-radius:4px; padding:10px 14px; background:var(--accent); color:white; cursor:pointer; }
    .detect-button:disabled { opacity:.55; cursor:wait; }
    .detect-result { min-height:70px; padding:13px 15px; border:1px solid var(--line); background:#f7f9fa; color:var(--muted); line-height:1.5; }
    .detect-result.ok { border-left:4px solid var(--ok); color:var(--ink); }
    .detect-result.error { border-left:4px solid var(--accent2); }
    .review-list { display:grid; gap:1px; border:1px solid var(--line); background:var(--line); }
    .review-row { display:grid; grid-template-columns:190px 1fr; gap:16px; padding:12px 14px; background:white; }
    .review-row span:first-child { color:var(--muted); }
    .wizard-actions { display:flex; align-items:center; justify-content:flex-end; gap:10px; padding:15px 28px; border-top:1px solid var(--line); background:#f5f7f8; }
    .wizard-actions .secondary { margin-right:auto; }
    .wizard-actions button { border:1px solid #aeb8c2; border-radius:4px; background:white; padding:10px 16px; cursor:pointer; }
    .wizard-actions .primary { border-color:var(--accent); background:var(--accent); color:white; font-weight:600; }
    .wizard-actions button:disabled { opacity:.45; cursor:not-allowed; }
    footer { position:sticky; bottom:0; background:rgba(247,248,250,.96); border-top:1px solid var(--line); padding:15px clamp(20px,5vw,64px); display:flex; align-items:center; justify-content:flex-end; gap:14px; }
    #status { margin-right:auto; color:var(--muted); font-size:13px; }
    #status.error { color:var(--accent2); } #status.ok { color:var(--ok); }
    .save { border:0; border-radius:4px; padding:11px 19px; background:var(--accent); color:white; font-weight:600; cursor:pointer; }
    .save:hover { background:#076b76; } .save:disabled { opacity:.55; cursor:wait; }
    @media (max-width:680px) { header { align-items:start; flex-direction:column; } .header-actions { width:100%; justify-content:space-between; } main { margin:16px auto; } .panel { padding:20px; } .grid,.choice-row { grid-template-columns:1fr; } .layout-head { align-items:start; flex-wrap:wrap; } .layout-canvas { height:390px; } .device-node { width:138px; } .wizard { padding:0; } .wizard-window { width:100%; height:100vh; max-height:none; border:0; } .wizard-header,.wizard-body,.wizard-actions { padding-left:20px; padding-right:20px; } .wizard-progress span { padding-left:3px; padding-right:3px; font-size:11px; } .review-row { grid-template-columns:1fr; gap:4px; } }
  </style>
</head>
<body>
<div class="shell">
    <header><div><div class="brand">kbshare configuration</div><div class="role">__ROLE__ node</div></div><div class="header-actions"><button class="guide-button" id="open_wizard" type="button">Setup guide</button><div>__APP_NAME__</div></div></header>
  <main>
    <nav aria-label="Configuration sections">
      <button class="tab" data-panel="general" aria-selected="true">General</button>
      <button class="tab" data-panel="connection" aria-selected="false">Connection</button>
      <button class="tab" data-panel="flow" aria-selected="false">Flow-lite</button>
      <button class="tab" data-panel="advanced" aria-selected="false">Advanced JSON</button>
    </nav>
    <section class="panel active" id="general"><h2>Identity</h2><div class="grid">
      <label>Local ID<input id="local_id" autocomplete="off"></label>
      <label>Remote ID<input id="remote_id" autocomplete="off"></label>
      <label>TCP port<input id="tcp_port" type="number" min="1" max="65535"></label>
      <label class="toggle"><input id="auto_trust_first_seen" type="checkbox">Trust first connection automatically</label>
      <label>Certificate file<input id="cert_file"></label><label>Private key file<input id="key_file"></label>
      <label class="wide">Trust store<input id="trust_store"></label>
    </div></section>
    <section class="panel" id="connection"><h2>Connection</h2><div class="grid" id="connection-fields"></div></section>
        <section class="panel" id="flow"><h2>Logitech Easy-Switch</h2><div class="grid">
      <label class="toggle wide"><input id="flow_enabled" type="checkbox">Enable Flow-lite edge switching</label>
      <label>Receiver slot<input id="flow_slot" type="number" min="1" max="6" placeholder="Automatic / Bluetooth"></label>
      <label>Edge threshold (px)<input id="flow_edge_px" type="number" min="0" max="100"></label>
        </div>
            <div id="flow_layout_home"><div id="layout_workspace">
                <div class="layout-head"><div><h3>Device layout</h3><span class="layout-version" id="layout_version"></span><span class="connection-indicator" id="connection_indicator">Not connected</span></div><button class="add-device" id="add_device" type="button" disabled>+ Add device</button></div>
                <div class="layout-canvas" id="layout_canvas" aria-label="Draggable device layout"></div>
                <div class="device-editor" id="device_editor" hidden><div class="grid">
                    <label>Display name<input id="device_label"></label>
                    <label>Device ID<input id="device_id"></label>
                    <label>Easy-Switch channel<input id="device_host_index" type="number" min="0" max="2"></label>
                    <div class="device-editor-actions"><button class="remove-device" id="remove_device" type="button">Remove device</button></div>
                </div></div>
            </div></div>
        </section>
    <section class="panel" id="advanced"><h2>Advanced JSON</h2><textarea id="raw" spellcheck="false"></textarea></section>
  </main>
  <footer><span id="status">Ready</span><button class="save" id="save">Save and restart</button></footer>
</div>
<div class="wizard" id="wizard" hidden>
    <div class="wizard-window" role="dialog" aria-modal="true" aria-labelledby="wizard_title">
        <div class="wizard-header"><h1 id="wizard_title">kbshare setup</h1><p id="wizard_subtitle">Configure this machine step by step.</p></div>
        <div class="wizard-progress">
            <span class="active">1 · Name</span><span>2 · Certificate</span><span>3 · Discover</span><span>4 · Mouse</span><span>5 · Layout</span><span>6 · Review</span>
        </div>
        <div class="wizard-body">
            <section class="wizard-step active" data-step="0"><h2>Name this machine</h2><p class="wizard-copy">Choose a stable, unique name. It becomes this machine's identity in certificates, discovery, and layout synchronization.</p><div class="grid">
                <label>This machine<input id="wizard_local_id" autocomplete="off" placeholder="office-desktop"></label>
            </div><div class="choice-row" style="margin-top:20px"><div class="choice"><strong id="wizard_role_name"></strong><span id="wizard_role_help"></span></div><div class="choice"><strong>Before continuing</strong><span>Install the same kbshare version on both machines. Protocol versions must match.</span></div></div></section>
            <section class="wizard-step" data-step="1"><h2>Create this machine's certificate</h2><p class="wizard-copy">The certificate identifies this machine over TLS. Existing certificate and key files are reused, never replaced.</p><div class="grid"><label>Certificate file<input id="wizard_cert_file"></label><label>Private key file<input id="wizard_key_file"></label></div><div class="detect-row" style="margin-top:18px"><button class="detect-button" id="generate_certificate" type="button">Generate or verify certificate</button><span>Stored beside the configuration file</span></div><div class="detect-result" id="certificate_result">Certificate has not been verified yet.</div></section>
            <section class="wizard-step" data-step="2"><h2>Discover the other machine</h2><p class="wizard-copy">Enter the cloud discovery endpoint and the other machine's name. If discovery is unavailable, enter one or more IP addresses manually.</p><div class="grid"><label>Other machine name<input id="wizard_remote_id" autocomplete="off" placeholder="laptop"></label><label>TCP port<input id="wizard_port" type="number" min="1" max="65535"></label><label class="wide">Cloud discovery endpoint<input id="wizard_registry" type="url" placeholder="https://registry.example.com"></label><label class="wide">Manual IP addresses (optional)<div class="chip-input" id="wizard_addresses"><input type="text" placeholder="Type an IP and press Enter" autocomplete="off"></div></label></div><div class="detect-row" style="margin-top:18px"><button class="detect-button" id="discover_machine" type="button">Discover machine</button><span>Manual IP remains available as fallback</span></div><div class="detect-result" id="discover_result">No discovery request has been run yet.</div></section>
            <section class="wizard-step" data-step="3"><h2>Find the Logitech mouse</h2><p class="wizard-copy">Keep the mouse connected to this machine, then scan. If it is currently on another Easy-Switch channel, enter the values manually and continue.</p><div class="detect-row"><button class="detect-button" id="detect_mouse" type="button">Scan this machine</button><span>HID++ read-only scan</span></div><div class="detect-result" id="detect_result">No scan has been run yet.</div><div class="grid" style="margin-top:18px"><label>Receiver slot<input id="wizard_slot" type="number" min="1" max="6" placeholder="Automatic / Bluetooth"></label><label>This machine's channel (1–3)<input id="wizard_local_channel" type="number" min="1" max="3"></label><label>Other machine's channel (1–3)<input id="wizard_remote_channel" type="number" min="1" max="3"></label><label class="toggle"><input id="wizard_flow_enabled" type="checkbox">Enable edge switching</label></div></section>
            <section class="wizard-step" data-step="4"><h2>Arrange the machines</h2><p class="wizard-copy">Drag the other machine to its physical position. Moving it right means crossing this screen's right edge; moving it above means crossing the top edge. Saved offline devices can also be added.</p><div id="wizard_layout_mount"></div></section>
            <section class="wizard-step" data-step="5"><h2>Review and apply</h2><p class="wizard-copy">Saving creates a backup, restarts this application, and synchronizes the newer complete layout after both machines reconnect.</p><div class="review-list" id="wizard_review"></div></section>
        </div>
        <div class="wizard-actions"><button class="secondary" id="wizard_exit" type="button">Advanced editor</button><button id="wizard_back" type="button">Back</button><button class="primary" id="wizard_next" type="button">Next</button></div>
    </div>
</div>
<script>
    const role="__ROLE__", saveRoute="__SAVE_ROUTE__", inspectRoute="__INSPECT_ROUTE__", certificateRoute="__CERTIFICATE_ROUTE__", discoverRoute="__DISCOVER_ROUTE__", statusRoute="__STATUS_ROUTE__"; let cfg=__INITIAL_CONFIG__, selectedDeviceId=null, wizardStep=0, certificateReady=false, certificateFingerprint="", peerConnected=false;
  const $=id=>document.getElementById(id), text=(id,key,def="")=>$(id).value=cfg[key]??def;
  function initChipInput(id, values){ const container=$(id); if(!container||!container.classList.contains("chip-input"))return; const input=container.querySelector("input"); container.querySelectorAll(".chip").forEach(c=>c.remove()); for(const v of values){ addChip(container, v, input); } }
  function addChip(container, value, input){ const chip=document.createElement("span"); chip.className="chip"; chip.textContent=value; const remove=document.createElement("button"); remove.type="button"; remove.className="chip-remove"; remove.textContent="×"; remove.onclick=()=>{ chip.remove(); }; chip.append(remove); container.insertBefore(chip, input); }
  function getChipValues(id){ const container=$(id); if(!container)return []; return [...container.querySelectorAll(".chip")].map(c=>c.textContent.replace("×","").trim()).filter(Boolean); }
  function bindChipInput(id){ const container=$(id); if(!container)return; const input=container.querySelector("input"); if(!input)return; input.addEventListener("keydown", e=>{ if(e.key==="Enter"||e.key===","){ e.preventDefault(); const v=input.value.trim(); if(v&&!getChipValues(id).includes(v)){ addChip(container, v, input); } input.value=""; } else if(e.key==="Backspace"&&!input.value){ const chips=container.querySelectorAll(".chip"); if(chips.length)chips[chips.length-1].remove(); } }); container.addEventListener("click", ()=>input.focus()); }
  function renderConnection(){ $("connection-fields").innerHTML='<label class="wide">Cloud discovery endpoint<input id="vps_base_url" type="url"></label><label class="wide">Manual peer IP addresses<div class="chip-input" id="fallback_remote_ips"><input type="text" placeholder="Type an IP and press Enter" autocomplete="off"></div></label><label>Reconnect interval (seconds)<input id="reconnect_secs" type="number" min="1"></label><label>Heartbeat interval (seconds)<input id="heartbeat_secs" type="number" min="0.05" step="0.05"></label><label>Idle timeout (seconds)<input id="idle_after_secs" type="number" min="0.1" step="0.1"></label>'; initChipInput("fallback_remote_ips", cfg.fallback_remote_ips??[]); bindChipInput("fallback_remote_ips"); }
    function ensureLayout(){ cfg.flow_lite??={}; const f=cfg.flow_lite; if(!f.layout?.devices?.length){ const localChannel=role==="host"?(f.local_host??0):(f.remote_host??2), remoteChannel=role==="host"?(f.remote_host??2):(f.local_host??0), localX=role==="host"?180:820, remoteX=role==="host"?820:180; f.layout={version:0,updated_by:"",devices:[{id:cfg.local_id,label:cfg.local_id,host_index:localChannel,x:localX,y:500},{id:cfg.remote_id,label:cfg.remote_id,host_index:remoteChannel,x:remoteX,y:500}]}; } return f.layout; }
    function render(){ renderConnection(); text("local_id","local_id"); text("remote_id","remote_id"); text("tcp_port","tcp_port",5005); text("cert_file","cert_file"); text("key_file","key_file"); text("trust_store","trust_store"); $("auto_trust_first_seen").checked=!!cfg.auto_trust_first_seen;
    if(role==="host"){ text("vps_base_url","vps_base_url"); text("reconnect_secs","reconnect_secs",3); text("heartbeat_secs","heartbeat_secs",1); text("idle_after_secs","idle_after_secs",3); } else { text("vps_base_url","vps_base_url"); text("reconnect_secs","reconnect_secs",3); text("heartbeat_secs","heartbeat_secs",1); text("idle_after_secs","idle_after_secs",3); }
        const f=cfg.flow_lite??{}; $("flow_enabled").checked=!!f.enabled; $("flow_slot").value=f.slot??""; $("flow_edge_px").value=f.edge_px??2; ensureLayout(); renderLayout(); $("raw").value=JSON.stringify(cfg,null,2); }
    async function pollStatus(){ try{ const r=await fetch(statusRoute), out=await r.json(); if(out.ok){ peerConnected=!!out.connected; updateConnectionIndicator(); } }catch(e){} }
    function updateConnectionIndicator(){ const btn=$("add_device"), indicator=$("connection_indicator"); if(btn){ btn.disabled=!peerConnected; btn.title=peerConnected?"":"Connect to the peer first to add devices"; } if(indicator){ indicator.textContent=peerConnected?`Connected to ${cfg.remote_id||"peer"}`:"Not connected — layout changes apply on next session"; indicator.className=peerConnected?"connection-indicator ok":"connection-indicator"; } }
    function collect(){ const oldLocal=cfg.local_id, oldRemote=cfg.remote_id; cfg.local_id=$("local_id").value.trim(); cfg.remote_id=$("remote_id").value.trim(); cfg.tcp_port=Number($("tcp_port").value); cfg.auto_trust_first_seen=$("auto_trust_first_seen").checked;
    for(const k of ["cert_file","key_file","trust_store"]){ const v=$(k).value.trim(); if(v) cfg[k]=v; else delete cfg[k]; }
    if(role==="host"){ cfg.fallback_remote_ips=getChipValues("fallback_remote_ips"); const u=$("vps_base_url").value.trim(); if(u) cfg.vps_base_url=u; else delete cfg.vps_base_url; cfg.reconnect_secs=Number($("reconnect_secs").value); cfg.heartbeat_secs=Number($("heartbeat_secs").value); cfg.idle_after_secs=Number($("idle_after_secs").value); } else { cfg.fallback_remote_ips=getChipValues("fallback_remote_ips"); const u=$("vps_base_url").value.trim(); if(u) cfg.vps_base_url=u; else delete cfg.vps_base_url; cfg.reconnect_secs=Number($("reconnect_secs").value); cfg.heartbeat_secs=Number($("heartbeat_secs").value); cfg.idle_after_secs=Number($("idle_after_secs").value); }
        const f=cfg.flow_lite??{}; f.enabled=$("flow_enabled").checked; f.edge_px=Number($("flow_edge_px").value); const slot=$("flow_slot").value; if(slot!=="") f.slot=Number(slot); else delete f.slot; const layout=ensureLayout(); for(const device of layout.devices){ if(device.id===oldLocal){device.id=cfg.local_id;if(device.label===oldLocal)device.label=cfg.local_id;} else if(device.id===oldRemote){device.id=cfg.remote_id;if(device.label===oldRemote)device.label=cfg.remote_id;} } if(selectedDeviceId===oldLocal)selectedDeviceId=cfg.local_id; if(selectedDeviceId===oldRemote)selectedDeviceId=cfg.remote_id; layout.version=Math.max(Date.now(),Number(layout.version||0)+1); layout.updated_by=cfg.local_id; cfg.flow_lite=f; $("raw").value=JSON.stringify(cfg,null,2); return cfg; }
    function clamp(v,min,max){ return Math.max(min,Math.min(max,v)); }
    function layoutMetrics(canvas){ const marginX=Math.min(innerWidth<=680?73:86,canvas.clientWidth/2),marginY=48; return {marginX,marginY,width:Math.max(1,canvas.clientWidth-marginX*2),height:Math.max(1,canvas.clientHeight-marginY*2)}; }
    function placeNode(node,device,canvas){ const m=layoutMetrics(canvas); node.style.left=`${m.marginX+clamp(device.x,0,1000)/1000*m.width}px`; node.style.top=`${m.marginY+clamp(device.y,0,1000)/1000*m.height}px`; }
    function deviceStatus(device){ if(device.id===cfg.local_id) return ["local","This device"]; if(device.id===cfg.remote_id) return ["peer","Paired device"]; return ["offline","Offline / saved"]; }
    function renderLayout(){ const layout=ensureLayout(), canvas=$("layout_canvas"); canvas.innerHTML=""; $("layout_version").textContent=layout.version?`Version ${layout.version} · ${layout.updated_by||"unknown"}`:"Not synchronized yet"; for(const device of layout.devices){ const [statusClass,statusLabel]=deviceStatus(device), node=document.createElement("button"); node.type="button"; node.className=`device-node ${statusClass}${device.id===selectedDeviceId?" selected":""}`; const name=document.createElement("span"); name.className="device-name"; name.textContent=device.label||device.id; const meta=document.createElement("span"); meta.className="device-meta"; const status=document.createElement("span"); status.className="device-status"; status.textContent=statusLabel; const channel=document.createElement("span"); channel.textContent=`CH ${Number(device.host_index)+1}`; meta.append(status,channel); node.append(name,meta); node.onclick=()=>selectDevice(device.id); node.onkeydown=e=>{ const delta={ArrowLeft:[-25,0],ArrowRight:[25,0],ArrowUp:[0,-25],ArrowDown:[0,25]}[e.key]; if(delta){e.preventDefault();device.x=clamp(device.x+delta[0],0,1000);device.y=clamp(device.y+delta[1],0,1000);selectedDeviceId=device.id;renderLayout();renderDeviceEditor();} }; node.onpointerdown=e=>{ selectedDeviceId=device.id; node.setPointerCapture(e.pointerId); const rect=canvas.getBoundingClientRect(),m=layoutMetrics(canvas); const move=event=>{device.x=Math.round(clamp((event.clientX-rect.left-m.marginX)/m.width*1000,0,1000));device.y=Math.round(clamp((event.clientY-rect.top-m.marginY)/m.height*1000,0,1000));placeNode(node,device,canvas);}; node.onpointermove=move; node.onpointerup=()=>{node.onpointermove=null;node.onpointerup=null;renderLayout();renderDeviceEditor();}; }; canvas.appendChild(node); placeNode(node,device,canvas); } renderDeviceEditor(); }
    function selectDevice(id){ selectedDeviceId=id; renderLayout(); }
    function selectedDevice(){ return ensureLayout().devices.find(device=>device.id===selectedDeviceId); }
    function renderDeviceEditor(){ const device=selectedDevice(), editor=$("device_editor"); editor.hidden=!device; if(!device)return; $("device_label").value=device.label??""; $("device_id").value=device.id; $("device_host_index").value=device.host_index; $("remove_device").disabled=device.id===cfg.local_id; }
    $("add_device").onclick=()=>{ const layout=ensureLayout(), id=`saved-${Date.now().toString(36)}`; layout.devices.push({id,label:"Saved device",host_index:1,x:500,y:180+layout.devices.length*90%650}); selectedDeviceId=id; renderLayout(); };
    $("device_label").oninput=e=>{ const device=selectedDevice(); if(device){device.label=e.target.value;renderLayout();} };
    $("device_id").onchange=e=>{ const device=selectedDevice(), next=e.target.value.trim(); if(!device||!next||ensureLayout().devices.some(item=>item!==device&&item.id===next)){setStatus("Device ID must be unique",true);renderDeviceEditor();return;} const wasSelected=device.id; device.id=next; if(selectedDeviceId===wasSelected)selectedDeviceId=next; renderLayout(); };
    $("device_host_index").oninput=e=>{ const device=selectedDevice(); if(device){device.host_index=clamp(Number(e.target.value),0,2);renderLayout();} };
    $("remove_device").onclick=()=>{ const device=selectedDevice(); if(!device||device.id===cfg.local_id)return; const layout=ensureLayout(); layout.devices=layout.devices.filter(item=>item!==device); selectedDeviceId=null; renderLayout(); };
    addEventListener("resize",()=>{ if($("flow").classList.contains("active"))renderLayout(); });
  document.querySelectorAll(".tab").forEach(tab=>tab.onclick=()=>{ if(tab.dataset.panel==="advanced") collect(); if(document.querySelector(".tab[aria-selected=true]").dataset.panel==="advanced" && tab.dataset.panel!=="advanced"){ try{cfg=JSON.parse($("raw").value);render();}catch(e){setStatus(e.message,true);return;} } document.querySelectorAll(".tab").forEach(t=>t.setAttribute("aria-selected",t===tab)); document.querySelectorAll(".panel").forEach(p=>p.classList.toggle("active",p.id===tab.dataset.panel)); });
  function setStatus(message,error=false,ok=false){ const s=$("status"); s.textContent=message; s.className=error?"error":ok?"ok":""; }
    async function saveConfig(data,button){ if(!data.local_id||!data.remote_id) throw new Error("This machine and other machine names are required"); button.disabled=true; setStatus("Saving…"); try{ const r=await fetch(saveRoute,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)}); const out=await r.json(); if(!r.ok) throw new Error(out.error||"Save failed"); setStatus("Saved. Restarting application…",false,true); }catch(e){setStatus(e.message,true);button.disabled=false;throw e;} }
    $("save").onclick=async()=>{ try{ const data=document.querySelector(".tab[aria-selected=true]").dataset.panel==="advanced"?JSON.parse($("raw").value):collect(); await saveConfig(data,$("save")); }catch(e){setStatus(e.message,true);} };
    function openWizard(){
        try{ if(document.querySelector(".tab[aria-selected=true]").dataset.panel==="advanced") cfg=JSON.parse($("raw").value); else collect(); }catch(e){ setStatus(e.message,true); return; }
        wizardStep=0; $("wizard_local_id").value=cfg.local_id??""; $("wizard_remote_id").value=cfg.remote_id??"";
        $("wizard_role_name").textContent="Both machines are equal peers";
        $("wizard_role_help").textContent="Each machine can capture its keyboard, inject the other's keystrokes, and switch the mouse across screen edges. No host or client role is needed.";
        $("wizard_cert_file").value=cfg.cert_file??`certs/${role}_cert.pem`; $("wizard_key_file").value=cfg.key_file??`certs/${role}_key.pem`; $("certificate_result").className="detect-result"; $("certificate_result").textContent="Certificate has not been verified yet."; certificateReady=false;certificateFingerprint="";
        initChipInput("wizard_addresses", cfg.fallback_remote_ips??[]); bindChipInput("wizard_addresses"); $("wizard_registry").value=cfg.vps_base_url??""; $("wizard_port").value=cfg.tcp_port??5005; $("discover_result").className="detect-result"; $("discover_result").textContent="No discovery request has been run yet.";
        const f=cfg.flow_lite??{}; $("wizard_slot").value=f.slot??""; $("wizard_flow_enabled").checked=!!f.enabled;
        $("wizard_local_channel").value=(role==="host"?(f.local_host??0):(f.remote_host??2))+1; $("wizard_remote_channel").value=(role==="host"?(f.remote_host??2):(f.local_host??0))+1;
        $("detect_result").className="detect-result"; $("detect_result").textContent="No scan has been run yet."; $("wizard").hidden=false; showWizardStep();
    }
    function closeWizard(){ $("flow_layout_home").append($("layout_workspace")); $("wizard").hidden=true; render(); }
    function wizardIdentity(){
        const local=$("wizard_local_id").value.trim(); if(!local) throw new Error("Name this machine before continuing");
        const oldLocal=cfg.local_id; if(oldLocal!==local)certificateReady=false; cfg.local_id=local; for(const device of ensureLayout().devices){ if(device.id===oldLocal){device.id=local;if(device.label===oldLocal)device.label=local;} }
    }
    function wizardCertificate(){ if(!certificateReady)throw new Error("Generate or verify the certificate before continuing"); cfg.cert_file=$("wizard_cert_file").value.trim();cfg.key_file=$("wizard_key_file").value.trim(); }
    function wizardNetwork(){ const remote=$("wizard_remote_id").value.trim(),port=Number($("wizard_port").value),oldRemote=cfg.remote_id; if(!remote)throw new Error("Enter the other machine's name");if(remote===cfg.local_id)throw new Error("The two machine names must be different");if(!Number.isInteger(port)||port<1||port>65535)throw new Error("Enter a valid TCP port (1–65535)"); const addresses=getChipValues("wizard_addresses"),url=$("wizard_registry").value.trim();if(!addresses.length&&!url)throw new Error("Enter a cloud endpoint or at least one manual IP address");cfg.remote_id=remote;cfg.tcp_port=port;cfg.fallback_remote_ips=addresses;if(url)cfg.vps_base_url=url;else delete cfg.vps_base_url;for(const device of ensureLayout().devices){if(device.id===oldRemote){device.id=remote;if(device.label===oldRemote)device.label=remote;}} }
    function wizardMouse(){ const local=Number($("wizard_local_channel").value),remote=Number($("wizard_remote_channel").value); if(![1,2,3].includes(local)||![1,2,3].includes(remote)) throw new Error("Choose channels 1–3 for both machines"); if(local===remote) throw new Error("The two machines need different Easy-Switch channels"); const f=cfg.flow_lite??={}; f.enabled=$("wizard_flow_enabled").checked; const slot=$("wizard_slot").value; if(slot)f.slot=Number(slot);else delete f.slot; if(role==="host"){f.local_host=local-1;f.remote_host=remote-1;}else{f.remote_host=local-1;f.local_host=remote-1;} const layout=ensureLayout(); const localDevice=layout.devices.find(d=>d.id===cfg.local_id), remoteDevice=layout.devices.find(d=>d.id===cfg.remote_id); if(localDevice)localDevice.host_index=local-1;if(remoteDevice)remoteDevice.host_index=remote-1; }
    function updateReview(){ const f=cfg.flow_lite??{}, local=role==="host"?f.local_host:f.remote_host,remote=role==="host"?f.remote_host:f.local_host, network=[cfg.vps_base_url,...(cfg.fallback_remote_ips??[])].filter(Boolean).join(", "); $("wizard_review").innerHTML=[["This machine",cfg.local_id],["Certificate",certificateFingerprint?`${cfg.cert_file} · ${certificateFingerprint.slice(0,16)}…`:cfg.cert_file],["Other machine",`${cfg.remote_id} · port ${cfg.tcp_port}`],["Discovery / IP",network||"Not configured"],["Mouse",f.enabled?`Enabled · channel ${Number(local)+1} ↔ ${Number(remote)+1}${f.slot?` · receiver slot ${f.slot}`:" · Bluetooth/direct"}`:"Edge switching disabled"],["Layout",`${ensureLayout().devices.length} devices · newer complete layout wins`]].map(([a,b])=>`<div class="review-row"><span>${a}</span><strong>${b}</strong></div>`).join(""); }
    function validateWizardStep(){ if(wizardStep===0)wizardIdentity();if(wizardStep===1)wizardCertificate();if(wizardStep===2)wizardNetwork();if(wizardStep===3)wizardMouse();if(wizardStep===4){ const layout=ensureLayout();layout.version=Math.max(Date.now(),Number(layout.version||0)+1);layout.updated_by=cfg.local_id; } }
    function showWizardStep(){ document.querySelectorAll(".wizard-step").forEach((node,index)=>node.classList.toggle("active",index===wizardStep)); document.querySelectorAll(".wizard-progress span").forEach((node,index)=>node.classList.toggle("active",index===wizardStep)); $("wizard_back").disabled=wizardStep===0; $("wizard_next").textContent=wizardStep===5?"Apply and restart":"Next"; if(wizardStep===4){$("wizard_layout_mount").append($("layout_workspace"));renderLayout();}else if($("layout_workspace").parentElement===$("wizard_layout_mount"))$("flow_layout_home").append($("layout_workspace")); if(wizardStep===5)updateReview(); }
    $("wizard_next").onclick=async()=>{ try{ if(wizardStep===5){ await saveConfig(cfg,$("wizard_next")); return; } validateWizardStep(); wizardStep++;$("wizard_subtitle").textContent="Configure this machine step by step.";showWizardStep(); }catch(e){setStatus(e.message,true);$("wizard_subtitle").textContent=e.message;} };
    $("wizard_back").onclick=()=>{ if(wizardStep>0){wizardStep--;showWizardStep();} };
    $("wizard_exit").onclick=closeWizard; $("open_wizard").onclick=openWizard;
    $("generate_certificate").onclick=async()=>{const button=$("generate_certificate"),result=$("certificate_result"),local=$("wizard_local_id").value.trim(),cert=$("wizard_cert_file").value.trim(),key=$("wizard_key_file").value.trim();if(!local){result.className="detect-result error";result.textContent="Name this machine first.";return;}if(!cert||!key){result.className="detect-result error";result.textContent="Certificate and key file paths are required.";return;}button.disabled=true;result.className="detect-result";result.textContent="Generating or checking the certificate…";try{const response=await fetch(certificateRoute,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({local_id:local,cert_file:cert,key_file:key})}),out=await response.json();if(!response.ok||!out.ok)throw new Error(out.error||"Certificate operation failed");certificateReady=true;certificateFingerprint=out.fingerprint;cfg.cert_file=cert;cfg.key_file=key;result.className="detect-result ok";result.textContent=`${out.created?"Created":"Verified existing"} certificate. SHA-256: ${out.fingerprint}`;}catch(e){certificateReady=false;result.className="detect-result error";result.textContent=`Could not prepare certificate: ${e.message}`;}finally{button.disabled=false;}};
    $("discover_machine").onclick=async()=>{const button=$("discover_machine"),result=$("discover_result"),base=$("wizard_registry").value.trim(),remote=$("wizard_remote_id").value.trim();if(!base||!remote){result.className="detect-result error";result.textContent="Enter both the cloud endpoint and other machine name, or use a manual IP.";return;}button.disabled=true;result.className="detect-result";result.textContent=`Looking for ${remote}…`;try{const response=await fetch(discoverRoute,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({base_url:base,remote_id:remote})}),out=await response.json();if(!response.ok||!out.ok)throw new Error(out.error||"Discovery failed");const container=$("wizard_addresses"),input=container.querySelector("input");for(const ip of out.ips){ if(!getChipValues("wizard_addresses").includes(ip)) addChip(container, ip, input); }if(out.tcp_port)$("wizard_port").value=out.tcp_port;result.className="detect-result ok";result.textContent=`Found ${out.node_id}: ${out.ips.join(", ")||"no IP addresses reported"}${out.tcp_port?` on port ${out.tcp_port}`:""}.`;}catch(e){result.className="detect-result error";result.textContent=`Could not discover the machine: ${e.message}. Enter its IP address manually below.`;}finally{button.disabled=false;}};
    $("detect_mouse").onclick=async()=>{ const button=$("detect_mouse"),result=$("detect_result");button.disabled=true;result.className="detect-result";result.textContent="Scanning Logitech HID++ devices…";try{const response=await fetch(inspectRoute),out=await response.json();if(!out.ok)throw new Error(out.error||"Scan failed");const mouse=out.devices.find(d=>d.is_mouse)||out.devices[0];if(!mouse)throw new Error("No compatible Logitech device was found on this machine");if(mouse.slot!=null)$("wizard_slot").value=mouse.slot;if(mouse.current_host!=null)$("wizard_local_channel").value=Number(mouse.current_host)+1;result.className="detect-result ok";result.textContent=`Found ${mouse.name} (${mouse.connection}). Current channel: ${mouse.current_host==null?"unknown":Number(mouse.current_host)+1}; available channels: ${mouse.host_count??"unknown"}.`; }catch(e){result.className="detect-result error";result.textContent=`Could not detect a mouse: ${e.message}. You can enter the channel manually.`;}finally{button.disabled=false;} };
  render();
    pollStatus(); setInterval(pollStatus, 3000);
    if(!cfg.local_id||!cfg.remote_id||!cfg.flow_lite?.layout?.devices?.length) openWizard();
</script>
</body></html>"#;

const PAGE_V2: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>__APP_NAME__ configuration</title>
  <style>
    :root { --ink:#17202a; --muted:#66717d; --line:#d8dee5; --paper:#f5f7f8; --accent:#087e8b; --danger:#c43d43; --ok:#18794e; }
    * { box-sizing:border-box; }
    body { margin:0; color:var(--ink); background:var(--paper); font-family:"Aptos","Segoe UI Variable",sans-serif; }
    button,input,textarea { font:inherit; }
    header { padding:22px clamp(20px,5vw,64px); display:flex; align-items:end; justify-content:space-between; gap:20px; color:white; background:var(--ink); }
    .brand { font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif; font-size:28px; font-weight:600; }
    .role { margin-top:4px; color:#9fe1e8; font-size:12px; text-transform:uppercase; }
    .guide { padding:9px 13px; color:white; background:transparent; border:1px solid #7e929f; border-radius:4px; cursor:pointer; }
    main { width:min(940px,calc(100% - 32px)); margin:30px auto; background:white; border:1px solid var(--line); box-shadow:0 18px 50px rgba(23,32,42,.09); }
    nav { display:flex; overflow:auto; background:#eef1f4; border-bottom:1px solid var(--line); }
    .tab { padding:15px 20px; color:var(--muted); background:transparent; border:0; border-right:1px solid var(--line); cursor:pointer; }
    .tab[aria-selected=true] { color:var(--ink); background:white; box-shadow:inset 0 3px var(--accent); }
    .panel { display:none; padding:28px; }
    .panel.active { display:block; }
    h2 { margin:0 0 8px; font-size:22px; }
    h3 { margin:26px 0 12px; font-size:16px; }
    .copy { margin:0 0 22px; color:var(--muted); line-height:1.55; }
    .grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:18px 22px; }
    label { display:grid; gap:7px; color:var(--muted); font-size:13px; }
    input,textarea { width:100%; padding:10px 11px; color:var(--ink); background:white; border:1px solid #bcc5ce; border-radius:4px; outline:none; }
    input:focus,textarea:focus { border-color:var(--accent); box-shadow:0 0 0 3px rgba(8,126,139,.14); }
    input[readonly] { color:#4d5965; background:#f3f5f6; }
    textarea { min-height:380px; resize:vertical; font-family:"Cascadia Code",Consolas,monospace; font-size:13px; line-height:1.5; }
    .wide { grid-column:1/-1; }
    .status-card { display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:22px; padding:14px 16px; background:#f5fafb; border:1px solid #c9e0e3; }
    .status-card strong { display:block; }
    .status-card span { color:var(--muted); font-size:13px; }
    .row { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
    button.primary,.save { padding:10px 16px; color:white; background:var(--accent); border:1px solid var(--accent); border-radius:4px; cursor:pointer; font-weight:600; }
    button.secondary { padding:9px 13px; color:var(--ink); background:white; border:1px solid #aeb8c2; border-radius:4px; cursor:pointer; }
    button:disabled { opacity:.45; cursor:not-allowed; }
    .node-list { display:grid; gap:8px; margin-top:12px; }
    .node { display:grid; grid-template-columns:1fr auto; align-items:center; gap:12px; padding:13px 14px; text-align:left; color:var(--ink); background:white; border:1px solid var(--line); border-radius:4px; cursor:pointer; }
    .node:hover,.node.selected { border-color:var(--accent); background:#f3fbfc; }
    .node small { display:block; margin-top:3px; color:var(--muted); }
    .badge { padding:4px 8px; color:var(--accent); background:#e1f3f5; border-radius:999px; font-size:12px; }
    .empty { padding:18px; color:var(--muted); text-align:center; border:1px dashed #bfc8d0; }
    .readonly-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:1px; background:var(--line); border:1px solid var(--line); }
    .datum { min-width:0; padding:14px; background:white; }
    .datum span { display:block; margin-bottom:5px; color:var(--muted); font-size:12px; }
    .datum strong { overflow-wrap:anywhere; }
    .device-list { margin:10px 0 0; padding-left:20px; color:#42505d; }
    footer { display:flex; align-items:center; gap:14px; padding:18px 28px; background:#f0f2f4; border-top:1px solid var(--line); }
    #status { margin-right:auto; color:var(--muted); font-size:13px; }
    #status.error { color:var(--danger); } #status.ok { color:var(--ok); }
    .wizard { position:fixed; inset:0; z-index:10; display:grid; place-items:center; padding:22px; background:rgba(12,19,25,.72); }
    .wizard[hidden] { display:none; }
    .wizard-window { width:min(760px,100%); max-height:calc(100vh - 44px); display:grid; grid-template-rows:auto auto minmax(0,1fr) auto; overflow:hidden; background:white; box-shadow:0 28px 80px rgba(0,0,0,.32); }
    .wizard-header { padding:22px 28px 16px; border-bottom:1px solid var(--line); }
    .wizard-header h1 { margin:0; font-size:25px; }
    .wizard-header p { margin:7px 0 0; color:var(--muted); }
    .progress { display:grid; grid-template-columns:repeat(3,1fr); background:#edf1f3; border-bottom:1px solid var(--line); }
    .progress span { padding:10px; text-align:center; color:var(--muted); font-size:12px; border-right:1px solid var(--line); }
    .progress span.active { color:var(--ink); background:white; box-shadow:inset 0 3px var(--accent); font-weight:700; }
    .wizard-body { overflow:auto; padding:28px; }
    .step { display:none; } .step.active { display:block; }
    .result { margin-top:16px; padding:12px 14px; color:var(--muted); background:#f3f5f6; border-left:3px solid #aeb8c2; line-height:1.45; }
    .result.ok { color:var(--ok); border-left-color:var(--ok); } .result.error { color:var(--danger); border-left-color:var(--danger); }
    .wizard-actions { display:flex; align-items:center; justify-content:flex-end; gap:10px; padding:15px 28px; background:#f5f7f8; border-top:1px solid var(--line); }
    .wizard-actions .secondary { margin-right:auto; }
    @media(max-width:680px) { .grid,.readonly-grid { grid-template-columns:1fr; } .wide { grid-column:auto; } main { width:100%; margin:0; border:0; } .panel { padding:22px 18px; } footer { padding:16px 18px; } .wizard { padding:0; } .wizard-window { width:100%; height:100vh; max-height:none; } }
  </style>
</head>
<body>
  <header><div><div class="brand">kbshare configuration</div><div class="role">__ROLE__ node</div></div><button class="guide" id="open_wizard" type="button">Registration guide</button></header>
  <main>
    <nav><button class="tab" data-panel="connection" aria-selected="true">Connection</button><button class="tab" data-panel="flow" aria-selected="false">Flow-Lite</button><button class="tab" data-panel="advanced" aria-selected="false">Advanced JSON</button></nav>
    <section class="panel active" id="connection">
      <h2>Connect another machine</h2><p class="copy">This node is registered independently. Choose a peer from the registry; mouse channels and receiver slots are detected only after the secure session connects.</p>
      <div class="status-card"><div><strong id="connection_title">Registered · waiting for connection</strong><span id="connection_detail"></span></div><span class="badge" id="connection_badge">Waiting</span></div>
      <div class="grid">
        <label>This machine<input id="local_id" readonly></label>
        <label>Selected peer<input id="remote_id" readonly placeholder="No peer selected"></label>
        <label class="wide">Registry endpoint<input id="registry_url" type="url" placeholder="https://registry.example.com"></label>
        <label>Listening TCP port<input id="tcp_port" type="number" min="1" max="65535"></label>
      </div>
      <h3>Available machines</h3>
      <div class="row"><button class="secondary" id="refresh_nodes" type="button">Refresh list</button><span class="copy" id="nodes_hint" style="margin:0">Load nodes registered at this endpoint.</span></div>
      <div class="node-list" id="node_list"></div>
    </section>
    <section class="panel" id="flow">
      <h2>Flow-Lite automatic configuration</h2><p class="copy">These values are read-only. They are populated after both machines report the same 16-byte mouse fingerprint.</p>
      <div class="readonly-grid">
        <div class="datum"><span>Status</span><strong id="flow_enabled">Not detected</strong></div>
        <div class="datum"><span>Receiver slot</span><strong id="flow_slot">—</strong></div>
        <div class="datum"><span>Local host channel</span><strong id="flow_local_host">—</strong></div>
        <div class="datum"><span>Remote host channel</span><strong id="flow_remote_host">—</strong></div>
        <div class="datum wide"><span>Feature 0x0003 fingerprint</span><strong id="flow_fingerprint">—</strong></div>
      </div>
      <h3>Automatically discovered layout</h3><ul class="device-list" id="layout_devices"></ul>
      <div class="row" style="margin-top:20px"><button class="secondary" id="inspect_mouse" type="button">Inspect this machine now</button><span id="inspect_result" class="copy" style="margin:0"></span></div>
    </section>
    <section class="panel" id="advanced"><h2>Advanced configuration</h2><p class="copy">Unknown fields are preserved. Flow-Lite identity fields should normally be left to automatic detection.</p><textarea id="raw" spellcheck="false"></textarea></section>
    <footer><span id="status">Ready</span><button class="save" id="save" type="button">Save and restart</button></footer>
  </main>

  <div class="wizard" id="wizard" hidden>
    <div class="wizard-window" role="dialog" aria-modal="true">
      <div class="wizard-header"><h1>Register this machine</h1><p id="wizard_subtitle">Registration does not look up or configure another machine.</p></div>
      <div class="progress"><span class="active">1 · Name</span><span>2 · Certificate</span><span>3 · Register</span></div>
      <div class="wizard-body">
        <section class="step active"><h2>Name this machine</h2><p class="copy">Choose a stable, unique identifier for this computer.</p><label>This machine<input id="wizard_local_id" autocomplete="off" placeholder="office-desktop"></label></section>
        <section class="step"><h2>Create this machine's certificate</h2><p class="copy">Existing certificate and key files are verified and reused.</p><div class="grid"><label>Certificate file<input id="wizard_cert_file"></label><label>Private key file<input id="wizard_key_file"></label></div><div class="row" style="margin-top:18px"><button class="secondary" id="generate_certificate" type="button">Generate or verify certificate</button></div><div class="result" id="certificate_result">Certificate has not been verified yet.</div></section>
        <section class="step"><h2>Report this machine to the registry</h2><p class="copy">Only this machine's ID, local IP address and listening TCP port are sent. No peer is queried.</p><div class="grid"><label class="wide">Registry endpoint<input id="wizard_registry" type="url" placeholder="https://registry.example.com"></label><label>Listening TCP port<input id="wizard_port" type="number" min="1" max="65535"></label></div><div class="result" id="register_result">Ready to register this machine.</div></section>
      </div>
      <div class="wizard-actions"><button class="secondary" id="wizard_exit" type="button">Close guide</button><button class="secondary" id="wizard_back" type="button">Back</button><button class="primary" id="wizard_next" type="button">Next</button></div>
    </div>
  </div>

  <script>
    const saveRoute="__SAVE_ROUTE__", inspectRoute="__INSPECT_ROUTE__", certificateRoute="__CERTIFICATE_ROUTE__", registerRoute="__REGISTER_ROUTE__", nodesRoute="__NODES_ROUTE__", statusRoute="__STATUS_ROUTE__";
    let cfg=__INITIAL_CONFIG__, wizardStep=0, certificateReady=false, connected=false;
    const $=id=>document.getElementById(id);
    cfg.remote_id??=""; cfg.flow_lite??={}; cfg.tcp_port??=5005;
    function setStatus(message,error=false,ok=false){$("status").textContent=message;$("status").className=error?"error":ok?"ok":"";}
    function fingerprint(value){return Array.isArray(value)&&value.length?value.map(byte=>Number(byte).toString(16).padStart(2,"0")).join(""):"—";}
    function render(){
      $("local_id").value=cfg.local_id??"";$("remote_id").value=cfg.remote_id??"";$("registry_url").value=cfg.vps_base_url??"";$("tcp_port").value=cfg.tcp_port??5005;
      const f=cfg.flow_lite??{};$("flow_enabled").textContent=f.enabled?"Enabled · fingerprint matched":"Not detected";$("flow_slot").textContent=f.slot??"Bluetooth / direct / unknown";$("flow_local_host").textContent=f.enabled?`Channel ${Number(f.local_host)+1}`:"—";$("flow_remote_host").textContent=f.enabled?`Channel ${Number(f.remote_host)+1}`:"—";$("flow_fingerprint").textContent=fingerprint(f.fingerprint);
      const devices=f.layout?.devices??[];$("layout_devices").innerHTML=devices.length?devices.map(d=>`<li>${escapeHtml(d.label||d.id)} — channel ${Number(d.host_index)+1}</li>`).join(""):"<li>No matched machines yet.</li>";
      $("raw").value=JSON.stringify(cfg,null,2);renderConnection();
    }
    function escapeHtml(value){const node=document.createElement("span");node.textContent=value;return node.innerHTML;}
    function collect(){cfg.local_id=$("local_id").value.trim();cfg.remote_id=$("remote_id").value.trim();cfg.tcp_port=Number($("tcp_port").value);const registry=$("registry_url").value.trim();if(registry)cfg.vps_base_url=registry;else delete cfg.vps_base_url;$("raw").value=JSON.stringify(cfg,null,2);return cfg;}
    function renderConnection(){const peer=cfg.remote_id?.trim();$("connection_title").textContent=connected?`Connected to ${peer||"peer"}`:peer?`Configured for ${peer}`:"Registered · waiting for connection";$("connection_detail").textContent=peer?(connected?"Secure session active":"The app will resolve this peer through the registry."):"Choose a registered machine below.";$("connection_badge").textContent=connected?"Connected":peer?"Configured":"Waiting";}
    async function pollStatus(){try{const r=await fetch(statusRoute),out=await r.json();if(out.ok){connected=!!out.connected;renderConnection();}}catch(_){}}
    async function save(data,button){if(!data.local_id)throw new Error("This machine must be registered first");button.disabled=true;setStatus("Saving…");try{const r=await fetch(saveRoute,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)}),out=await r.json();if(!r.ok||!out.ok)throw new Error(out.error||"Save failed");setStatus("Saved. Restarting application…",false,true);}catch(error){button.disabled=false;setStatus(error.message,true);throw error;}}
    async function loadNodes(){const button=$("refresh_nodes"),list=$("node_list"),base=$("registry_url").value.trim();if(!base){setStatus("Enter the registry endpoint first",true);return;}button.disabled=true;list.innerHTML='<div class="empty">Loading registered nodes…</div>';try{const r=await fetch(nodesRoute,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({base_url:base})}),out=await r.json();if(!r.ok||!out.ok)throw new Error(out.error||"Could not load nodes");const nodes=out.nodes.filter(node=>node.node_id!==cfg.local_id);list.innerHTML=nodes.length?"":'<div class="empty">No other registered machines found.</div>';for(const node of nodes){const item=document.createElement("button");item.type="button";item.className=`node${node.node_id===cfg.remote_id?" selected":""}`;const details=(node.ips??[]).join(", ")||"No IP reported";item.innerHTML=`<span><strong>${escapeHtml(node.node_id)}</strong><small>${escapeHtml(details)} · port ${node.tcp_port??cfg.tcp_port}</small></span><span class="badge">${node.node_id===cfg.remote_id?"Selected":"Select"}</span>`;item.onclick=()=>{cfg.remote_id=node.node_id;cfg.vps_base_url=base;$("remote_id").value=node.node_id;renderConnection();loadNodes();};list.append(item);}setStatus(`Loaded ${nodes.length} available machine${nodes.length===1?"":"s"}`,false,true);}catch(error){list.innerHTML=`<div class="empty">${escapeHtml(error.message)}</div>`;setStatus(error.message,true);}finally{button.disabled=false;}}
    document.querySelectorAll(".tab").forEach(tab=>tab.onclick=()=>{if(document.querySelector(".tab[aria-selected=true]").dataset.panel==="advanced"){try{cfg=JSON.parse($("raw").value);}catch(error){setStatus(error.message,true);return;}render();}document.querySelectorAll(".tab").forEach(item=>item.setAttribute("aria-selected",item===tab));document.querySelectorAll(".panel").forEach(panel=>panel.classList.toggle("active",panel.id===tab.dataset.panel));});
    $("refresh_nodes").onclick=()=>{collect();loadNodes();};
    $("save").onclick=async()=>{try{const data=document.querySelector(".tab[aria-selected=true]").dataset.panel==="advanced"?JSON.parse($("raw").value):collect();await save(data,$("save"));}catch(error){setStatus(error.message,true);}};
    $("inspect_mouse").onclick=async()=>{const button=$("inspect_mouse");button.disabled=true;$("inspect_result").textContent="Inspecting…";try{const r=await fetch(inspectRoute),out=await r.json();if(!out.ok)throw new Error(out.error||"Inspection failed");const mouse=out.devices.find(device=>device.is_mouse);if(!mouse)throw new Error("No compatible Logitech mouse found");$("inspect_result").textContent=`${mouse.name}; channel ${Number(mouse.current_host)+1}; slot ${mouse.connection==="receiver"?mouse.slot:"direct"}; fingerprint ${mouse.fingerprint??"unavailable"}`;}catch(error){$("inspect_result").textContent=error.message;}finally{button.disabled=false;}};
    function openWizard(){wizardStep=0;certificateReady=false;$("wizard_local_id").value=cfg.local_id??"";$("wizard_cert_file").value=cfg.cert_file??"certs/kbshare_cert.pem";$("wizard_key_file").value=cfg.key_file??"certs/kbshare_key.pem";$("wizard_registry").value=cfg.vps_base_url??"";$("wizard_port").value=cfg.tcp_port??5005;$("certificate_result").className="result";$("certificate_result").textContent="Certificate has not been verified yet.";$("register_result").className="result";$("register_result").textContent="Ready to register this machine.";$("wizard").hidden=false;showStep();}
    function showStep(){document.querySelectorAll(".step").forEach((step,index)=>step.classList.toggle("active",index===wizardStep));document.querySelectorAll(".progress span").forEach((step,index)=>step.classList.toggle("active",index===wizardStep));$("wizard_back").disabled=wizardStep===0;$("wizard_next").textContent=wizardStep===2?"Register this machine":"Next";}
    function validateName(){const local=$("wizard_local_id").value.trim();if(!local)throw new Error("Name this machine before continuing");if(local!==cfg.local_id)certificateReady=false;cfg.local_id=local;}
    $("wizard_next").onclick=async()=>{try{if(wizardStep===0)validateName();else if(wizardStep===1){if(!certificateReady)throw new Error("Generate or verify the certificate before continuing");}else{await registerMachine();return;}wizardStep++;$("wizard_subtitle").textContent="Registration does not look up or configure another machine.";showStep();}catch(error){$("wizard_subtitle").textContent=error.message;}};
    $("wizard_back").onclick=()=>{if(wizardStep>0){wizardStep--;showStep();}};
    $("wizard_exit").onclick=()=>$("wizard").hidden=true;$("open_wizard").onclick=openWizard;
    $("generate_certificate").onclick=async()=>{const button=$("generate_certificate"),result=$("certificate_result");try{validateName();const cert=$("wizard_cert_file").value.trim(),key=$("wizard_key_file").value.trim();if(!cert||!key)throw new Error("Certificate and key paths are required");button.disabled=true;result.className="result";result.textContent="Generating or verifying…";const r=await fetch(certificateRoute,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({local_id:cfg.local_id,cert_file:cert,key_file:key})}),out=await r.json();if(!r.ok||!out.ok)throw new Error(out.error||"Certificate operation failed");certificateReady=true;cfg.cert_file=cert;cfg.key_file=key;result.className="result ok";result.textContent=`${out.created?"Created":"Verified"} certificate. SHA-256: ${out.fingerprint}`;}catch(error){certificateReady=false;result.className="result error";result.textContent=error.message;}finally{button.disabled=false;}};
    async function registerMachine(){const button=$("wizard_next"),result=$("register_result"),base=$("wizard_registry").value.trim(),port=Number($("wizard_port").value);validateName();if(!certificateReady)throw new Error("Verify the certificate first");if(!base)throw new Error("Enter the registry endpoint");if(!Number.isInteger(port)||port<1||port>65535)throw new Error("Enter a valid TCP port");cfg.remote_id="";cfg.vps_base_url=base;cfg.tcp_port=port;cfg.flow_lite={...(cfg.flow_lite??{}),enabled:false,slot:null,fingerprint:null,layout:{version:0,updated_by:"",devices:[]}};button.disabled=true;result.className="result";result.textContent="Reporting this machine…";try{const r=await fetch(registerRoute,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(cfg)}),out=await r.json();if(!r.ok||!out.ok)throw new Error(out.error||"Registration failed");result.className="result ok";result.textContent=`Registered ${out.node_id} at ${out.ips.join(", ")}. Restarting in waiting mode…`;setStatus("Registration complete. Restarting…",false,true);}catch(error){button.disabled=false;result.className="result error";result.textContent=error.message;throw error;}}
    render();pollStatus();setInterval(pollStatus,3000);if(!cfg.local_id)openWizard();else if(cfg.vps_base_url)loadNodes();
  </script>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_contains_initial_config_and_role() {
        let page = render_page(
            &serde_json::json!({"local_id":"alpha","remote_id":"beta"}),
            "kbshare",
            "/token",
        )
        .unwrap();
        assert!(page.contains("alpha"));
        assert!(page.contains("host node"));
        assert!(page.contains("/token/save"));
        assert!(page.contains("/token/inspect"));
        assert!(page.contains("/token/certificate"));
        assert!(page.contains("/token/register"));
        assert!(page.contains("/token/nodes"));
        assert!(page.contains("/token/status"));
        assert!(page.contains("Register this machine"));
    }

    #[test]
    fn save_validates_and_creates_backup() {
        let unique = format!(
            "kbshare-editor-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::write(&path, br#"{"local_id":"old","remote_id":"peer"}"#).unwrap();

        save_config(
            &path,
            br#"{"local_id":"new","remote_id":"peer","custom_field":42}"#,
        )
        .unwrap();

        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["local_id"], "new");
        assert_eq!(saved["custom_field"], 42);
        let backup = path.with_extension("json.bak");
        assert!(backup.exists());

        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(backup).unwrap();
    }

    #[test]
    fn save_rejects_missing_identity() {
        let path = std::env::temp_dir().join("kbshare-editor-invalid.json");
        let error = save_config(&path, br#"{"local_id":"","remote_id":"peer"}"#).unwrap_err();
        assert!(error.to_string().contains("local_id"));
        assert!(!path.exists());
    }

    #[test]
    fn save_allows_registered_node_without_remote_id() {
        let path = std::env::temp_dir().join(format!(
            "kbshare-editor-registered-{}.json",
            std::process::id()
        ));
        save_config(
            &path,
            br#"{"local_id":"desktop","remote_id":"","tcp_port":5005}"#,
        )
        .unwrap();
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["local_id"], "desktop");
        assert_eq!(saved["remote_id"], "");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn save_allows_stale_layout_until_automatic_detection_rebuilds_it() {
        let path = std::env::temp_dir().join(format!(
            "kbshare-editor-stale-layout-{}.json",
            std::process::id()
        ));
        save_config(
            &path,
            br#"{
                "local_id":"new-desktop",
                "remote_id":"",
                "flow_lite":{"layout":{"devices":[
                    {"id":"old-desktop","host_index":0,"x":180,"y":500}
                ]}}
            }"#,
        )
        .unwrap();
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["local_id"], "new-desktop");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn layout_rejects_duplicate_device_ids() {
        let config = serde_json::json!({
            "local_id": "host",
            "remote_id": "client",
            "flow_lite": { "layout": { "devices": [
                { "id": "host", "host_index": 0, "x": 100, "y": 500 },
                { "id": "host", "host_index": 2, "x": 900, "y": 500 }
            ]}}
        });
        assert!(validate_layout(&config)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
    }
}
