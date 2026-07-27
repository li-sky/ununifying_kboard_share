//! Minimal registry HTTP client + embedded server.
//!
//! Wire-compatible with the Python reference: POST `/report`, GET `/node/<id>`,
//! all JSON bodies. The embedded server is used by the `registry` binary.

use anyhow::{Context, Result};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeReport {
    pub node_id: String,
    pub ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_port: Option<u16>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub event: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEntry {
    pub node_id: String,
    pub ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_port: Option<u16>,
    #[serde(default)]
    pub event: String,
    pub updated_at: f64,
}

pub struct RegistryClient {
    base_url: String,
    agent: ureq::Agent,
}

impl RegistryClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(5))
                .build(),
        }
    }

    pub fn report(&self, payload: &NodeReport) -> Result<()> {
        let url = format!("{}/report", self.base_url);
        self.agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_json(serde_json::to_value(payload)?)
            .context("POST /report")?;
        Ok(())
    }

    pub fn lookup(&self, node_id: &str) -> Result<NodeEntry> {
        let url = format!("{}/node/{}", self.base_url, node_id);
        let entry: NodeEntry = self.agent.get(&url).call()?.into_json()?;
        Ok(entry)
    }
}

// ------------------------- Embedded server -------------------------

#[derive(Default)]
pub struct RegistryStore {
    inner: Mutex<HashMap<String, NodeEntry>>,
}

impl RegistryStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn upsert(&self, report: NodeReport) -> NodeEntry {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let entry = NodeEntry {
            node_id: report.node_id.clone(),
            ips: report.ips,
            tcp_port: report.tcp_port,
            udp_port: report.udp_port,
            event: report.event,
            updated_at: now,
        };
        self.inner
            .lock()
            .insert(entry.node_id.clone(), entry.clone());
        entry
    }
    pub fn lookup(&self, node_id: &str) -> Option<NodeEntry> {
        self.inner.lock().get(node_id).cloned()
    }
}

/// Run a blocking HTTP server on `bind`. Plain HTTP only; deploy behind
/// nginx or similar for TLS.
pub fn serve_http(store: Arc<RegistryStore>, bind: &str) -> Result<()> {
    let server = tiny_http::Server::http(bind).map_err(|e| anyhow::anyhow!("bind {bind}: {e}"))?;
    tracing::info!(address = %bind, "registry listening");
    for mut req in server.incoming_requests() {
        let method = req.method().clone();
        let url = req.url().to_string();
        let resp = match (method.as_str(), url.as_str()) {
            ("POST", "/report") => handle_report(&mut req, &store),
            ("GET", path) if path.starts_with("/node/") => {
                handle_lookup(path.trim_start_matches("/node/"), &store)
            }
            ("GET", "/health") => (200, r#"{"status":"healthy"}"#.to_string()),
            _ => (404, "{}".into()),
        };
        let (status, body) = resp;
        let response = tiny_http::Response::from_string(body)
            .with_status_code(status)
            .with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap(),
            );
        let _ = req.respond(response);
    }
    Ok(())
}

fn handle_report(req: &mut tiny_http::Request, store: &Arc<RegistryStore>) -> (u16, String) {
    let mut body = String::new();
    if req.as_reader().read_to_string(&mut body).is_err() {
        return (400, r#"{"error":"read"}"#.into());
    }
    let report: NodeReport = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return (400, r#"{"error":"json"}"#.into()),
    };
    store.upsert(report);
    (200, r#"{"status":"ok"}"#.into())
}

fn handle_lookup(node_id: &str, store: &Arc<RegistryStore>) -> (u16, String) {
    match store.lookup(node_id) {
        Some(entry) => (200, serde_json::to_string(&entry).unwrap()),
        None => (404, r#"{"error":"not found"}"#.into()),
    }
}
