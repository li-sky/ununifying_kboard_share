//! TOFU trust store.
//!
//! A plain JSON map of `peer_id -> fingerprint_hex`. The first time we
//! see a peer, the policy decides whether to accept it. On subsequent
//! connects we refuse if the fingerprint changed.

use anyhow::{Context, Result};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug)]
pub struct TrustStore {
    path: PathBuf,
    inner: Mutex<BTreeMap<String, String>>,
}

/// Outcome of trust evaluation. The runtime decides what to actually do
/// about each.
#[derive(Debug, PartialEq, Eq)]
pub enum TrustDecision {
    /// Peer fingerprint matches what we stored. Safe to proceed.
    KnownAndMatches,
    /// Peer is not in our store. Caller must either prompt or auto-trust.
    Unknown,
    /// DANGER: stored fingerprint differs from the one just observed.
    Mismatch { expected: String, actual: String },
}

#[derive(Debug, Clone, Copy)]
pub enum AutoTrustPolicy {
    /// Reject any unknown peer. Test-friendly default.
    RequireKnown,
    /// Accept unknown peers on first sight (TOFU).
    TrustOnFirstUse,
}

impl TrustStore {
    pub fn load(path: PathBuf) -> Result<Self> {
        let inner = if path.exists() {
            let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            serde_json::from_slice::<BTreeMap<String, String>>(&bytes).unwrap_or_default()
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path,
            inner: Mutex::new(inner),
        })
    }

    pub fn evaluate(&self, peer_id: &str, observed_fp: &str) -> TrustDecision {
        let inner = self.inner.lock();
        match inner.get(peer_id) {
            None => TrustDecision::Unknown,
            Some(stored) if stored.eq_ignore_ascii_case(observed_fp) => {
                TrustDecision::KnownAndMatches
            }
            Some(stored) => TrustDecision::Mismatch {
                expected: stored.clone(),
                actual: observed_fp.to_string(),
            },
        }
    }

    /// Persist a freshly-trusted fingerprint. Returns error if `peer_id`
    /// already maps to a different fingerprint — callers must explicitly
    /// rotate via `rotate`.
    pub fn learn(&self, peer_id: &str, fp: &str) -> Result<()> {
        let mut inner = self.inner.lock();
        if let Some(existing) = inner.get(peer_id) {
            if !existing.eq_ignore_ascii_case(fp) {
                anyhow::bail!(
                    "refusing to overwrite fingerprint for {} (use rotate)",
                    peer_id
                );
            }
            return Ok(());
        }
        inner.insert(peer_id.to_string(), fp.to_string());
        self.flush(&inner)?;
        Ok(())
    }

    /// Explicit rotation. Caller has verified the new fingerprint out-of-band.
    pub fn rotate(&self, peer_id: &str, fp: &str) -> Result<()> {
        let mut inner = self.inner.lock();
        inner.insert(peer_id.to_string(), fp.to_string());
        self.flush(&inner)?;
        Ok(())
    }

    fn flush(&self, inner: &BTreeMap<String, String>) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let bytes = serde_json::to_vec_pretty(inner)?;
        fs::write(&self.path, bytes).with_context(|| format!("write {}", self.path.display()))?;
        Ok(())
    }

    pub fn snapshot(&self) -> BTreeMap<String, String> {
        self.inner.lock().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn tmp() -> PathBuf {
        let p = temp_dir().join(format!(
            "kbshare-trust-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn unknown_then_learn_then_match() {
        let path = tmp();
        let s = TrustStore::load(path.clone()).unwrap();
        assert_eq!(s.evaluate("peer", "ABCD"), TrustDecision::Unknown);
        s.learn("peer", "ABCD").unwrap();
        assert_eq!(s.evaluate("peer", "ABCD"), TrustDecision::KnownAndMatches);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn mismatch_is_reported() {
        let path = tmp();
        let s = TrustStore::load(path.clone()).unwrap();
        s.learn("peer", "AA").unwrap();
        match s.evaluate("peer", "BB") {
            TrustDecision::Mismatch { expected, actual } => {
                assert_eq!(expected, "AA");
                assert_eq!(actual, "BB");
            }
            other => panic!("expected mismatch, got {other:?}"),
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn learn_refuses_to_overwrite() {
        let path = tmp();
        let s = TrustStore::load(path.clone()).unwrap();
        s.learn("peer", "AA").unwrap();
        assert!(s.learn("peer", "BB").is_err());
        assert!(s.rotate("peer", "BB").is_ok());
        assert_eq!(s.evaluate("peer", "BB"), TrustDecision::KnownAndMatches);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn case_insensitive_compare() {
        let path = tmp();
        let s = TrustStore::load(path.clone()).unwrap();
        s.learn("peer", "abcd").unwrap();
        assert_eq!(s.evaluate("peer", "ABCD"), TrustDecision::KnownAndMatches);
        let _ = fs::remove_file(&path);
    }
}
