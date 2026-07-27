//! Certificate management.
//!
//! First launch generates a self-signed cert via `rcgen` and persists it to
//! disk. Subsequent launches reuse it. The SHA-256 digest of the cert's DER
//! is our TOFU identity.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub struct CertBundle {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub cert_der: Vec<u8>,
}

pub fn load_or_create_cert(
    cert_path: &Path,
    key_path: &Path,
    common_name: &str,
) -> Result<CertBundle> {
    if cert_path.exists() && key_path.exists() {
        let cert_pem = fs::read(cert_path).context("read cert pem")?;
        let key_pem = fs::read(key_path).context("read key pem")?;
        let cert_der = pem_to_der(&cert_pem).context("decode existing cert pem")?;
        return Ok(CertBundle {
            cert_pem,
            key_pem,
            cert_der,
        });
    }

    if let Some(dir) = cert_path.parent() {
        fs::create_dir_all(dir).ok();
    }
    if let Some(dir) = key_path.parent() {
        fs::create_dir_all(dir).ok();
    }

    let params = rcgen::CertificateParams::new(vec![common_name.to_string()])
        .context("build cert params")?;
    let key_pair = rcgen::KeyPair::generate().context("generate keypair")?;
    let cert = params.self_signed(&key_pair).context("self-sign cert")?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    fs::write(cert_path, &cert_pem).context("write cert pem")?;
    fs::write(key_path, &key_pem).context("write key pem")?;

    let cert_der = cert.der().to_vec();
    Ok(CertBundle {
        cert_pem: cert_pem.into_bytes(),
        key_pem: key_pem.into_bytes(),
        cert_der,
    })
}

pub fn fingerprint_hex(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    hex::encode(digest)
}

fn pem_to_der(pem_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(pem_bytes);
    for item in rustls_pemfile::read_all(&mut cursor) {
        let item = item.context("parse pem item")?;
        if let rustls_pemfile::Item::X509Certificate(der) = item {
            return Ok(der.to_vec());
        }
    }
    anyhow::bail!("no certificate found in pem");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    #[test]
    fn generate_and_reload_cert() {
        let dir = temp_dir().join(format!("kbshare-cert-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");

        let first = load_or_create_cert(&cert, &key, "test").unwrap();
        let second = load_or_create_cert(&cert, &key, "test").unwrap();
        assert_eq!(
            fingerprint_hex(&first.cert_der),
            fingerprint_hex(&second.cert_der),
            "second call must reuse the first cert"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_is_stable() {
        let der = b"abcdef";
        assert_eq!(fingerprint_hex(der), fingerprint_hex(der));
    }
}
