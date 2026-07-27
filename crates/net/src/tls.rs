//! rustls glue.
//!
//! We use TLS purely as a transport encryption layer. Identity verification
//! is done at the application layer via SHA-256 fingerprints (TOFU), exactly
//! like the Python version. The rustls verifiers therefore accept any
//! certificate; we extract the peer DER right after the handshake.

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme,
};
use std::sync::Arc;

use crate::cert::CertBundle;

/// Install the rustls crypto provider exactly once per process.
pub fn ensure_crypto_installed() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // ignore error if already installed
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        all_schemes()
    }
}

impl ClientCertVerifier for AcceptAny {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        all_schemes()
    }
}

fn all_schemes() -> Vec<SignatureScheme> {
    vec![
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ED25519,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
    ]
}

fn load_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = std::io::Cursor::new(pem);
    for item in rustls_pemfile::read_all(&mut cursor) {
        let item = item.context("parse key pem")?;
        match item {
            rustls_pemfile::Item::Pkcs8Key(k) => return Ok(PrivateKeyDer::Pkcs8(k)),
            rustls_pemfile::Item::Pkcs1Key(k) => return Ok(PrivateKeyDer::Pkcs1(k)),
            rustls_pemfile::Item::Sec1Key(k) => return Ok(PrivateKeyDer::Sec1(k)),
            _ => continue,
        }
    }
    Err(anyhow!("no private key in pem"))
}

fn load_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = std::io::Cursor::new(pem);
    let mut out = Vec::new();
    for item in rustls_pemfile::read_all(&mut cursor) {
        let item = item.context("parse cert pem")?;
        if let rustls_pemfile::Item::X509Certificate(der) = item {
            out.push(der);
        }
    }
    if out.is_empty() {
        return Err(anyhow!("no certs in pem"));
    }
    Ok(out)
}

pub fn build_client_config(bundle: &CertBundle) -> Result<Arc<ClientConfig>> {
    ensure_crypto_installed();
    let certs = load_cert_chain(&bundle.cert_pem)?;
    let key = load_private_key(&bundle.key_pem)?;
    let cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_client_auth_cert(certs, key)
        .context("attach client cert")?;
    Ok(Arc::new(cfg))
}

pub fn build_server_config(bundle: &CertBundle) -> Result<Arc<ServerConfig>> {
    ensure_crypto_installed();
    let certs = load_cert_chain(&bundle.cert_pem)?;
    let key = load_private_key(&bundle.key_pem)?;
    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAny))
        .with_single_cert(certs, key)
        .context("attach server cert")?;
    Ok(Arc::new(cfg))
}
