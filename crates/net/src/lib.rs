//! Network layer: TLS over TCP with SHA-256 TOFU fingerprint verification,
//! plus a tiny HTTP client for the IP registry.

pub mod cert;
pub mod registry;
pub mod session;
pub mod tls;
pub mod trust;

pub use cert::{fingerprint_hex, load_or_create_cert, CertBundle};
pub use session::{run_client_session, run_server_session, SessionEnd};
pub use trust::TrustStore;
