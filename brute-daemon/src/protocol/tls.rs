/////////
// TLS //
/////////
// Generates a self-signed certificate at runtime and returns a TlsAcceptor
// that all TLS honeypot servers share.

use std::sync::Arc;

use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub fn create_tls_acceptor() -> anyhow::Result<TlsAcceptor> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["honeypot".to_string(), "localhost".to_string()])?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());

    let config = ServerConfig::builder_with_provider(
        tokio_rustls::rustls::crypto::ring::default_provider().into()
    )
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
