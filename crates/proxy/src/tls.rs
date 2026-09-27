use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::SessionError;

pub const CERT_ENV: &str = "SHAHRAH_TLS_CERT";
pub const KEY_ENV: &str = "SHAHRAH_TLS_KEY";
pub const METRICS_CERT_ENV: &str = "SHAHRAH_METRICS_TLS_CERT";
pub const METRICS_KEY_ENV: &str = "SHAHRAH_METRICS_TLS_KEY";
pub const BACKEND_TLS_ENV: &str = "SHAHRAH_BACKEND_TLS";
pub const BACKEND_TLS_INSECURE_ENV: &str = "SHAHRAH_BACKEND_TLS_INSECURE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendTls {
    Disable,
    Require,
}

impl BackendTls {
    pub fn from_env() -> Result<Self, String> {
        match std::env::var(BACKEND_TLS_ENV).as_deref() {
            Ok("require") => Ok(Self::Require),
            Ok("disable" | "") | Err(_) => Ok(Self::Disable),
            Ok(other) => Err(format!(
                "{BACKEND_TLS_ENV} is set to \"{other}\", which is neither \"require\" nor \
                 \"disable\". shahrah will not start rather than quietly speak to the shards \
                 in the clear because of a typo"
            )),
        }
    }
}

pub fn install_crypto_provider() {
    let provider = rustls::crypto::ring::default_provider();
    if provider.install_default().is_err() {
        tracing::debug!("a rustls crypto provider was already installed");
    }
}

pub fn load_metrics_acceptor() -> Result<Option<TlsAcceptor>, SessionError> {
    let (Ok(cert_path), Ok(key_path)) = (
        std::env::var(METRICS_CERT_ENV),
        std::env::var(METRICS_KEY_ENV),
    ) else {
        return Ok(None);
    };
    acceptor_from(&cert_path, &key_path).map(Some)
}

pub fn load_acceptor() -> Result<Option<TlsAcceptor>, SessionError> {
    let (Ok(cert_path), Ok(key_path)) = (std::env::var(CERT_ENV), std::env::var(KEY_ENV)) else {
        return Ok(None);
    };
    acceptor_from(&cert_path, &key_path).map(Some)
}

fn acceptor_from(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, SessionError> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|cause| SessionError::Tls(cause.to_string()))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub fn load_connector() -> Result<TlsConnector, SessionError> {
    let unverified =
        crate::settings::flag(BACKEND_TLS_INSECURE_ENV).map_err(SessionError::Setting)?;
    let config = if unverified {
        let mut config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(insecure::AcceptAnyServer));
        config
    } else {
        let mut roots = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            roots.add(cert).ok();
        }
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

pub fn server_name(address: &str) -> Result<ServerName<'static>, SessionError> {
    let host = crate::address::host_of(address).to_owned();
    ServerName::try_from(host).map_err(|cause| SessionError::Tls(cause.to_string()))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, SessionError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut certs = Vec::new();
    for entry in rustls_pemfile::certs(&mut reader) {
        certs.push(entry?);
    }
    if certs.is_empty() {
        return Err(SessionError::Tls(format!("{path} holds no certificate")));
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, SessionError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    match rustls_pemfile::private_key(&mut reader)? {
        Some(key) => Ok(key),
        None => Err(SessionError::Tls(format!("{path} holds no private key"))),
    }
}

mod insecure {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct AcceptAnyServer;

    impl ServerCertVerifier for AcceptAnyServer {
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
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
