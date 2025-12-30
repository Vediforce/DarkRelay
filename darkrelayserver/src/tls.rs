use std::{fs, io, path::Path, sync::Arc};
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use rustls::{ServerConfig, server::AllowAnyAuthenticatedClient, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tracing::{info, warn};

pub fn load_or_generate_tls_config(cert_path: Option<&str>, key_path: Option<&str>) -> io::Result<Arc<ServerConfig>> {
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => {
            info!("loading TLS certificate from {}", cert);
            load_tls_config(cert, key)
        }
        _ => {
            info!("generating self-signed TLS certificate");
            generate_self_signed_config()
        }
    }
}

fn load_tls_config(cert_path: &str, key_path: &str) -> io::Result<Arc<ServerConfig>> {
    let cert_file = fs::File::open(cert_path)?;
    let key_file = fs::File::open(key_path)?;
    
    let mut cert_reader = io::BufReader::new(cert_file);
    let mut key_reader = io::BufReader::new(key_file);
    
    let cert_chain: Vec<rustls::Certificate> = certs(&mut cert_reader)?
        .into_iter()
        .map(rustls::Certificate)
        .collect();
    
    let mut keys: Vec<rustls::PrivateKey> = pkcs8_private_keys(&mut key_reader)?
        .into_iter()
        .map(rustls::PrivateKey)
        .collect();
    
    if keys.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no private keys found"));
    }
    
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys.remove(0))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    
    Ok(Arc::new(config))
}

fn generate_self_signed_config() -> io::Result<Arc<ServerConfig>> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, "darkrelay-server");
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".to_string()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
    ];
    
    let cert = Certificate::from_params(params)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    let cert_der = cert.serialize_der()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let key_der = cert.serialize_private_key_der();
    
    let cert_chain = vec![rustls::Certificate(cert_der)];
    let private_key = rustls::PrivateKey(key_der);
    
    warn!("using self-signed certificate - clients will need to accept this");
    
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    
    Ok(Arc::new(config))
}
