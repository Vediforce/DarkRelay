use std::{
    io,
    sync::Arc,
    time::Duration,
};

use bincode;
use darkrelayprotocol::protocol::{ClientMessage, ServerMessage};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};
use tokio_rustls::TlsConnector;
use rustls::{ClientConfig, RootCertStore, client::ServerCertVerifier, Certificate, Error};
use tracing::warn;

struct AcceptAnyCertVerifier;

impl ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, Error> {
        warn!("accepting unverified TLS certificate (self-signed)");
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

pub struct Connection {
    outgoing: mpsc::UnboundedSender<ClientMessage>,
    incoming: mpsc::UnboundedReceiver<ServerMessage>,
}

impl Connection {
    pub async fn connect(addr: &str, timeout: Duration) -> io::Result<Self> {
        let tcp_stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection timeout"))??;

        // Create TLS config that accepts self-signed certificates
        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        
        config.dangerous()
            .set_certificate_verifier(Arc::new(AcceptAnyCertVerifier));
        
        let connector = TlsConnector::from(Arc::new(config));
        let domain = rustls::ServerName::try_from("localhost")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        
        let tls_stream = connector.connect(domain, tcp_stream).await?;
        let (mut reader, mut writer) = tokio::io::split(tls_stream);

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ClientMessage>();
        let (in_tx, in_rx) = mpsc::unbounded_channel::<ServerMessage>();

        tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                if write_frame(&mut writer, &msg).await.is_err() {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            loop {
                match read_frame::<ServerMessage, _>(&mut reader).await {
                    Ok(msg) => {
                        if in_tx.send(msg).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            outgoing: out_tx,
            incoming: in_rx,
        })
    }

    pub fn send(&self, msg: ClientMessage) -> io::Result<()> {
        self.outgoing
            .send(msg)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))
    }

    pub async fn recv(&mut self) -> io::Result<Option<ServerMessage>> {
        Ok(self.incoming.recv().await)
    }

    pub fn try_recv(&mut self) -> Option<ServerMessage> {
        self.incoming.try_recv().ok()
    }
}

async fn read_frame<T: DeserializeOwned, R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<T> {
    let len = reader.read_u32().await?;
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;

    bincode::deserialize::<T>(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

async fn write_frame<T: Serialize, W: AsyncWrite + Unpin>(writer: &mut W, msg: &T) -> io::Result<()> {
    let data = bincode::serialize(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len: u32 = data
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;

    writer.write_u32(len).await?;
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}
