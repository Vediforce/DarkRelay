use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{StaticSecret, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::client::TlsStream;
use tokio::net::TcpStream;
use bincode;

use darkrelayprotocol::federation::{
    ServerFederationMessage, ServerId, ServerIntro, ServerAck,
    FEDERATION_PROTOCOL_VERSION, FederationStatus,
};

pub async fn perform_client_handshake(
    stream: &mut TlsStream<TcpStream>,
    our_server_id: ServerId,
    our_server_name: String,
) -> io::Result<[u8; 32]> {
    let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let client_public = PublicKey::from(&client_secret);
    
    let intro = ServerIntro {
        server_id: our_server_id,
        server_name: our_server_name,
        server_version: "1.0.0".to_string(),
        public_key: client_public.as_bytes().to_vec(),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        protocol_version: FEDERATION_PROTOCOL_VERSION,
    };

    // Send ServerIntro
    let intro_bytes = bincode::serialize(&ServerFederationMessage::ServerIntro(intro))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    write_frame(stream, &intro_bytes).await?;

    // Wait for ServerAck
    let msg = read_frame(stream).await?;
    let ack = match msg {
        ServerFederationMessage::ServerAck(ack) => ack,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "expected ServerAck")),
    };

    if ack.public_key.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid public key length"));
    }

    let mut pub_key_bytes = [0u8; 32];
    pub_key_bytes.copy_from_slice(&ack.public_key);
    let server_public = PublicKey::from(pub_key_bytes);
    
    let shared_secret_scalar = client_secret.diffie_hellman(&server_public);
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(shared_secret_scalar.as_bytes());
    
    Ok(secret_bytes)
}

pub async fn perform_server_handshake(
    stream: &mut TlsStream<TcpStream>,
    our_server_id: ServerId,
    our_server_name: String,
    their_intro: ServerIntro,
) -> io::Result<[u8; 32]> {
    if their_intro.public_key.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid public key length"));
    }

    let mut their_pub_key_bytes = [0u8; 32];
    their_pub_key_bytes.copy_from_slice(&their_intro.public_key);
    let their_public = PublicKey::from(their_pub_key_bytes);

    let our_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let our_public = PublicKey::from(&our_secret);

    // Create ServerAck
    let ack = ServerAck {
        server_id: our_server_id,
        status: FederationStatus::Connected,
        server_name: our_server_name,
        server_version: "1.0.0".to_string(),
        public_key: our_public.as_bytes().to_vec(),
        protocol_version: FEDERATION_PROTOCOL_VERSION,
    };

    let ack_msg = ServerFederationMessage::ServerAck(ack);
    let ack_bytes = bincode::serialize(&ack_msg)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    write_frame(stream, &ack_bytes).await?;

    let shared_secret_scalar = our_secret.diffie_hellman(&their_public);
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(shared_secret_scalar.as_bytes());

    Ok(shared_secret)
}

async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await
}

async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<ServerFederationMessage> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;

    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;

    bincode::deserialize(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
