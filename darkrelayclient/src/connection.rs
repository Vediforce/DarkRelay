use std::{
    io,
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

pub struct Connection {
    outgoing: mpsc::UnboundedSender<ClientMessage>,
    incoming: mpsc::UnboundedReceiver<ServerMessage>,
}

impl Connection {
    pub async fn connect(addr: &str, timeout: Duration) -> io::Result<Self> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection timeout"))??;

        let (mut reader, mut writer) = stream.into_split();

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
