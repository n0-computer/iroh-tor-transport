//! Tests for the Tor packet stream protocol.

use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use iroh::SecretKey;
use iroh_tor::{TorPacket, TorPacketService, write_tor_packet};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

#[tokio::test]
async fn test_packet_service_roundtrip() -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<iroh_tor::TorPacket>(1);
    let service = TorPacketService::new(tx);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await?;
        service.handle_stream(stream).await
    });

    let mut client = TcpStream::connect(addr).await?;
    let from = SecretKey::generate(&mut rand::rng()).public();
    let packet = TorPacket {
        from,
        data: Bytes::from_static(b"hello-tor-packet"),
        segment_size: Some(512),
    };
    write_tor_packet(&mut client, &packet).await?;

    // The service should deliver the packet quickly.
    let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .context("Timed out waiting for packet")?
        .context("Packet channel closed")?;

    assert_eq!(received.from, packet.from);
    assert_eq!(received.data, packet.data);
    assert_eq!(received.segment_size, packet.segment_size);

    drop(client);

    server.await??;
    Ok(())
}
