//! Internal tests for packet protocol and sender.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use iroh::SecretKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::{
    TorPacket, TorPacketSender, TorPacketService, TorStreamIo, iroh_to_tor_secret_key,
    onion_address, read_tor_packet, write_tor_packet,
};

#[tokio::test]
async fn test_packet_service_roundtrip() -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<TorPacket>(1);
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
        .map_err(|_| anyhow!("Timed out waiting for packet"))?
        .ok_or_else(|| anyhow!("Packet channel closed"))?;

    assert_eq!(received.from, packet.from);
    assert_eq!(received.data, packet.data);
    assert_eq!(received.segment_size, packet.segment_size);

    drop(client);

    server.await??;
    Ok(())
}

#[tokio::test]
async fn test_sender_reuses_connection() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await?;
        let mut packets = Vec::new();
        if let Some(packet) = read_tor_packet(&mut stream).await? {
            packets.push(packet);
        }
        if let Some(packet) = read_tor_packet(&mut stream).await? {
            packets.push(packet);
        }
        // Ensure no second connection is opened.
        let accept_timeout =
            tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(accept_timeout.is_err());
        Ok::<_, anyhow::Error>(packets)
    });

    let connects = Arc::new(AtomicUsize::new(0));
    let io = Arc::new(TorStreamIo::new(
        || async { Err(anyhow!("accept not used in this test")) },
        {
            let connects = connects.clone();
            move |_endpoint| {
                let connects = connects.clone();
                async move {
                    connects.fetch_add(1, Ordering::SeqCst);
                    let stream = TcpStream::connect(addr).await?;
                    Ok(stream)
                }
            }
        },
    ));
    let sender = TorPacketSender::new(io);

    let to = SecretKey::generate(&mut rand::rng()).public();
    let from = SecretKey::generate(&mut rand::rng()).public();
    let packet1 = TorPacket {
        from,
        data: Bytes::from_static(b"one"),
        segment_size: Some(32),
    };
    let packet2 = TorPacket {
        from,
        data: Bytes::from_static(b"two"),
        segment_size: None,
    };

    sender.send(to, &packet1).await?;
    sender.send(to, &packet2).await?;

    let packets = server.await??;
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0], packet1);
    assert_eq!(packets[1], packet2);
    assert_eq!(
        connects.load(Ordering::SeqCst),
        1,
        "expected single connection reuse"
    );

    Ok(())
}

#[test]
fn test_key_conversion() {
    // Generate an iroh key
    let iroh_key = SecretKey::generate(&mut rand::rng());

    // Convert to tor key
    let tor_key = iroh_to_tor_secret_key(&iroh_key);

    // The public keys should match
    let iroh_public = iroh_key.public();
    let tor_public = tor_key.public();

    // iroh public key is 32 bytes, tor public key is also 32 bytes
    assert_eq!(iroh_public.as_bytes(), tor_public.as_bytes());
}

#[test]
fn test_onion_address_deterministic() {
    let iroh_key = SecretKey::generate(&mut rand::rng());

    let addr1 = onion_address(&iroh_key);
    let addr2 = onion_address(&iroh_key);

    assert_eq!(addr1.to_string(), addr2.to_string());
}
