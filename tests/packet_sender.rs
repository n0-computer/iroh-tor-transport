//! Tests for reusing packet sender connections.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use iroh::SecretKey;
use iroh_tor::{read_tor_packet, TorPacket, TorPacketSender, TorStreamIo};
use tokio::net::{TcpListener, TcpStream};

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
        let accept_timeout = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
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
    assert_eq!(connects.load(Ordering::SeqCst), 1, "expected single connection reuse");

    Ok(())
}
