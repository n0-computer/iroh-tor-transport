//! Integration test for the iroh user transport backed by Tor streams.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Once},
};

use anyhow::Result;
use iroh::{
    Endpoint, EndpointAddr, SecretKey, TransportAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
};
use tokio::{net::TcpListener, sync::Mutex};
use tracing::info;

use crate::{TorStreamIo, TorCustomTransport, tor_user_addr};

const ALPN: &[u8] = b"iroh-tor/user-transport/0";

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
        info!("echo copied {bytes_sent} bytes");
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init()
            .ok();
    });
}

async fn setup_endpoint(sk: SecretKey, io: Arc<TorStreamIo>) -> Result<Endpoint> {
    let transport = TorCustomTransport::builder().io(io).build(sk.clone()).await?;
    Ok(Endpoint::builder()
        .secret_key(sk)
        .clear_ip_transports()
        .clear_relay_transports()
        .clear_address_lookup()
        .preset(transport.preset())
        .bind()
        .await?)
}

async fn build_local_io(
    listener: TcpListener,
    map: Arc<Mutex<HashMap<iroh::EndpointId, SocketAddr>>>,
) -> Arc<TorStreamIo> {
    Arc::new(TorStreamIo::new(
        {
            let listener = Arc::new(listener);
            move || {
                let listener = listener.clone();
                async move {
                    let (stream, _) = listener.accept().await?;
                    Ok(stream)
                }
            }
        },
        {
            move |endpoint| {
                let map = map.clone();
                async move {
                    let addr = map
                        .lock()
                        .await
                        .get(&endpoint)
                        .copied()
                        .ok_or_else(|| std::io::Error::other("missing endpoint addr"))?;
                    let stream = tokio::net::TcpStream::connect(addr).await?;
                    Ok(stream)
                }
            }
        },
    ))
}

#[tokio::test]
async fn test_user_transport_roundtrip_local() -> Result<()> {
    init_tracing();
    info!("starting local user-transport test");
    let map: Arc<Mutex<HashMap<iroh::EndpointId, SocketAddr>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let sk1 = SecretKey::generate(&mut rand::rng());
    let sk2 = SecretKey::generate(&mut rand::rng());
    let id1 = sk1.public();
    let id2 = sk2.public();

    let listener1 = TcpListener::bind("127.0.0.1:0").await?;
    let listener2 = TcpListener::bind("127.0.0.1:0").await?;
    let addr1 = listener1.local_addr()?;
    let addr2 = listener2.local_addr()?;
    info!("listener1 bound at {addr1}");
    info!("listener2 bound at {addr2}");

    {
        let mut guard = map.lock().await;
        guard.insert(id1, addr1);
        guard.insert(id2, addr2);
    }

    let io1 = build_local_io(listener1, map.clone()).await;
    let io2 = build_local_io(listener2, map.clone()).await;

    let ep1 = setup_endpoint(sk1, io1).await?;
    let ep2 = setup_endpoint(sk2, io2).await?;
    info!("endpoints bound");

    let _server = Router::builder(ep2).accept(ALPN, Echo).spawn();

    let addr2 = EndpointAddr::from_parts(id2, [TransportAddr::Custom(tor_user_addr(id2))]);
    info!("dialing remote endpoint (local)");
    let conn = ep1.connect(addr2, ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"hello user transport").await?;
    send.finish()?;
    let response = recv.read_to_end(1024).await?;
    assert_eq!(&response, b"hello user transport");
    info!("local user-transport test completed");

    Ok(())
}
