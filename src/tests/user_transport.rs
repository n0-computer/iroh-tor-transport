//! Integration test for the iroh user transport backed by Tor streams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Once};

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_socks::tcp::Socks5Stream;
use tracing::info;

use crate::{
    DEFAULT_CONTROL_PORT, DEFAULT_SOCKS_PORT, TorControl, TorStreamIo, TorUserTransport,
    iroh_to_tor_secret_key, tor_user_addr,
};

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

async fn setup_endpoint(
    sk: &SecretKey,
    io: Arc<TorStreamIo>,
    use_user_discovery: bool,
) -> Result<Endpoint> {
    let transport = TorUserTransport::builder(sk.public(), io).build();
    let mut builder = Endpoint::builder()
        .secret_key(sk.clone())
        .add_user_transport(transport.factory())
        .clear_ip_transports()
        .clear_relay_transports()
        .clear_discovery();
    if use_user_discovery {
        builder = builder.discovery(transport.discovery());
    }
    Ok(builder.bind().await?)
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
                        .context("missing endpoint addr")?;
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

    let ep1 = setup_endpoint(&sk1, io1, true).await?;
    let ep2 = setup_endpoint(&sk2, io2, true).await?;
    info!("endpoints bound");

    let _server = Router::builder(ep2).accept(ALPN, Echo).spawn();

    let addr2 = EndpointAddr::from_parts(id2, [TransportAddr::User(tor_user_addr(id2))]);
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

async fn build_tor_io(
    listener: TcpListener,
    map: Arc<Mutex<HashMap<iroh::EndpointId, String>>>,
    socks_addr: SocketAddr,
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
                    let onion = map
                        .lock()
                        .await
                        .get(&endpoint)
                        .cloned()
                        .context("missing onion address")?;
                    let stream = Socks5Stream::connect(socks_addr, (onion.as_str(), 9999)).await?;
                    Ok(stream.into_inner())
                }
            }
        },
    ))
}

#[tokio::test]
async fn test_user_transport_roundtrip_tor() -> Result<()> {
    init_tracing();
    info!("starting tor user-transport test");
    let control_addr = format!("127.0.0.1:{}", DEFAULT_CONTROL_PORT);
    let mut tor_control = TorControl::connect(&control_addr).await.context(
        "Tor control port unavailable. Start Tor with ControlPort 9051 enabled and try again.",
    )?;
    info!("connected to tor control");

    let socks_addr: SocketAddr = format!("127.0.0.1:{}", DEFAULT_SOCKS_PORT).parse()?;
    info!("using socks at {socks_addr}");
    let map: Arc<Mutex<HashMap<iroh::EndpointId, String>>> = Arc::new(Mutex::new(HashMap::new()));

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

    let tor_key1 = iroh_to_tor_secret_key(&sk1);
    let tor_key2 = iroh_to_tor_secret_key(&sk2);

    let (onion1, _) = tor_control
        .create_hidden_service_with_tor_key(&tor_key1, 9999, addr1)
        .await?;
    let (onion2, _) = tor_control
        .create_hidden_service_with_tor_key(&tor_key2, 9999, addr2)
        .await?;
    info!(
        "hidden services: {}.onion, {}.onion",
        onion1.get_address_without_dot_onion(),
        onion2.get_address_without_dot_onion()
    );

    {
        let mut guard = map.lock().await;
        guard.insert(
            id1,
            format!("{}.onion", onion1.get_address_without_dot_onion()),
        );
        guard.insert(
            id2,
            format!("{}.onion", onion2.get_address_without_dot_onion()),
        );
    }

    let io1 = build_tor_io(listener1, map.clone(), socks_addr).await;
    let io2 = build_tor_io(listener2, map.clone(), socks_addr).await;

    let ep1 = setup_endpoint(&sk1, io1, true).await?;
    let ep2 = setup_endpoint(&sk2, io2, true).await?;
    info!("endpoints bound");

    let _server = Router::builder(ep2).accept(ALPN, Echo).spawn();

    let addr2 = EndpointAddr::from_parts(id2, [TransportAddr::User(tor_user_addr(id2))]);
    info!("dialing remote endpoint (tor)");
    let conn = ep1.connect(addr2, ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"hello tor user transport").await?;
    send.finish()?;
    let response = recv.read_to_end(1024).await?;
    assert_eq!(&response, b"hello tor user transport");
    info!("tor user-transport test completed");

    Ok(())
}
