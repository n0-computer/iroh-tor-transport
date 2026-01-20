//! Tor hidden service utilities for iroh.
//!
//! This crate provides utilities for creating Tor hidden services that can be used
//! as a custom transport for iroh networking.

use std::{future::Future, pin::Pin, str::FromStr, time::Duration};

use anyhow::{Context, Result};
use iroh::SecretKey;
use sha2::{Digest, Sha512};
use tokio::net::TcpStream;
// Re-export TorSecretKeyV3 for users who want to use native Tor keys
pub use torut::onion::TorSecretKeyV3;
use torut::{
    control::{AuthenticatedConn, ConnError, UnauthenticatedConn},
    onion::OnionAddressV3,
};

/// Default Tor control port
pub const DEFAULT_CONTROL_PORT: u16 = 9051;

/// Default Tor SOCKS5 proxy port
pub const DEFAULT_SOCKS_PORT: u16 = 9050;

/// Convert an iroh SecretKey to a Tor v3 secret key.
///
/// Iroh uses standard Ed25519 32-byte secret keys (seeds), while Tor uses
/// 64-byte "expanded" secret keys. This function performs the expansion
/// using SHA-512 as specified in RFC 8032.
///
/// Note: torut uses ed25519-dalek 1.x internally. We generate the expanded
/// key format that torut expects by using its internal ed25519-dalek types.
pub fn iroh_to_tor_secret_key(key: &SecretKey) -> TorSecretKeyV3 {
    // Get the 32-byte seed from iroh's SecretKey
    let seed = key.to_bytes();

    // Use torut's internal ed25519-dalek 1.x to create the expanded key
    // torut re-exports what we need through its generate() path
    // We'll create an ExpandedSecretKey using SHA-512 expansion
    let hash = Sha512::digest(seed);
    let expanded_bytes: [u8; 64] = hash.into();

    // TorSecretKeyV3::from expects a 64-byte array
    TorSecretKeyV3::from(expanded_bytes)
}

/// Generate a new Tor secret key using torut's native key generation.
/// This is useful for testing that the basic mechanism works.
pub fn generate_tor_key() -> TorSecretKeyV3 {
    TorSecretKeyV3::generate()
}

/// Get the onion address for an iroh SecretKey.
pub fn onion_address(key: &SecretKey) -> OnionAddressV3 {
    let tor_key = iroh_to_tor_secret_key(key);
    tor_key.public().get_onion_address()
}

/// Type alias for the async event handler function.
type EventHandler = Box<
    dyn Fn(
            torut::control::AsyncEvent<'static>,
        ) -> Pin<Box<dyn Future<Output = Result<(), ConnError>> + Send>>
        + Send
        + Sync,
>;

/// A connection to the Tor control port.
pub struct TorControl {
    conn: AuthenticatedConn<TcpStream, EventHandler>,
}

impl TorControl {
    /// Connect to the Tor control port and authenticate.
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .context("Failed to connect to Tor control port")?;

        let mut conn = UnauthenticatedConn::new(stream);

        // Get authentication info
        let auth_data = conn
            .load_protocol_info()
            .await
            .context("Failed to load protocol info")?;

        // Try to authenticate (cookie auth or null auth)
        let auth_method = auth_data
            .make_auth_data()
            .context("Failed to determine auth method")?;

        if let Some(auth) = auth_method {
            conn.authenticate(&auth)
                .await
                .context("Failed to authenticate")?;
        }

        let conn: AuthenticatedConn<TcpStream, EventHandler> = conn.into_authenticated().await;

        Ok(Self { conn })
    }

    /// Create or reuse a hidden service using the given secret key.
    ///
    /// The hidden service will forward connections from `onion_port` to `local_addr`.
    ///
    /// Returns a tuple of (onion_address, already_existed). If `already_existed` is true,
    /// the service was already registered with Tor (likely from a previous run with
    /// deterministic keys), meaning the descriptor is probably already published and
    /// connections should be fast.
    ///
    /// Note: If the service is reused, the port mapping from the original creation
    /// is kept. The `onion_port` and `local_addr` parameters are only used for new services.
    pub async fn create_hidden_service(
        &mut self,
        key: &SecretKey,
        onion_port: u16,
        local_addr: std::net::SocketAddr,
    ) -> Result<(OnionAddressV3, bool)> {
        let tor_key = iroh_to_tor_secret_key(key);
        self.create_hidden_service_with_tor_key(&tor_key, onion_port, local_addr)
            .await
    }

    /// Create or reuse a hidden service using a native Tor secret key.
    /// This is useful for testing or when you have a TorSecretKeyV3 directly.
    pub async fn create_hidden_service_with_tor_key(
        &mut self,
        tor_key: &TorSecretKeyV3,
        onion_port: u16,
        local_addr: std::net::SocketAddr,
    ) -> Result<(OnionAddressV3, bool)> {
        let onion_addr = tor_key.public().get_onion_address();

        println!(
            "DEBUG: Creating hidden service {} -> {}:{}",
            onion_addr.get_address_without_dot_onion(),
            local_addr,
            onion_port
        );

        let listeners = [(onion_port, local_addr)];
        match self
            .conn
            .add_onion_v3(
                tor_key,
                false, // detach: false means the service will be removed when we disconnect
                false, // non_anonymous: false for full anonymity
                false, // max_streams_close_circuit
                None,  // max_num_streams
                &mut listeners.iter(),
            )
            .await
        {
            Ok(()) => {
                println!("DEBUG: add_onion_v3 returned Ok");
                Ok((onion_addr, false))
            }
            Err(e) => {
                println!("DEBUG: add_onion_v3 returned Err: {:?}", e);
                // Check if this is a "key collision" error (service already exists)
                // torut returns InvalidResponseCode(552) for this case
                if matches!(e, ConnError::InvalidResponseCode(552)) {
                    tracing::info!(
                        "Hidden service {} already exists, reusing it",
                        onion_addr.get_address_without_dot_onion()
                    );
                    Ok((onion_addr, true))
                } else {
                    Err(e).context("Failed to create hidden service")
                }
            }
        }
    }

    /// Wait for hidden service descriptor to be published.
    ///
    /// This is a simple delay-based approach. Tor doesn't provide a reliable way
    /// to query publication status via GETINFO, and torut has a bug that prevents
    /// subscribing to HS_DESC events (it rejects underscores in event names).
    ///
    /// For new services, we wait a fixed amount of time. For production use,
    /// consider using retry logic when connecting instead.
    pub async fn wait_for_publication(
        &mut self,
        _onion_addr: &OnionAddressV3,
        _timeout: Duration,
    ) -> Result<()> {
        // Just wait a fixed delay for the descriptor to propagate.
        // The actual time needed varies (30s-120s for first publish, faster with cached keys).
        // Connection retry logic should handle cases where this isn't enough.
        println!("Waiting 30s for descriptor to propagate to HSDir nodes...");
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok(())
    }

    /// Remove a hidden service by its onion address.
    pub async fn remove_hidden_service(&mut self, addr: &OnionAddressV3) -> Result<()> {
        // The service_id is the onion address without the .onion suffix
        let service_id = addr.get_address_without_dot_onion();
        self.conn
            .del_onion(&service_id)
            .await
            .context("Failed to remove hidden service")?;
        Ok(())
    }

    /// List hidden services owned by the current control connection.
    ///
    /// This uses the Tor control command `GETINFO onions/current`, which only
    /// returns services created on this connection and not detached services.
    pub async fn list_hidden_services(&mut self) -> Result<Vec<OnionAddressV3>> {
        let response = self
            .conn
            .get_info_unquote("onions/current")
            .await
            .context("Failed to query onions/current")?;

        let mut services = Vec::new();
        for line in response.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let addr = OnionAddressV3::from_str(line)
                .with_context(|| format!("Invalid onion address from Tor: {}", line))?;
            services.push(addr);
        }

        Ok(services)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
