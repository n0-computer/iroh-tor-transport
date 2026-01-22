# iroh-tor

Tor hidden-service utilities and a custom iroh transport for routing packets over Tor streams.

> **Experimental:** both iroh custom transports and this crate are experimental and may change.

## What is iroh-tor?

`iroh-tor` provides a custom iroh user transport that routes packets over Tor hidden services.
Given only an iroh `EndpointId`, it derives the corresponding `.onion` address and connects
through the Tor network.

## Getting started

### Tor control port

Most tests require a running Tor daemon with the control port enabled:

```
tor --ControlPort 9051 --CookieAuthentication 0
```

### Custom transport

The transport connects to Tor's control port, creates an ephemeral hidden service,
and handles packet framing and stream reuse:

```rust
use iroh::{Endpoint, SecretKey};
use iroh_tor::TorUserTransport;

let secret_key = SecretKey::generate(&mut rand::rng());

// Build the transport (creates hidden service)
let transport = TorUserTransport::builder()
    .build(secret_key.clone())
    .await?;

// Build the endpoint with the Tor transport
let endpoint = Endpoint::builder()
    .secret_key(secret_key)
    .preset(transport.preset())
    .bind()
    .await?;
```

The `preset()` method configures the endpoint with:
- The Tor user transport
- A discovery service that derives Tor addresses from endpoint IDs

## Packet framing

Each packet is framed as:

- `flags: u8` (bit 0 indicates `segment_size` present)
- `from: [u8; 32]` (iroh `EndpointId`)
- `segment_size: u16` (optional hint, not a payload limit)
- `data_len: u32`
- `data: [u8; data_len]`

## Example

`examples/echo.rs` provides a CLI for echo server/client over Tor:

```bash
# Terminal 1: Start the echo server
cargo run --example echo -- accept

# Terminal 2: Connect to the server (use the EndpointId printed by the server)
cargo run --example echo -- connect <ENDPOINT_ID>
```

The onion address is derived from the `EndpointId`, so you only need the endpoint ID to connect.

## Tests

- `tests/echo.rs`: hidden-service echo tests (Tor required)
- Internal tests cover packet framing, sender stream reuse, and user transport

## License

Copyright 2025 N0, INC.

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
