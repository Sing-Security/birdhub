// ============================================================================
// HUB MODULE: VISP Server-Side Implementation
// ============================================================================
//
// Orchestrates the server-side logic for the VISP transport protocol. It manages
// the cryptographic handshake, session establishment, and data streaming for
// all incoming client connections.

// region: --- Imports
use crate::crypto::{self, TemperKeyManager};
use crate::error::{Error, Result};
use crate::handshake::{self, ClientHandshake, SessionKeys};
use crate::netbird::NetbirdManager;
use crate::session::{self, StreamSession};
use crate::transport::{read_message, write_message};
use axum::{
    extract::{ConnectInfo, State},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use temper::{
    envelope,
    seal::{self, TemperKeypair},
    TemperEntropy,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, Duration};
// endregion: --- Imports

// region: --- Types

/// The response from the `/auth` endpoint, providing the hub's connection port and identity.
#[derive(Serialize)]
pub struct AuthResponse {
    pub server_port: u16,
    /// The hub's NetBird public key for peer identity binding
    pub hub_netbird_pubkey: String,
    /// The hub's hostname for verification
    pub hub_hostname: String,
}

/// The shared state for the Axum control plane.
#[derive(Clone)]
pub struct HubState {
    pub server_port: u16,
    pub _key_manager: Arc<TemperKeyManager>,
    pub _hub_netbird_pubkey: String,
}

/// The main Hub server structure.
pub struct Hub {
    bind_addr: String,
    server_port: u16,
    rotation_interval_secs: u64,
    key_manager: Arc<TemperKeyManager>,
    /// The Hub's long-term identity keypair, used for signing Seals.
    signing_keypair: TemperKeypair,
    /// The Hub's NetBird public key for identity binding.
    hub_netbird_pubkey: String,
}
// endregion: --- Types

// region: --- Hub Implementation

impl Hub {
    /// Creates a new Hub instance.
    /// In a production environment, the `signing_keypair` would be loaded from a
    /// secure, persistent storage. For this implementation, it's generated on startup.
    pub async fn new(
        bind_addr: impl Into<String>,
        server_port: u16,
        rotation_interval_secs: u64,
    ) -> Result<Self> {
        let initial_seed = crypto::generate_seed();
        let key_manager = Arc::new(TemperKeyManager::new(initial_seed));

        // Generate a new long-term signing keypair for the hub's identity.
        println!("Hub: Generating new long-term signing identity...");
        let mut rng = TemperEntropy::new()?;
        let signing_keypair = seal::generate_keypair(&mut rng, "visp-hub-identity")
            .map_err(Error::custom_from_err)?;

        // Verify hub's NetBird identity is available
        let netbird_mgr = NetbirdManager::new();
        let hub_identity = netbird_mgr.get_identity().await?;
        if !hub_identity.is_connected {
            return Err(Error::Custom(
                "Hub is not connected to NetBird mesh. Cannot start.".to_string(),
            ));
        }
        println!(
            "Hub: NetBird identity verified - IP: {}, Hostname: {}",
            hub_identity.ip, hub_identity.hostname
        );

        Ok(Self {
            bind_addr: bind_addr.into(),
            server_port,
            rotation_interval_secs,
            key_manager,
            signing_keypair,
            hub_netbird_pubkey: hub_identity.pubkey,
        })
    }

    /// Starts the Hub server, including the control plane, data plane, and key rotation loop.
    pub async fn start(self) -> Result<()> {
        let shared_state = HubState {
            server_port: self.server_port,
            _key_manager: self.key_manager.clone(),
            _hub_netbird_pubkey: self.hub_netbird_pubkey.clone(),
        };

        // --- Spawn Master Key Rotation Loop ---
        let key_manager_clone = self.key_manager.clone();
        let rotation_interval = self.rotation_interval_secs;
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(rotation_interval)).await;
                println!("Hub: Rotating master key...");
                let new_seed = crypto::generate_seed();
                key_manager_clone.rotate_key(new_seed);
                println!(
                    "Hub: Master key rotated to version {}",
                    key_manager_clone.current_version()
                );
            }
        });

        // --- Spawn Data Plane Listener ---
        let data_plane_listener =
            TcpListener::bind(format!("0.0.0.0:{}", self.server_port)).await?;
        println!("Hub Data Plane listening on 0.0.0.0:{}", self.server_port);
        let key_manager_for_data_plane = self.key_manager.clone();
        let signing_keypair_for_data_plane = self.signing_keypair.clone();
        let hub_netbird_pubkey_for_data_plane = self.hub_netbird_pubkey.clone();
        tokio::spawn(async move {
            loop {
                match data_plane_listener.accept().await {
                    Ok((socket, addr)) => {
                        let key_manager = key_manager_for_data_plane.clone();
                        let signing_keypair = signing_keypair_for_data_plane.clone();
                        let hub_netbird_pubkey = hub_netbird_pubkey_for_data_plane.clone();
                        tokio::spawn(async move {
                            println!("Hub: New connection from {}", addr);
                            if let Err(e) = Self::handle_client_connection(
                                socket,
                                addr,
                                key_manager,
                                signing_keypair,
                                hub_netbird_pubkey,
                            )
                            .await
                            {
                                eprintln!("Hub: Connection with {} ended with error: {}", addr, e);
                            } else {
                                println!("Hub: Connection with {} closed gracefully.", addr);
                            }
                        });
                    }
                    Err(e) => eprintln!("Hub: Failed to accept new connection: {}", e),
                }
            }
        });

        // --- Start Axum Control Plane ---
        let app = Router::new()
            .route("/auth", get(auth_handler))
            .with_state(shared_state);
        let control_plane_listener = TcpListener::bind(&self.bind_addr).await?;
        println!("Hub Control Plane listening on {}", self.bind_addr);
        axum::serve(
            control_plane_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(Error::custom_from_err)?;

        Ok(())
    }

    /// Handles a new client connection, performing the 3-phase handshake and then streaming data.
    async fn handle_client_connection(
        mut socket: TcpStream,
        addr: SocketAddr,
        key_manager: Arc<TemperKeyManager>,
        signing_keypair: TemperKeypair,
        hub_netbird_pubkey: String,
    ) -> Result<()> {
        let mut rng = TemperEntropy::new()?;

        // === PHASE 1: HUB AUTHENTICATION (SEND SEAL) ===
        // Generate an ephemeral keypair for this specific session for forward secrecy.
        let ephemeral_envelope_keypair = envelope::generate_envelope_keypair(&mut rng)?;

        // Create a Seal that signs the public part of our ephemeral key with our long-term identity.
        let hub_identity = handshake::create_hub_identity_seal(
            &mut rng,
            &signing_keypair,
            &ephemeral_envelope_keypair,
            &hub_netbird_pubkey,
        )?;
        let hub_identity_bytes: Vec<u8> = postcard::to_vec::<_, 32768>(&hub_identity)?.to_vec();

        // Send the length-prefixed Seal to the client.
        socket.write_u32(hub_identity_bytes.len() as u32).await?;
        socket.write_all(&hub_identity_bytes).await?;

        // === PHASE 2: SESSION KEY ESTABLISHMENT (RECEIVE ENVELOPE) ===
        // Read the length-prefixed handshake from the client with a 5-second timeout.
        let client_handshake_len = tokio::time::timeout(Duration::from_secs(5), socket.read_u32())
            .await
            .map_err(|_| {
                Error::Custom("Handshake timed out waiting for client Envelope".into())
            })??;

        if client_handshake_len > 16384 {
            return Err(Error::Custom("Client handshake message too large".into()));
        }
        let mut client_handshake_buf = vec![0; client_handshake_len as usize];
        tokio::time::timeout(
            Duration::from_secs(5),
            socket.read_exact(&mut client_handshake_buf),
        )
        .await
        .map_err(|_| Error::Custom("Handshake timed out reading client Envelope data".into()))??;
        let client_handshake: ClientHandshake = postcard::from_bytes(&client_handshake_buf)?;

        // Decapsulate the client's envelope using our ephemeral private key to get the shared secret.
        let session_keys: SessionKeys =
            handshake::decapsulate_client_envelope(&client_handshake, &ephemeral_envelope_keypair)?;

        println!(
            "Hub: Handshake with {} successful. Entering streaming phase.",
            addr
        );

        // === PHASE 3: STREAMING ENCRYPTION ===
        // Derive peer_id from the client's NetBird public key (received in the handshake)
        let peer_id = Self::peer_id_from_netbird_pubkey(&client_handshake.client_netbird_pubkey);
        let session = StreamSession::new(
            session_keys.hub_to_client_key, // encryption_key: for encrypting responses
            session_keys.client_to_hub_key, // decryption_key: for decrypting client data
            peer_id,
            key_manager,
        );

        loop {
            // 1. Read an encrypted packet from the client using the length-prefixed protocol.
            // This ensures we have a complete packet before attempting decryption.
            let encrypted_packet = match read_message(&mut socket).await {
                Ok(data) => data,
                Err(e) => {
                    if let Error::Custom(ref msg) = e {
                        if msg.contains("Unexpected EOF") {
                            break; // Connection closed gracefully
                        }
                    }
                    return Err(e);
                }
            };

            // 2. Unseal the packet (verify HMAC, decrypt).
            let plaintext = session::unseal_stream_packet(&session, &encrypted_packet, false)?;

            // 3. In a real implementation, this plaintext would be forwarded to the internet.
            // For now, we just echo it back to the client to confirm the crypto works.
            let response_plaintext = plaintext;

            // 4. Seal the response packet.
            let response_packet = session::seal_stream_packet(
                &session,
                &response_plaintext,
                &[], // No obfuscation from hub to client
                false,
            )?;

            // 5. Send the encrypted response using the length-prefixed protocol.
            write_message(&mut socket, &response_packet).await?;
        }

        Ok(())
    }

    /// Creates a deterministic, 32-byte peer ID from a client's NetBird public key using BLAKE3.
    /// This cryptographically binds the transport identity to the NetBird mesh identity.
    fn peer_id_from_netbird_pubkey(netbird_pubkey: &str) -> [u8; 32] {
        let hash = blake3::hash(netbird_pubkey.as_bytes());
        *hash.as_bytes()
    }
}
// endregion: --- Hub Implementation

// region: --- Handlers & Helpers

/// Axum handler for the `/auth` endpoint.
async fn auth_handler(
    State(state): State<HubState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> std::result::Result<Json<AuthResponse>, axum::http::StatusCode> {
    // Verify the caller is a valid NetBird peer before providing connection info.
    if !is_valid_netbird_peer(addr.ip()) {
        eprintln!(
            "Hub: Unauthorized auth attempt from non-NetBird IP {}",
            addr.ip()
        );
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }

    // Get the hub's NetBird identity to include in the auth response
    let netbird_mgr = NetbirdManager::new();
    let hub_identity = match netbird_mgr.get_identity().await {
        Ok(identity) => {
            if !identity.is_connected {
                eprintln!("Hub: NetBird connection lost, denying auth");
                return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
            }
            identity
        }
        Err(e) => {
            eprintln!("Hub: Failed to verify NetBird identity: {}", e);
            return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Ok(Json(AuthResponse {
        server_port: state.server_port,
        hub_netbird_pubkey: hub_identity.pubkey,
        hub_hostname: hub_identity.hostname,
    }))
}

/// Mock verification for NetBird peers.
fn is_valid_netbird_peer(ip: IpAddr) -> bool {
    // In production, this would involve a call to the NetBird management API.
    // For now, we assume any IP in the CGNAT range is a valid peer.
    if let IpAddr::V4(ipv4) = ip {
        let octets = ipv4.octets();
        // Check for 100.64.0.0/10 range
        if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
            return true;
        }
    }
    // Allow localhost for local testing
    ip.is_loopback()
}
// endregion: --- Handlers & Helpers
