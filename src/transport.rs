// ============================================================================
// TRANSPORT MODULE: Client-Side Transport and Cryptographic Handshake
// ============================================================================
//
// Manages the client-side of a VISP connection. It listens for local TCP
// connections, performs the 3-phase cryptographic handshake with the remote
// hub for each connection, and then enters a high-performance streaming phase.

// region: --- Imports
use crate::crypto::TemperKeyManager;
use crate::error::{Error, Result};
use crate::handshake;
use crate::netbird::NetbirdManager;
use crate::session::{self, StreamSession};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::bytes::{Bytes, BytesMut};
// endregion: --- Imports

// region: --- Config & State

/// Transport layer configuration.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub server_address: String,
    pub server_port: u16,
    pub local_port: u16,
    #[allow(dead_code)]
    pub mark: Option<u32>, // Reserved for SO_MARK
}

/// Manages all client-side transport tunnels.
/// It holds the master key manager and spawns a new task for each incoming connection.
pub struct TransportManager {
    config: Arc<TransportConfig>,
    key_manager: Arc<TemperKeyManager>,
}
// endregion: --- Config & State

// region: --- TransportManager Implementation

impl TransportManager {
    /// Creates a new transport manager with a randomly generated master seed.
    pub fn new(config: TransportConfig) -> Self {
        // Generate initial seed for the master key manager using a blake3 hash of the current time.
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos().to_le_bytes().to_vec())
            .unwrap_or_default();
        let hash = blake3::hash(&timestamp);
        let mut initial_seed = [0u8; 32];
        initial_seed.copy_from_slice(hash.as_bytes());

        Self {
            config: Arc::new(config),
            key_manager: Arc::new(TemperKeyManager::new(initial_seed)),
        }
    }

    /// Starts the main tunnel listener.
    /// It binds to a local port and accepts incoming connections, handing each
    /// off to a dedicated asynchronous task for the handshake and streaming.
    pub async fn start_tunnel(&self) -> Result<()> {
        let bind_addr = format!("127.0.0.1:{}", self.config.local_port);
        let listener = TcpListener::bind(&bind_addr).await?;
        println!("Transport Manager listening on {}", bind_addr);

        loop {
            let (mut client_stream, client_addr) = listener.accept().await?;
            let config = self.config.clone();
            let key_manager = self.key_manager.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_client_connection(
                    &mut client_stream,
                    client_addr.ip(),
                    config,
                    key_manager,
                )
                .await
                {
                    eprintln!("Connection from {} failed: {}", client_addr.ip(), e);
                }
            });
        }
    }

    /// Handles a single client connection from start to finish.
    async fn handle_client_connection(
        local_stream: &mut TcpStream,
        _local_ip: IpAddr,
        config: Arc<TransportConfig>,
        key_manager: Arc<TemperKeyManager>,
    ) -> Result<()> {
        // 1. Connect to the remote hub.
        let remote_addr = format!("{}:{}", config.server_address, config.server_port);
        let mut hub_stream = TcpStream::connect(&remote_addr).await?;
        println!("Connected to hub at {}", remote_addr);

        // 2. Perform the cryptographic handshake to establish a secure session.
        let session = Self::perform_handshake(&mut hub_stream, key_manager).await?;
        println!(
            "Handshake with {} successful. Session established.",
            remote_addr
        );

        // 3. Enter the high-performance streaming phase.
        let (local_read, local_write) = local_stream.split();
        let (hub_read, hub_write) = hub_stream.split();
        Self::stream_data(session, local_read, local_write, hub_read, hub_write).await?;

        Ok(())
    }

    /// Executes the 3-phase cryptographic handshake.
    async fn perform_handshake(
        hub_stream: &mut TcpStream,
        key_manager: Arc<TemperKeyManager>,
    ) -> Result<StreamSession> {
        // Create a Temper entropy source for cryptographic operations.
        let mut rng = temper::TemperEntropy::new().map_err(Error::custom_from_err)?;

        // Fetch local NetBird identity to be included in the handshake.
        let netbird_manager = NetbirdManager::new();
        let client_identity = netbird_manager.get_identity().await?;
        if !client_identity.is_connected {
            return Err(Error::Custom(
                "Client is not connected to NetBird mesh. Cannot start transport.".to_string(),
            ));
        }

        // --- Phase 1: Receive and Verify Hub's Identity Seal ---
        let hub_identity_bytes = read_message(hub_stream).await?;
        let hub_identity: handshake::HubIdentitySeal =
            postcard::from_bytes(&hub_identity_bytes).map_err(Error::custom_from_err)?;

        // This is the core client-side crypto logic:
        // 1. Verifies the Hub's Seal.
        // 2. Creates the Envelope to establish the shared secret.
        // 3. Derives the final symmetric session keys.
        let (session_keys, client_handshake) = handshake::verify_hub_seal_and_create_envelope(
            &mut rng,
            &hub_identity,
            &client_identity.pubkey,
        )?;

        // --- Phase 2: Send Client Envelope to Hub ---
        let client_handshake_bytes: Vec<u8> = postcard::to_vec::<_, 16384>(&client_handshake)
            .map_err(Error::custom_from_err)?
            .to_vec();
        write_message(hub_stream, &client_handshake_bytes).await?;

        // --- Phase 3: Create StreamSession ---
        // Derive peer_id from our own NetBird public key. This must match the
        // peer_id the hub derives from the public key we sent in the handshake.
        let hash = blake3::hash(client_identity.pubkey.as_bytes());
        let peer_id = *hash.as_bytes();
        let session = StreamSession::new(
            session_keys.client_to_hub_key, // encryption_key: for encrypting data to hub
            session_keys.hub_to_client_key, // decryption_key: for decrypting responses from hub
            peer_id,
            key_manager,
        );

        Ok(session)
    }

    /// Manages the bidirectional data streaming after a handshake is complete.
    async fn stream_data(
        session: StreamSession,
        mut local_read: impl AsyncReadExt + Unpin,
        mut local_write: impl AsyncWriteExt + Unpin,
        mut hub_read: impl AsyncReadExt + Unpin,
        mut hub_write: impl AsyncWriteExt + Unpin,
    ) -> Result<()> {
        let mut local_to_hub_buf = BytesMut::with_capacity(65536);

        loop {
            tokio::select! {
                // Read from local client (unencrypted), encrypt, and send to hub.
                result = local_read.read_buf(&mut local_to_hub_buf) => {
                    let n = result?;
                    if n == 0 { break; } // EOF

                    let plaintext = &local_to_hub_buf[..n];
                    let obfuscation_header = Self::generate_obfuscation_header();
                    let sealed_packet = session::seal_stream_packet(&session, plaintext, &obfuscation_header, false)?;

                    // Use length-prefixing to send the encrypted packet over TCP
                    write_message(&mut hub_write, &sealed_packet).await?;
                    local_to_hub_buf.clear();
                },

                // Read from hub (encrypted), decrypt, and send to local client.
                result = read_message(&mut hub_read) => {
                    let sealed_packet = match result {
                        Ok(data) => data,
                        Err(e) => {
                            if let Error::Custom(ref msg) = e {
                                if msg.contains("Unexpected EOF") {
                                    break;
                                }
                            }
                            return Err(e);
                        }
                    };

                    let plaintext = session::unseal_stream_packet(&session, &sealed_packet, false)?;

                    local_write.write_all(&plaintext).await?;
                }
            }
        }
        Ok(())
    }

    /// Generates a randomized DPI obfuscation header (16-64 bytes).
    fn generate_obfuscation_header() -> Vec<u8> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos().to_le_bytes().to_vec())
            .unwrap_or_default();

        let hash = blake3::hash(&timestamp);
        let hash_bytes = hash.as_bytes();
        let header_len = ((hash_bytes[0] as usize) % 49) + 16; // Range 16-64

        let mut header = hash_bytes[1..].to_vec();
        header.truncate(header_len);
        if header.len() < header_len {
            let hash2 = blake3::hash(&header);
            header.extend_from_slice(hash2.as_bytes());
            header.truncate(header_len);
        }
        header
    }
}

// endregion: --- TransportManager Implementation

// region: --- Stream Helper Functions

/// Reads a message from the stream that has a 4-byte (u32) length prefix.
pub async fn read_message<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Bytes> {
    let len = match stream.read_u32().await {
        Ok(l) => l as usize,
        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(Error::Custom("Unexpected EOF".to_string()));
        }
        Err(e) => return Err(e.into()),
    };
    if len > 1_000_000 {
        // Basic sanity check to prevent OOM
        return Err(Error::Custom("Message too large".to_string()));
    }
    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer).await?;
    Ok(buffer.into())
}

/// Writes a message to the stream with a 4-byte (u32) length prefix.
pub async fn write_message<W: AsyncWriteExt + Unpin>(stream: &mut W, buffer: &[u8]) -> Result<()> {
    let len = buffer.len() as u32;
    stream.write_u32(len).await?;
    stream.write_all(buffer).await?;
    Ok(())
}

// endregion: --- Stream Helper Functions
