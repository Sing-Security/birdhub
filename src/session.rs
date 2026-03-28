// ============================================================================
// SESSION MODULE: Post-Handshake Streaming Encryption
// ============================================================================
//
// Manages the state and cryptographic operations for a live, authenticated
// transport session after the initial Seal and Envelope handshake is complete.
// This module is optimized for high-performance, per-packet operations.

// region: --- Imports
use crate::crypto::{self, PacketHeader, TemperKeyManager};
use crate::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// endregion: --- Imports

// region: --- Constants
const BLAKE3_HASH_SIZE: usize = 32;
const NONCE_SIZE: usize = 16;
// endregion: --- Constants

// region: --- ReplayCache Struct
/// A sliding window replay cache to prevent replay attacks.
#[derive(Debug)]
pub struct ReplayCache {
    /// The highest sequence number seen so far.
    highest_seq: u64,
    /// A bitmask of recently seen sequence numbers. The bit at index `i`
    /// represents whether `highest_seq - i` has been seen.
    window: u64,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self {
            highest_seq: 0,
            window: 0,
        }
    }

    /// Checks if a sequence number has been seen and records it if not.
    /// Returns `true` if it's a replay, `false` otherwise.
    pub fn check_and_record(&mut self, seq: u64) -> bool {
        if seq == 0 && self.highest_seq == 0 && self.window == 0 {
            // First packet ever
            self.window |= 1;
            return false;
        }

        if seq > self.highest_seq {
            let diff = seq - self.highest_seq;
            if diff < 64 {
                self.window <<= diff;
                self.window |= 1;
            } else {
                self.window = 1;
            }
            self.highest_seq = seq;
            return false;
        }

        let diff = self.highest_seq - seq;
        if diff >= 64 {
            // Packet is too old
            return true;
        }

        let bit = 1 << diff;
        if (self.window & bit) != 0 {
            // Already seen
            return true;
        }

        // Mark as seen
        self.window |= bit;
        false
    }
}
// endregion: --- ReplayCache Struct

// region: --- StreamSession Struct
/// Represents the state of an active, authenticated streaming session.
///
/// This struct is created after a successful cryptographic handshake and holds
/// the derived session key used for all subsequent high-speed data transfer.
#[derive(Debug)]
pub struct StreamSession {
    /// The 32-byte symmetric key for encrypting outbound data.
    pub encryption_key: [u8; BLAKE3_HASH_SIZE],

    /// The 32-byte symmetric key for decrypting inbound data.
    pub decryption_key: [u8; BLAKE3_HASH_SIZE],

    /// A unique identifier for the peer, typically derived from their IP address.
    pub _peer_id: [u8; BLAKE3_HASH_SIZE],

    /// A monotonically increasing counter for generating nonces to prevent replay attacks.
    pub sequence_counter: AtomicU64,

    /// A reference to the global key manager for HMAC operations.
    pub key_manager: Arc<TemperKeyManager>,

    /// Replay cache for sequence numbers.
    pub replay_cache: Mutex<ReplayCache>,

    /// Timestamp of when the connection was established.
    pub _connection_established_at: u64,
}

impl StreamSession {
    /// Creates a new `StreamSession` after a successful handshake.
    pub fn new(
        encryption_key: [u8; BLAKE3_HASH_SIZE],
        decryption_key: [u8; BLAKE3_HASH_SIZE],
        peer_id: [u8; BLAKE3_HASH_SIZE],
        key_manager: Arc<TemperKeyManager>,
    ) -> Self {
        Self {
            encryption_key,
            decryption_key,
            _peer_id: peer_id,
            sequence_counter: AtomicU64::new(0),
            key_manager,
            replay_cache: Mutex::new(ReplayCache::new()),
            _connection_established_at: crypto::current_unix_timestamp(),
        }
    }

    /// Generates the next nonce for a packet, combining a sequence number and randomness.
    fn next_nonce(&self) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        let seq = self.sequence_counter.fetch_add(1, Ordering::Relaxed);
        nonce[0..8].copy_from_slice(&seq.to_le_bytes());

        // The remaining 8 bytes are derived from a hash of the sequence number
        // to provide deterministic "randomness" for the nonce, avoiding the need
        // for a CSPRNG on the hot path.
        let hashed_seq = blake3::hash(&seq.to_le_bytes());
        nonce[8..16].copy_from_slice(&hashed_seq.as_bytes()[0..8]);
        nonce
    }
}
// endregion: --- StreamSession Struct

// region: --- Per-Packet Crypto Functions

/// Seals (encrypts and authenticates) a single data packet for streaming.
///
/// This is the primary function for sending data during the session phase. It uses
/// the derived session key for fast ChaCha20-Poly1305 encryption and a BLAKE3 HMAC.
///
/// # Packet Format
/// `[obfuscation_header][packet_header][hmac][encrypted_data]`
pub fn seal_stream_packet(
    session: &StreamSession,
    plaintext: &[u8],
    obfuscation_header: &[u8],
    _debug_mode: bool,
) -> Result<Vec<u8>> {
    // 1. Generate the next nonce from the sequence counter.
    let nonce = session.next_nonce();

    // 2. Encrypt the plaintext using ChaCha20-Poly1305 with the encryption key.
    let encrypted =
        crypto::encrypt_with_chacha20poly1305(&session.encryption_key, &nonce, plaintext)?;

    // 3. Create the packet header. The key version is from the master key manager,
    // which indicates which master key was active when the session was established.
    let key_version = session.key_manager.current_version();
    let obfuscation_size = obfuscation_header.len();
    let packet_header =
        PacketHeader::new(obfuscation_size, key_version, nonce, encrypted.len() as u16)
            .ok_or(crate::Error::InvalidObfuscationSize)?;

    // 4. Compute the BLAKE3 HMAC on the encrypted data using the session key.
    let hmac = crypto::compute_hmac(&session.encryption_key, packet_header.nonce(), &encrypted);

    // 5. Assemble the final packet.
    let header_bytes = packet_header.to_bytes();
    let mut packet =
        Vec::with_capacity(obfuscation_size + header_bytes.len() + hmac.len() + encrypted.len());
    packet.extend_from_slice(obfuscation_header);
    packet.extend_from_slice(&header_bytes);
    packet.extend_from_slice(&hmac);
    packet.extend_from_slice(&encrypted);

    Ok(packet)
}

/// Unseals (verifies and decrypts) a single data packet from the stream.
///
/// This is the primary function for receiving data. It verifies the HMAC first,
/// then decrypts using ChaCha20-Poly1305.
pub fn unseal_stream_packet(
    session: &StreamSession,
    packet: &[u8],
    _debug_mode: bool,
) -> Result<Vec<u8>> {
    // 1. Parse the packet structure to separate components (zero-copy).
    let (header_bytes, hmac_bytes, encrypted_data, _obfuscation_size) =
        crypto::parse_packet(packet)?;

    let packet_header = PacketHeader::from_bytes(header_bytes)
        .ok_or(crate::Error::InvalidHeader)?;

    // 2. Verify the BLAKE3 HMAC using the decryption key. This prevents processing
    // tampered or invalid packets.

    if !crypto::verify_hmac(
        &session.decryption_key,
        packet_header.nonce(),
        encrypted_data,
        hmac_bytes,
    ) {
        return Err(crate::Error::HmacMismatch);
    }

    // 3. Check for replay attacks using a sliding window bitmask.
    let sequence = u64::from_le_bytes(packet_header.nonce()[0..8].try_into().unwrap());
    let mut replay_cache = session.replay_cache.lock().unwrap();
    if replay_cache.check_and_record(sequence) {
        return Err(crate::Error::ReplayDetected);
    }

    // 4. Decrypt the encrypted data using ChaCha20-Poly1305 with the decryption key.
    let plaintext = crypto::decrypt_with_chacha20poly1305(
        &session.decryption_key,
        packet_header.nonce(),
        encrypted_data,
    )?;

    Ok(plaintext)
}
// endregion: --- Per-Packet Crypto Functions

#[cfg(test)]
mod tests {
    use super::*;

    fn test_setup() -> (StreamSession, StreamSession) {
        let initial_seed = [0u8; 32];
        let key_manager = Arc::new(TemperKeyManager::new(initial_seed));
        let peer_id = [1u8; 32];
        let client_enc_key = key_manager.derive_connection_key(&[1u8; 32]);
        let client_dec_key = key_manager.derive_connection_key(&[2u8; 32]);

        let client_session =
            StreamSession::new(client_enc_key, client_dec_key, peer_id, key_manager.clone());

        // Server session has swapped keys
        let server_session =
            StreamSession::new(client_dec_key, client_enc_key, peer_id, key_manager.clone());
        (client_session, server_session)
    }

    #[test]
    fn test_seal_unseal_stream_roundtrip() {
        let (client_session, server_session) = test_setup();

        let plaintext = b"hello world from the stream";
        let obfuscation = vec![0u8; 32];

        // Seal the packet with the client's session
        let sealed_packet = seal_stream_packet(&client_session, plaintext, &obfuscation, true)
            .expect("seal should succeed");

        // Unseal the packet with the server's session
        let unsealed_plaintext = unseal_stream_packet(&server_session, &sealed_packet, true)
            .expect("unseal should succeed");

        assert_eq!(unsealed_plaintext, plaintext);
    }

    #[test]
    fn test_unseal_stream_tampered_hmac() {
        let (client_session, server_session) = test_setup();
        let plaintext = b"this is a test";
        let obfuscation = vec![0xCD; 32];

        let mut sealed_packet = seal_stream_packet(&client_session, plaintext, &obfuscation, true)
            .expect("seal should succeed");

        // Tamper with the HMAC (byte 40, for example)
        let hmac_start_index = obfuscation.len() + 23;
        sealed_packet[hmac_start_index] ^= 0xFF;

        let result = unseal_stream_packet(&server_session, &sealed_packet, true);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "HmacMismatch"
        );
    }

    #[test]
    fn test_unseal_stream_tampered_ciphertext() {
        let (client_session, server_session) = test_setup();
        let plaintext = b"this is another test";
        let obfuscation = vec![0xEF; 16];

        let mut sealed_packet = seal_stream_packet(&client_session, plaintext, &obfuscation, true)
            .expect("seal should succeed");

        // Tamper with the ciphertext
        let ciphertext_start_index = obfuscation.len() + 23 + 32;
        sealed_packet[ciphertext_start_index] ^= 0xFF;

        let result = unseal_stream_packet(&server_session, &sealed_packet, true);
        assert!(result.is_err());
        // HMAC will fail first, which is the correct behavior
        assert_eq!(
            result.unwrap_err().to_string(),
            "HmacMismatch"
        );
    }

    #[test]
    fn test_nonce_sequence_increases() {
        let (session, _) = test_setup();

        let nonce1 = session.next_nonce();
        let nonce2 = session.next_nonce();

        let seq1 = u64::from_le_bytes(nonce1[0..8].try_into().unwrap());
        let seq2 = u64::from_le_bytes(nonce2[0..8].try_into().unwrap());

        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
        assert_ne!(nonce1, nonce2);
    }
}
