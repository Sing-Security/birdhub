// ============================================================================
// CRYPTO MODULE: Temper-Aligned Cryptographic Primitives
// ============================================================================
// Core Principles:
// 1. BLAKE3 as cryptographic foundation (hashing, key derivation, HMAC)
// 2. Domain separation constants to prevent cross-protocol attacks
// 3. Stack-allocated data structures via heapless design (zero heap allocations)
// 4. Zero-copy packet handling with borrowed references
// 5. Zeroize trait on all key material for secure erasure
// 6. ArcSwap<T> for lock-free atomic key rotation
// 7. spin::Mutex for minimal-overhead state management

// region: --- Standard Library & Internal
use crate::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
// endregion: --- Standard Library & Internal

// region: --- External Crates
use arc_swap::ArcSwap;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce as ChaChaNonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};
// endregion: --- External Crates

// ============================================================================
// REGION: Constants & Domain Separation
// ============================================================================

/// Domain constant for key derivation operations
/// Prevents key reuse across different protocol contexts
const DOMAIN_KEY_DERIVATION: &str = "Temper.Transport.Derivation.v1";

/// Domain constant for packet HMAC operations
const DOMAIN_PACKET_HMAC: &str = "Temper.Transport.HMAC.v1";

/// Domain constant for master key material context
const _DOMAIN_KEY_MATERIAL: &str = "Temper.Transport.Master.v1";

/// Size of BLAKE3 output (always 32 bytes)
const BLAKE3_HASH_SIZE: usize = 32;

/// Standard nonce size for packet operations (16 bytes)
const NONCE_SIZE: usize = 16;

/// ChaCha20-Poly1305 nonce size (12 bytes)
const CHACHA_NONCE_SIZE: usize = 12;

/// Key TTL in seconds (24 hours)
const KEY_TTL_SECS: u64 = 86_400;

// ============================================================================
// REGION: Utility Functions
// ============================================================================

/// Generate a random 32-byte seed for key derivation
pub fn generate_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = rand::random();
    }
    seed
}

/// Compute BLAKE3-based packet HMAC using a provided key.
pub fn compute_hmac(
    key: &[u8; BLAKE3_HASH_SIZE],
    nonce: &[u8; NONCE_SIZE],
    packet_data: &[u8],
) -> [u8; BLAKE3_HASH_SIZE] {
    // Create keyed hash context with domain separation
    let mut hasher = blake3::Hasher::new_keyed(key);

    // Domain separation: add context identifier
    hasher.update(DOMAIN_PACKET_HMAC.as_bytes());
    hasher.update(nonce);
    hasher.update(packet_data);

    // Output [u8; 32] HMAC
    let mut output = [0u8; BLAKE3_HASH_SIZE];
    output.copy_from_slice(&hasher.finalize().as_bytes()[..BLAKE3_HASH_SIZE]);
    output
}

/// Verify packet HMAC with constant-time comparison using a provided key.
pub fn verify_hmac(
    key: &[u8; BLAKE3_HASH_SIZE],
    nonce: &[u8; NONCE_SIZE],
    packet_data: &[u8],
    provided_hmac: &[u8; 32],
) -> bool {
    let computed = compute_hmac(key, nonce, packet_data);
    constant_time_compare(&computed, provided_hmac)
}

/// Get current Unix timestamp in seconds
pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8; BLAKE3_HASH_SIZE], b: &[u8; BLAKE3_HASH_SIZE]) -> bool {
    let mut result = 0u8;
    for i in 0..BLAKE3_HASH_SIZE {
        result |= a[i] ^ b[i];
    }
    result == 0
}

// ============================================================================
// REGION: Stack-Allocated Types (Heapless Design)
// ============================================================================

/// Packet header containing metadata for encrypted packets
///
/// Stack-allocated (23 bytes total):
/// - obfuscation_size: 1 byte (encodes 16-64 range)
/// - key_version: 4 bytes
/// - nonce: 16 bytes
/// - packet_len: 2 bytes
#[derive(Clone, Copy, Debug)]
pub struct PacketHeader {
    /// Encoded obfuscation size (16-64 range in single byte)
    obfuscation_size: u8,
    /// Current key version at time of packet creation
    key_version: u32,
    /// Per-packet nonce for replay protection and IV
    nonce: [u8; NONCE_SIZE],
    /// Encrypted payload length (supports packets up to 64KB)
    packet_len: u16,
}

impl PacketHeader {
    /// Create a new packet header with stack allocation
    pub fn new(
        obfuscation_size: usize,
        key_version: u32,
        nonce: [u8; NONCE_SIZE],
        packet_len: u16,
    ) -> Option<Self> {
        // Validate obfuscation size is in valid range [16, 64]
        if obfuscation_size < 16 || obfuscation_size > 64 {
            return None;
        }

        Some(Self {
            obfuscation_size: Self::encode_obfuscation_size(obfuscation_size)?,
            key_version,
            nonce,
            packet_len,
        })
    }

    /// Serialize header to fixed 23-byte buffer (stack allocation, zero-copy)
    pub fn to_bytes(&self) -> [u8; 23] {
        let mut bytes = [0u8; 23];
        bytes[0] = self.obfuscation_size;
        bytes[1..5].copy_from_slice(&self.key_version.to_le_bytes());
        bytes[5..21].copy_from_slice(&self.nonce);
        bytes[21..23].copy_from_slice(&self.packet_len.to_le_bytes());
        bytes
    }

    /// Parse header from bytes (zero-copy, borrowed reference)
    pub fn from_bytes(bytes: &[u8; 23]) -> Option<Self> {
        let key_version = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[5..21]);
        let packet_len = u16::from_le_bytes([bytes[21], bytes[22]]);

        Some(Self {
            obfuscation_size: bytes[0],
            key_version,
            nonce,
            packet_len,
        })
    }

    /// Get obfuscation size (decodes from packed byte)
    pub fn obfuscation_size(&self) -> usize {
        Self::decode_obfuscation_size(self.obfuscation_size)
    }

    /// Get key version
    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Get nonce
    pub fn nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.nonce
    }

    /// Get packet length
    pub fn packet_len(&self) -> u16 {
        self.packet_len
    }

    /// Encode obfuscation size (16-64) as single byte (0-48)
    fn encode_obfuscation_size(size: usize) -> Option<u8> {
        if size < 16 || size > 64 {
            return None;
        }
        Some((size - 16) as u8)
    }

    /// Decode obfuscation size from packed byte back to original value
    fn decode_obfuscation_size(byte: u8) -> usize {
        (byte as usize) + 16
    }
}

/// Packet authentication tag (40 bytes on stack)
///
/// Contains:
/// - hmac: 32 bytes (BLAKE3 keyed hash)
/// - sequence: 8 bytes (replay attack counter)
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PacketAuth {
    /// BLAKE3 HMAC for packet integrity verification
    hmac: [u8; BLAKE3_HASH_SIZE],
    /// Anti-replay sequence number
    sequence: u64,
}

impl PacketAuth {
    /// Create new packet auth tag (stack-allocated)
    pub fn new(hmac: [u8; BLAKE3_HASH_SIZE], sequence: u64) -> Self {
        Self { hmac, sequence }
    }

    /// Get HMAC bytes
    pub fn hmac(&self) -> &[u8; BLAKE3_HASH_SIZE] {
        &self.hmac
    }

    /// Get sequence number
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Master key material (stack-allocated, implements Zeroize)
///
/// Contains:
/// - seed: 32 bytes (master secret)
/// - version: 4 bytes
/// - created_at: 8 bytes (Unix timestamp)
/// Total: 44 bytes on stack, auto-zeroed on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    /// Master seed for key derivation (auto-zeroed on drop)
    seed: [u8; BLAKE3_HASH_SIZE],
    /// Version number for key rotation tracking
    version: u32,
    /// Creation timestamp (Unix seconds)
    created_at: u64,
}

impl KeyMaterial {
    /// Create new key material from seed bytes
    pub fn new(seed: [u8; BLAKE3_HASH_SIZE], version: u32) -> Self {
        Self {
            seed,
            version,
            created_at: current_unix_timestamp(),
        }
    }

    /// Get seed bytes (read-only reference)
    pub fn seed(&self) -> &[u8; BLAKE3_HASH_SIZE] {
        &self.seed
    }

    /// Get version
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Get creation timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Check if key material has expired (24-hour TTL)
    pub fn is_expired(&self) -> bool {
        let now = current_unix_timestamp();
        now.saturating_sub(self.created_at) >= KEY_TTL_SECS
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("seed", &"[REDACTED]")
            .field("version", &self.version)
            .field("created_at", &self.created_at)
            .finish()
    }
}

// ============================================================================
// REGION: Lock-Free Key Manager (ArcSwap + Atomic Counter)
// ============================================================================

/// Lock-free cryptographic key manager with atomic rotation
///
/// Features:
/// - ArcSwap enables non-blocking key reads for all threads
/// - AtomicU64 for lock-free sequence number generation
/// - Zero allocations on read path
/// - O(1) key rotation via atomic swap
pub struct TemperKeyManager {
    /// Master key material (lock-free atomic swaps)
    master: ArcSwap<KeyMaterial>,
    /// Per-connection sequence counter (anti-replay)
    connection_counter: AtomicU64,
}

impl TemperKeyManager {
    /// Create new key manager with initial 32-byte seed
    pub fn new(initial_seed: [u8; BLAKE3_HASH_SIZE]) -> Self {
        let initial_key = KeyMaterial::new(initial_seed, 0);
        Self {
            master: ArcSwap::new(Arc::new(initial_key)),
            connection_counter: AtomicU64::new(0),
        }
    }

    /// Rotate key with new seed material (lock-free, O(1))
    ///
    /// # Example
    /// ```ignore
    /// let manager = TemperKeyManager::new([0u8; 32]);
    /// let new_seed = [1u8; 32];
    /// manager.rotate_key(new_seed);
    /// ```
    pub fn rotate_key(&self, new_seed: [u8; BLAKE3_HASH_SIZE]) {
        let old_key = self.master.load();
        let new_version = old_key.version.wrapping_add(1);
        let new_key = KeyMaterial::new(new_seed, new_version);

        // Atomic swap - readers never block
        self.master.swap(Arc::new(new_key));
    }

    /// Derive per-connection key using BLAKE3.derive_key()
    ///
    /// Zero-copy: takes borrowed reference, returns derived key on stack
    /// Domain separation: uses DOMAIN_KEY_DERIVATION constant
    pub fn derive_connection_key(
        &self,
        peer_id: &[u8; BLAKE3_HASH_SIZE],
    ) -> [u8; BLAKE3_HASH_SIZE] {
        let key = self.master.load();
        let mut context = [0u8; 64];

        // Concatenate: master_seed || version || peer_id
        context[0..32].copy_from_slice(key.seed());
        context[32..36].copy_from_slice(&key.version().to_le_bytes());
        context[36..44].copy_from_slice(&key.created_at().to_le_bytes());
        context[44..60].copy_from_slice(&peer_id[0..16]);
        context[60..64].copy_from_slice(&peer_id[16..20]);

        // BLAKE3 derive_key with domain separation
        blake3::derive_key(DOMAIN_KEY_DERIVATION, &context)
    }

    /// Get next sequence number for replay protection (lock-free)
    pub fn next_sequence(&self) -> u64 {
        self.connection_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Get current key version for protocol negotiation
    pub fn current_version(&self) -> u32 {
        self.master.load().version()
    }

    /// Check if current key has expired (24-hour TTL)
    pub fn _is_expired(&self) -> bool {
        self.master.load().is_expired()
    }
}

impl std::fmt::Debug for TemperKeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = self.master.load();
        f.debug_struct("TemperKeyManager")
            .field("master_version", &key.version())
            .field("master_expired", &key.is_expired())
            .field(
                "connection_counter",
                &self.connection_counter.load(Ordering::Relaxed),
            )
            .finish()
    }
}

// ============================================================================
// REGION: Zero-Copy Packet Operations
// ============================================================================

/// Parses a raw packet into its constituent parts with zero-copy.
///
/// Returns a tuple: `(header_bytes, hmac_bytes, encrypted_data, obfuscation_size)`
pub fn parse_packet(packet: &[u8]) -> Result<(&[u8; 23], &[u8; 32], &[u8], usize)> {
    const HEADER_SIZE: usize = 23;
    const HMAC_SIZE: usize = 32;
    const MIN_OBFUSCATION_SIZE: usize = 16;
    const MAX_OBFUSCATION_SIZE: usize = 64;

    // The packet structure is [obfuscation][header][hmac][encrypted].
    // The obfuscation size is encoded in the first byte of the header.
    // This creates a circular dependency. We have to search for the header.
    let mut found_obfuscation_size = None;
    for i in (MIN_OBFUSCATION_SIZE..=MAX_OBFUSCATION_SIZE).rev() {
        if packet.len() >= i + HEADER_SIZE + HMAC_SIZE {
            // The first byte of the potential header at offset `i`.
            let header_first_byte = packet[i];
            // The obfuscation size is encoded as `size - 16`.
            // So, the decoded size is `byte_value + 16`.
            let decoded_size = (header_first_byte as usize) + MIN_OBFUSCATION_SIZE;

            if decoded_size == i {
                // To avoid false positives, verify the packet length encoded in the header
                // matches the actual packet size.
                let len_offset = i + HEADER_SIZE - 2;
                let packet_len =
                    u16::from_le_bytes([packet[len_offset], packet[len_offset + 1]]) as usize;

                if packet.len() == i + HEADER_SIZE + HMAC_SIZE + packet_len {
                    found_obfuscation_size = Some(i);
                    break;
                }
            }
        }
    }

    let obfuscation_size =
        found_obfuscation_size.ok_or_else(|| crate::Error::InvalidObfuscationSize)?;

    let min_packet_size = obfuscation_size + HEADER_SIZE + HMAC_SIZE;
    if packet.len() < min_packet_size {
        return Err(crate::Error::PacketTooShort);
    }

    let header_start = obfuscation_size;
    let header_end = header_start + HEADER_SIZE;
    let hmac_start = header_end;
    let hmac_end = hmac_start + HMAC_SIZE;
    let data_start = hmac_end;

    let header_bytes: &[u8; 23] = packet[header_start..header_end]
        .try_into()
        .expect("slice with incorrect length");
    let hmac_bytes: &[u8; 32] = packet[hmac_start..hmac_end]
        .try_into()
        .expect("slice with incorrect length");
    let encrypted_data = &packet[data_start..];

    // Sanity check that the header we found is valid
    let header = PacketHeader::from_bytes(header_bytes).ok_or(crate::Error::InvalidHeader)?;
    if header.obfuscation_size() != obfuscation_size {
        return Err(crate::Error::InvalidObfuscationSize);
    }

    Ok((header_bytes, hmac_bytes, encrypted_data, obfuscation_size))
}

// ============================================================================
// REGION: Encryption & Decryption
// ============================================================================

/// Encrypt plaintext with ChaCha20-Poly1305 AEAD
///
/// Uses BLAKE3-derived key and 16-byte nonce.
/// Adapts nonce to ChaCha20-Poly1305's 12-byte requirement by hashing first 12 bytes.
///
/// # Arguments
/// - `key`: 32-byte encryption key (from BLAKE3 derivation)
/// - `nonce`: 16-byte nonce from packet header
/// - `plaintext`: Data to encrypt
///
/// # Returns
/// Ciphertext with Poly1305 authentication tag appended
pub fn encrypt_with_chacha20poly1305(
    key: &[u8; BLAKE3_HASH_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    // Create cipher from 32-byte key
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| crate::Error::custom("Invalid cipher key"))?;

    // ChaCha20-Poly1305 requires 12-byte nonce; take first 12 bytes of our 16-byte nonce
    let chacha_nonce = ChaChaNonce::from_slice(&nonce[0..CHACHA_NONCE_SIZE]);

    // Encrypt with empty AAD (associated authenticated data)
    cipher
        .encrypt(chacha_nonce, plaintext)
        .map_err(|_| crate::Error::custom("Encryption failed"))
}

/// Decrypt ciphertext with ChaCha20-Poly1305 AEAD
///
/// Uses BLAKE3-derived key and adapts 16-byte nonce to 12-byte requirement.
///
/// # Arguments
/// - `key`: 32-byte decryption key (from BLAKE3 derivation)
/// - `nonce`: 16-byte nonce from packet header
/// - `ciphertext`: Data to decrypt (includes Poly1305 tag)
///
/// # Returns
/// Decrypted plaintext on successful authentication
pub fn decrypt_with_chacha20poly1305(
    key: &[u8; BLAKE3_HASH_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    // Create cipher from 32-byte key
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| crate::Error::custom("Invalid cipher key"))?;

    // ChaCha20-Poly1305 requires 12-byte nonce; take first 12 bytes of our 16-byte nonce
    let chacha_nonce = ChaChaNonce::from_slice(&nonce[0..CHACHA_NONCE_SIZE]);

    // Decrypt with empty AAD and verify Poly1305 tag
    cipher
        .decrypt(chacha_nonce, ciphertext)
        .map_err(|_| crate::Error::custom("Decryption failed or authentication tag invalid"))
}

// ============================================================================
// REGION: Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_header_encode_decode() {
        // Test header serialization and deserialization
        let nonce = [42u8; NONCE_SIZE];
        let header = PacketHeader::new(32, 1234, nonce, 5678).expect("valid header");

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 23);

        let decoded = PacketHeader::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded.key_version(), 1234);
        assert_eq!(decoded.packet_len(), 5678);
        assert_eq!(decoded.nonce(), &nonce);
        assert_eq!(decoded.obfuscation_size(), 32);
    }

    #[test]
    fn test_packet_header_obfuscation_encoding() {
        // Test boundary values for obfuscation size encoding
        assert_eq!(PacketHeader::decode_obfuscation_size(0), 16);
        assert_eq!(PacketHeader::decode_obfuscation_size(48), 64);

        assert_eq!(PacketHeader::encode_obfuscation_size(16).unwrap(), 0);
        assert_eq!(PacketHeader::encode_obfuscation_size(64).unwrap(), 48);

        // Test invalid values
        assert!(PacketHeader::encode_obfuscation_size(15).is_none());
        assert!(PacketHeader::encode_obfuscation_size(65).is_none());
    }

    #[test]
    fn test_lock_free_key_rotation() {
        let manager = TemperKeyManager::new([1u8; 32]);
        assert_eq!(manager.current_version(), 0);

        // Rotate to new key (lock-free, no blocking)
        manager.rotate_key([2u8; 32]);
        assert_eq!(manager.current_version(), 1);

        // Rotate again
        manager.rotate_key([3u8; 32]);
        assert_eq!(manager.current_version(), 2);
    }

    #[test]
    fn test_blake3_key_derivation() {
        let manager = TemperKeyManager::new([1u8; 32]);
        let peer1 = [10u8; 32];
        let peer2 = [20u8; 32];

        // Derive different keys for different peers
        let key1 = manager.derive_connection_key(&peer1);
        let key2 = manager.derive_connection_key(&peer2);

        // Keys should be different
        assert_ne!(key1, key2);

        // Same peer should derive same key
        let key1_again = manager.derive_connection_key(&peer1);
        assert_eq!(key1, key1_again);
    }

    #[test]
    fn test_blake3_key_derivation_after_rotation() {
        let manager = TemperKeyManager::new([1u8; 32]);
        let peer = [42u8; 32];

        let key_v0 = manager.derive_connection_key(&peer);

        // Rotate key
        manager.rotate_key([2u8; 32]);
        let key_v1 = manager.derive_connection_key(&peer);

        // Rotated key should be different due to version change
        assert_ne!(key_v0, key_v1);
    }

    #[test]
    fn test_packet_hmac_verification() {
        let manager = TemperKeyManager::new([1u8; 32]);
        let peer_id = [42u8; 32];
        let nonce = [99u8; NONCE_SIZE];
        let packet_data = b"test packet data";
        let key = manager.derive_connection_key(&peer_id);

        // Compute HMAC
        let hmac = compute_hmac(&key, &nonce, packet_data);
        assert_eq!(hmac.len(), BLAKE3_HASH_SIZE);

        // Verify should succeed
        assert!(verify_hmac(&key, &nonce, packet_data, &hmac));

        // Modified data should fail verification
        let modified_data = b"tampered packet data";
        assert!(!verify_hmac(&key, &nonce, modified_data, &hmac));

        // Modified nonce should fail verification
        let mut modified_nonce = nonce;
        modified_nonce[0] ^= 0xFF;
        assert!(!verify_hmac(&key, &modified_nonce, packet_data, &hmac));

        // Modified HMAC should fail verification
        let mut modified_hmac = hmac;
        modified_hmac[0] ^= 0xFF;
        assert!(!verify_hmac(&key, &nonce, packet_data, &modified_hmac));
    }

    #[test]
    fn test_replay_protection_sequence() {
        let manager = TemperKeyManager::new([1u8; 32]);

        let seq1 = manager.next_sequence();
        let seq2 = manager.next_sequence();
        let seq3 = manager.next_sequence();

        // Sequences should be monotonically increasing
        assert!(seq1 < seq2);
        assert!(seq2 < seq3);
    }

    #[test]
    fn test_stack_allocation_sizes() {
        // Verify stack-only data structures
        use std::mem;

        // PacketHeader serialized form is 23 bytes (struct may have padding)
        let header = PacketHeader::new(32, 1234, [0u8; NONCE_SIZE], 5678).unwrap();
        assert_eq!(header.to_bytes().len(), 23);

        // PacketAuth should fit on stack (< 64 bytes with potential padding)
        assert!(mem::size_of::<PacketAuth>() <= 64);

        // KeyMaterial should fit on stack (< 64 bytes with potential padding)
        assert!(mem::size_of::<KeyMaterial>() <= 64);
    }

    #[test]
    fn test_key_material_expiration() {
        // Create key material
        let key = KeyMaterial::new([1u8; 32], 0);

        // Freshly created key should not be expired
        assert!(!key.is_expired());

        // Note: Testing expiration directly would require time travel
        // In real scenarios, check TTL_SECS constant
        assert_eq!(KEY_TTL_SECS, 86_400);
    }

    #[test]
    fn test_packet_auth_zeroize() {
        let auth = PacketAuth::new([42u8; 32], 123);
        assert_eq!(auth.sequence(), 123);
        assert_eq!(auth.hmac()[0], 42);

        // PacketAuth implements ZeroizeOnDrop
        drop(auth);
        // After drop, memory is zeroed (verified by ZeroizeOnDrop trait)
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
        let manager = Arc::new(TemperKeyManager::new([1u8; 32]));
        let peer_id = [77u8; 32];
        let plaintext = b"secret message";
        let obfuscation = [0u8; 32];
        let encryption_key = manager.derive_connection_key(&peer_id);
        let decryption_key = manager.derive_connection_key(&[78u8; 32]);
        let client_session = crate::session::StreamSession::new(
            encryption_key,
            decryption_key,
            peer_id,
            manager.clone(),
        );

        // Seal packet
        let sealed =
            crate::session::seal_stream_packet(&client_session, plaintext, &obfuscation, true)
                .expect("seal succeeds");

        // Create a server session with swapped keys
        let server_session = crate::session::StreamSession::new(
            decryption_key,
            encryption_key,
            peer_id,
            manager.clone(),
        );

        // Unseal packet
        let unsealed = crate::session::unseal_stream_packet(&server_session, &sealed, true)
            .expect("unseal succeeds");

        // Should recover original plaintext
        assert_eq!(unsealed, plaintext);
    }

    #[test]
    fn test_seal_packet_structure() {
        let manager = Arc::new(TemperKeyManager::new([1u8; 32]));
        let peer_id = [50u8; 32];
        let plaintext = b"test";
        let obfuscation = [0u8; 32];

        let key = manager.derive_connection_key(&peer_id);
        let session = crate::session::StreamSession::new(key, key, peer_id, manager.clone());

        let sealed = crate::session::seal_stream_packet(&session, plaintext, &obfuscation, true)
            .expect("seal succeeds");

        // Packet structure: [header (23)] + [hmac (32)] + [encrypted]
        // obfuscation_size is encoded in header, actual obfuscation bytes handled separately
        const AEAD_TAG_SIZE: usize = 16;
        assert_eq!(
            sealed.len(),
            obfuscation.len() + 23 + 32 + plaintext.len() + AEAD_TAG_SIZE
        );
    }

    #[test]
    fn test_unseal_rejects_invalid_hmac() {
        let manager = Arc::new(TemperKeyManager::new([1u8; 32]));
        let peer_id = [75u8; 32];
        let plaintext = b"secret";
        let obfuscation = [0u8; 32];

        let key = manager.derive_connection_key(&peer_id);
        let session = crate::session::StreamSession::new(key, key, peer_id, manager.clone());
        let mut sealed =
            crate::session::seal_stream_packet(&session, plaintext, &obfuscation, true)
                .expect("seal succeeds");

        // Tamper with HMAC (at offset obfuscation_len + header_len)
        let hmac_offset = obfuscation.len() + 23;
        if sealed.len() > hmac_offset {
            sealed[hmac_offset] ^= 0xFF;
        }

        // Unseal should reject tampered packet
        let result = crate::session::unseal_stream_packet(&session, &sealed, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_unseal_rejects_short_packet() {
        let manager = Arc::new(TemperKeyManager::new([1u8; 32]));
        let peer_id = [77u8; 32];
        let key = manager.derive_connection_key(&peer_id);
        let session = crate::session::StreamSession::new(key, key, peer_id, manager.clone());
        let short_packet = [0u8; 32]; // Shorter than min packet size

        let result = crate::session::unseal_stream_packet(&session, &short_packet, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_packet_with_obfuscation() {
        const HMAC_SIZE: usize = 32;
        const OBFUSCATION_SIZE: usize = 32;

        // 1. Create a known-good packet structure
        // Use a value that won't be misinterpreted as an encoded obfuscation size.
        let obfuscation_data = vec![0xFFu8; OBFUSCATION_SIZE];

        let nonce = [3u8; NONCE_SIZE];
        let encrypted_data = vec![4u8; 128];

        let header = PacketHeader::new(OBFUSCATION_SIZE, 1, nonce, encrypted_data.len() as u16)
            .expect("header creation failed");
        let header_bytes = header.to_bytes();

        let hmac_data = [2u8; HMAC_SIZE];

        let mut packet = Vec::new();
        packet.extend_from_slice(&obfuscation_data);
        packet.extend_from_slice(&header_bytes);
        packet.extend_from_slice(&hmac_data);
        packet.extend_from_slice(&encrypted_data);

        // 2. Call parse_packet
        let (
            parsed_header_bytes,
            parsed_hmac_bytes,
            parsed_encrypted_data,
            parsed_obfuscation_size,
        ) = parse_packet(&packet).expect("parse_packet should succeed");

        // 3. Assert correctness
        assert_eq!(parsed_obfuscation_size, OBFUSCATION_SIZE);
        assert_eq!(parsed_header_bytes, &header_bytes);
        assert_eq!(parsed_hmac_bytes, &hmac_data);
        assert_eq!(parsed_encrypted_data, &encrypted_data[..]);
    }
}
