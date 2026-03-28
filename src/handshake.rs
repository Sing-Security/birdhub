//! # VISP Connection Handshake Module
//!
//! Implements the 3-phase cryptographic handshake using Temper's primitives:
//! 1.  **Phase 1: Hub Authentication (Seal)** - The client verifies a post-quantum signature
//!     (Seal) from the hub to authenticate it. This is computationally expensive but performed
//!     only once at the start of a connection.
//! 2.  **Phase 2: Session Key Establishment (Envelope)** - The client and hub use a hybrid
//!     post-quantum key encapsulation mechanism (Envelope) to securely agree on a shared
//!     session secret. This provides forward secrecy.
//! 3.  **Phase 3: Key Derivation (BLAKE3)** - Both parties use the shared secret from the
//!     Envelope to derive symmetric keys for the fast, streaming encryption phase (ChaCha20-Poly1305).
//!
//! This process ensures a mutually authenticated, forward-secure, and post-quantum resistant
//! session key before any application data is transmitted.

// region: --- Imports
use crate::error::{Error, Result};
use chacha20poly1305::aead::rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use temper::{
    envelope::{self, Envelope, EnvelopeKeypair},
    seal::{self, Seal, TemperKeypair},
    TemperEntropy,
};
// endregion: --- Imports

// region: --- Domain Separation Constants
/// Domain separation constant for deriving the client-to-hub streaming key.
const DOMAIN_C2H_KEY: &str = "VISP.SESSION.C2H.V1";
/// Domain separation constant for deriving the hub-to-client streaming key.
const DOMAIN_H2C_KEY: &str = "VISP.SESSION.H2C.V1";
// endregion: --- Domain Separation Constants

// region: --- Handshake Data Structures

/// Contains the cryptographic materials for the established session.
/// These keys are used for the fast ChaCha20-Poly1305 streaming encryption phase.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    /// The primary 32-byte shared secret agreed upon via the Envelope.
    pub _shared_secret: [u8; 32],
    /// The symmetric key for encrypting data from the client to the hub.
    pub client_to_hub_key: [u8; 32],
    /// The symmetric key for encrypting data from the hub to the client.
    pub hub_to_client_key: [u8; 32],
}

/// The initial message sent from the Hub to the Client.
/// It contains a post-quantum signature (Seal) to prove the Hub's identity,
/// and the public keys needed for the client to establish a shared secret.
#[derive(Serialize, Deserialize, Debug)]
pub struct HubIdentitySeal {
    /// The Temper Seal, which contains a signature over the Hub's ephemeral public key.
    pub seal: Seal,
    /// The public part of the Hub's ephemeral EnvelopeKeypair for this session.
    /// This is the concatenation of mlkem_public_key || x25519_public_key.
    pub envelope_pk_bytes: Vec<u8>,
    /// The ML-DSA public key used to sign the Seal, for client-side verification.
    pub mldsa_pk_bytes: Vec<u8>,
    /// The SLH-DSA public key used to sign the Seal, for client-side verification.
    pub slhdsa_pk_bytes: Vec<u8>,
    /// The Hub's NetBird public key for explicit identity binding.
    pub hub_netbird_pubkey: String,
}

/// The response message from the Client to the Hub.
/// It contains the Temper Envelope, which encapsulates the session's shared secret,
/// encrypted with the Hub's public key, and the client's NetBird identity.
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientHandshake {
    /// The Temper Envelope containing the encrypted shared secret.
    pub envelope: Envelope,
    /// The Client's NetBird public key for explicit identity binding.
    pub client_netbird_pubkey: String,
}

// endregion: --- Handshake Data Structures

// region: --- Hub-Side Handshake Logic

/// **(Hub-Side)** Creates the initial `HubIdentitySeal` message to send to a new client.
///
/// This function generates an ephemeral keypair for the session, creates content that
/// includes the public part of that keypair, and signs it with the Hub's long-term
/// signing keypair to produce a `Seal`. It also includes the Hub's NetBird public key
/// for explicit cryptographic binding to the mesh identity.
///
/// # Arguments
/// * `rng` - A mutable reference to a `TemperEntropy` generator.
/// * `hub_signing_keypair` - The Hub's long-term `TemperKeypair` used for signing.
/// * `ephemeral_envelope_keypair` - The session-specific `EnvelopeKeypair` generated for this connection.
/// * `hub_netbird_pubkey` - The Hub's NetBird public key for identity binding.
///
/// # Returns
/// A `HubIdentitySeal` ready to be serialized and sent to the client.
pub fn create_hub_identity_seal(
    rng: &mut TemperEntropy,
    hub_signing_keypair: &TemperKeypair,
    ephemeral_envelope_keypair: &EnvelopeKeypair,
    hub_netbird_pubkey: &str,
) -> Result<HubIdentitySeal> {
    // The content to be signed is the public part of the ephemeral envelope key.
    // This is the concatenation of mlkem_public_key || x25519_public_key.
    // This proves to the client that the hub owns the corresponding private key.
    let mut content_to_seal = Vec::new();
    content_to_seal.extend_from_slice(&ephemeral_envelope_keypair.mlkem_public_key);
    content_to_seal.extend_from_slice(&ephemeral_envelope_keypair.x25519_public_key);

    // Create the post-quantum signature (Seal) over the content.
    let context: BTreeMap<String, String> = BTreeMap::new();
    let seal = seal::create_seal(rng, &content_to_seal, hub_signing_keypair, context)
        .map_err(Error::custom_from_err)?;

    // Store the public key bytes for client verification
    let mut envelope_pk_bytes = Vec::new();
    envelope_pk_bytes.extend_from_slice(&ephemeral_envelope_keypair.mlkem_public_key);
    envelope_pk_bytes.extend_from_slice(&ephemeral_envelope_keypair.x25519_public_key);

    Ok(HubIdentitySeal {
        seal,
        envelope_pk_bytes,
        mldsa_pk_bytes: hub_signing_keypair.mldsa_public_key.clone(),
        slhdsa_pk_bytes: hub_signing_keypair.slhdsa_public_key.clone(),
        hub_netbird_pubkey: hub_netbird_pubkey.to_string(),
    })
}

/// **(Hub-Side)** Decapsulates the client's envelope to retrieve the shared secret and derive session keys.
///
/// This function is called after the hub receives the `ClientHandshake` message. It uses its
/// ephemeral private key to decrypt the envelope and establish the symmetric session keys.
///
/// # Arguments
/// * `client_handshake` - The `ClientHandshake` message received from the client.
/// * `ephemeral_envelope_keypair` - The session-specific `EnvelopeKeypair` whose public part was sent to the client.
///
/// # Returns
/// The derived `SessionKeys` for this connection.
pub fn decapsulate_client_envelope(
    client_handshake: &ClientHandshake,
    ephemeral_envelope_keypair: &EnvelopeKeypair,
) -> Result<SessionKeys> {
    // Decapsulate the envelope to get the shared secret. This will fail if the
    // private key does not match the public key used for encapsulation.
    let shared_secret_bytes =
        envelope::decapsulate(&client_handshake.envelope, ephemeral_envelope_keypair)
            .map_err(Error::custom_from_err)?;

    // The shared secret from ML-KEM is 32 bytes, which is what we need.
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&shared_secret_bytes);

    // Derive the final session keys from the shared secret.
    Ok(derive_session_keys(&shared_secret))
}

// endregion: --- Hub-Side Handshake Logic

// region: --- Client-Side Handshake Logic

/// **(Client-Side)** Verifies the hub's identity and creates an envelope to establish the session.
///
/// This function performs two critical steps:
/// 1. Verifies the received `Seal` to ensure the hub is authentic.
/// 2. If authentic, it encapsulates a newly generated shared secret within an `Envelope`
///    and prepares it to be sent back to the hub, including the client's NetBird identity.
///
/// # Arguments
/// * `rng` - A mutable reference to a `TemperEntropy` generator.
/// * `hub_identity` - The `HubIdentitySeal` message received from the hub.
/// * `client_netbird_pubkey` - The client's NetBird public key for identity binding.
///
/// # Returns
/// A tuple containing the derived `SessionKeys` and the `ClientHandshake` message to send to the hub.
pub fn verify_hub_seal_and_create_envelope(
    rng: &mut TemperEntropy,
    hub_identity: &HubIdentitySeal,
    client_netbird_pubkey: &str,
) -> Result<(SessionKeys, ClientHandshake)> {
    // The content that the hub *should* have signed is the public envelope key it sent.
    let expected_sealed_content = &hub_identity.envelope_pk_bytes;

    // Verify the seal. This checks both the ML-DSA and SLH-DSA signatures.
    // It cryptographically proves that the sender of this message possesses the
    // private keys corresponding to the public keys provided.
    let verification_result = seal::verify_seal(
        expected_sealed_content,
        &hub_identity.seal,
        &hub_identity.mldsa_pk_bytes,
        &hub_identity.slhdsa_pk_bytes,
    )
    .map_err(Error::custom_from_err)?;

    if !verification_result.valid {
        return Err(Error::HandshakeFailed);
    }

    // --- Seal is valid, proceed to create the envelope ---

    // Create a new 32-byte shared secret that we will send to the hub.
    let mut shared_secret = [0u8; 32];
    rng.fill_bytes(&mut shared_secret);

    // Reconstruct the hub's envelope keypair from the public bytes sent to us.
    // We create a temporary keypair with the public keys from the hub and dummy secret keys.
    // The encapsulate function only uses the public key fields, so the dummy secrets are safe.
    //
    // The envelope_pk_bytes from the hub is: mlkem_public_key || x25519_public_key
    // ML-KEM-1024 public key is 1568 bytes, X25519 is 32 bytes
    const MLKEM_PK_SIZE: usize = 1568; // ML-KEM-1024 public key size (3 * 512 + 32)
    const X25519_PK_SIZE: usize = 32;
    const EXPECTED_PK_SIZE: usize = MLKEM_PK_SIZE + X25519_PK_SIZE;

    let pk_bytes = &hub_identity.envelope_pk_bytes;
    if pk_bytes.len() != EXPECTED_PK_SIZE {
        return Err(Error::Custom(format!(
            "Invalid hub public key length: expected {}, got {}",
            EXPECTED_PK_SIZE,
            pk_bytes.len()
        )));
    }

    let (mlkem_pk_bytes, x25519_pk_bytes) = pk_bytes.split_at(MLKEM_PK_SIZE);

    // Create a temporary EnvelopeKeypair with the public keys from the hub.
    // The secret keys and other fields are left empty/dummy since they're not used during encapsulation.
    let hub_envelope_pk = EnvelopeKeypair {
        schema_version: 1u16,         // Dummy value, not used in encapsulation
        mlkem_secret_key: Vec::new(), // Dummy, not used
        mlkem_public_key: mlkem_pk_bytes.to_vec(),
        x25519_secret_key: Vec::new(), // Dummy, not used
        x25519_public_key: x25519_pk_bytes.to_vec(),
        key_id: String::new(), // Dummy, not used
    };

    // Encapsulate the shared secret. This encrypts it so that only the hub
    // (which has the corresponding private key) can open it.
    let envelope = envelope::encapsulate(rng, &shared_secret, &hub_envelope_pk)
        .map_err(Error::custom_from_err)?;

    // Derive our own copy of the session keys.
    let session_keys = derive_session_keys(&shared_secret);

    let client_handshake = ClientHandshake {
        envelope,
        client_netbird_pubkey: client_netbird_pubkey.to_string(),
    };

    Ok((session_keys, client_handshake))
}

// endregion: --- Client-Side Handshake Logic

// region: --- Helper Functions

/// Derives symmetric session keys from a single shared secret using BLAKE3.
///
/// This uses domain separation to ensure that the client-to-hub and hub-to-client
/// keys are cryptographically distinct, even though they originate from the same secret.
///
/// # Arguments
/// * `shared_secret` - A 32-byte secret agreed upon via the `Envelope` exchange.
///
/// # Returns
/// A `SessionKeys` struct containing the derived keys.
fn derive_session_keys(shared_secret: &[u8; 32]) -> SessionKeys {
    let client_to_hub_key = blake3::derive_key(DOMAIN_C2H_KEY, shared_secret);
    let hub_to_client_key = blake3::derive_key(DOMAIN_H2C_KEY, shared_secret);

    SessionKeys {
        _shared_secret: *shared_secret,
        client_to_hub_key,
        hub_to_client_key,
    }
}

// endregion: --- Helper Functions
