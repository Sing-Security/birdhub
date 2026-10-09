// ============================================================================
// IDENTITY MODULE: a node's long-term Temper identity
// ============================================================================
//
// Identity used to be NetBird's: birdhub shelled out to `netbird status`,
// read an IP and a public key out of the mesh, and called that who it was.
// Every peer check downstream was then a check on an *address* — a CGNAT range
// test — which is to say a check anyone who can present that address passes.
//
// Here identity is a Temper keypair. A node is its ML-DSA-65 and SLH-DSA
// signing keys plus its concealment key; a peer is whoever presents a
// certificate over those keys that chains to the fleet CA (`ca.rs`). The
// address is only how the two reach each other.
//
// Two halves are persisted:
//
//   - The signing keypair, which is already serde-capable (`TemperKeypair`).
//   - A 32-byte *seed* for the concealment keypair, rather than the keypair
//     itself: `ConcealmentKeypair` deliberately hands out no way to read its
//     secret bytes back, and `TemperEntropy::from_seed` makes the keypair a
//     pure function of the seed. The seed is therefore exactly as secret as
//     the keypair and no more, and the type keeps its asymmetry.

use crate::Result;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use temper::ca::{ConcealmentBinding, SubjectKeys, TemperCertificate};
use temper::{
    generate_keypair, ConcealmentKeypair, ConcealmentPublicKey, PeerIdentity, TemperEntropy,
    TemperKeypair,
};

// region:    --- Types

/// What a node holds privately.
pub struct Identity {
    pub name: String,
    pub signing: TemperKeypair,
    pub concealment: ConcealmentKeypair,
}

/// What a node exports for the CA, and what the CA consumes.
///
/// The concealment half travels as its schema version and two public keys —
/// exactly the fields the certificate signs — so the exporter and the issuer
/// cannot disagree about what "the same key" means.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub name: String,
    pub peer: PeerIdentity,
    pub concealment: ConcealmentPublicKey,
}

/// The on-disk shape of [`Identity`]. Separate from `Identity` because the
/// concealment half is a seed here and a keypair there.
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    name: String,
    signing: TemperKeypair,
    concealment_seed: [u8; 32],
}

// endregion: --- Types

// region:    --- Implementation

impl Identity {
    /// Load the identity at `path`, generating and persisting one if the file
    /// does not exist yet.
    ///
    /// First-run generation is silent about where the key came from on
    /// purpose: there is exactly one source of entropy and it is the OS.
    pub fn load_or_create(path: impl AsRef<Path>, name: &str) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            return Self::load(path);
        }

        println!(
            "Identity: no key at {}, generating a new long-term identity...",
            path.display()
        );
        let mut rng = TemperEntropy::new()?;
        let signing = generate_keypair(&mut rng, name).map_err(crate::Error::custom_from_err)?;
        let mut concealment_seed = [0u8; 32];
        rng.fill_bytes(&mut concealment_seed);

        let stored = StoredIdentity {
            name: name.to_string(),
            signing,
            concealment_seed,
        };
        write_private(path, &postcard::to_allocvec(&stored)?)?;

        let identity = Self::from_stored(stored)?;
        println!(
            "Identity: generated. key_id={} concealment_id={}",
            identity.signing.key_id,
            identity.concealment.public().key_id
        );
        println!("Identity: this node now needs a certificate from the fleet CA:");
        println!(
            "  birdhub identity export --key {} --pub <name>.pub",
            path.display()
        );
        Ok(identity)
    }

    /// Load an identity that is expected to exist.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|e| {
            crate::Error::custom(format!(
                "failed to read identity '{}': {}",
                path.display(),
                e
            ))
        })?;
        let stored: StoredIdentity = postcard::from_bytes(&bytes).map_err(|e| {
            crate::Error::custom(format!(
                "failed to parse identity '{}': {}",
                path.display(),
                e
            ))
        })?;
        Self::from_stored(stored)
    }

    fn from_stored(stored: StoredIdentity) -> Result<Self> {
        let mut rng = TemperEntropy::from_seed(stored.concealment_seed);
        let concealment =
            ConcealmentKeypair::generate(&mut rng).map_err(crate::Error::custom_from_err)?;
        Ok(Self {
            name: stored.name,
            signing: stored.signing,
            concealment,
        })
    }

    /// This node's identity minus the secrets.
    ///
    /// The certificate field of the `PeerIdentity` is `None` here: this is
    /// the file the CA reads *before* a certificate exists, so there is
    /// nothing to embed — and once a certificate is issued it lives in its
    /// own file (`[identity] certificate`), where it can be replaced without
    /// touching the keys.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            name: self.name.clone(),
            peer: PeerIdentity {
                mldsa_pk: self.signing.mldsa_public_key.clone(),
                slhdsa_pk: self.signing.slhdsa_public_key.clone(),
                key_id: self.signing.key_id.clone(),
                certificate: None,
            },
            concealment: self.concealment.public(),
        }
    }

    /// This node's certified keys, in the grouping the certificate signs.
    ///
    /// Comparing a certificate against an identity is comparing these:
    /// grouping them here means the comparison cannot silently skip the
    /// concealment half, which is the half the certificate exists to bind
    /// and the half nothing else would notice was missing.
    pub fn certified_keys(&self) -> SubjectKeys {
        SubjectKeys {
            mldsa_public_key: self.signing.mldsa_public_key.clone(),
            slhdsa_public_key: self.signing.slhdsa_public_key.clone(),
            concealment: ConcealmentBinding::from_public_key(&self.concealment.public()),
        }
    }

    /// Write the public half to `path`, for the operator to carry to the CA.
    pub fn export_public(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let bytes = postcard::to_allocvec(&self.public())?;
        std::fs::write(path, &bytes).map_err(|e| {
            crate::Error::custom(format!(
                "failed to write public identity '{}': {}",
                path.display(),
                e
            ))
        })?;
        Ok(())
    }
}

impl PublicIdentity {
    /// Read a node's exported public identity (the CA's side of the handoff).
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|e| {
            crate::Error::custom(format!(
                "failed to read public identity '{}' (export it on the node with \
                 `birdhub identity export`): {}",
                path.display(),
                e
            ))
        })?;
        let published: Self = postcard::from_bytes(&bytes).map_err(|e| {
            crate::Error::custom(format!(
                "failed to parse public identity '{}' (re-export it on the node): {}",
                path.display(),
                e
            ))
        })?;
        Ok(published)
    }
}

// endregion: --- Implementation

// region:    --- Certificate checks

/// Check that `cert` certifies exactly this identity's keys.
///
/// A certificate for the wrong keys does not fail at startup — the node
/// starts, handshakes, and is refused by the *peer*, which reports "peer
/// certificate is not signed by the trusted CA"-shaped errors about a
/// certificate the operator believes is fine. This check moves that failure
/// to the node that holds the mismatched pair, where the fix is.
///
/// All three keys are compared. The concealment half is the one to keep an
/// eye on: a certificate that signs the wrong concealment key still verifies,
/// still matches the signing keys, and fails only at the first real
/// handshake, as "handshake refused" on the *other* machine.
pub fn check_certificate_matches_identity(
    identity: &Identity,
    cert: &TemperCertificate,
) -> Result<()> {
    let expected = identity.certified_keys();
    let certified = cert.subject_keys();
    if certified == expected {
        return Ok(());
    }

    let mut wrong = Vec::new();
    if certified.mldsa_public_key != expected.mldsa_public_key {
        wrong.push("ML-DSA signing key");
    }
    if certified.slhdsa_public_key != expected.slhdsa_public_key {
        wrong.push("SLH-DSA signing key");
    }
    if certified.concealment != expected.concealment {
        wrong.push("concealment key");
    }

    Err(crate::Error::custom(format!(
        "certificate '{}' (for '{}') does not certify this identity's {} — \
         re-export the identity and re-issue the certificate",
        cert.cert_id,
        cert.subject_id,
        wrong.join(", ")
    )))
}

// endregion: --- Certificate checks

// region:    --- Commands

/// `birdhub identity export` — write the public half for the CA.
///
/// Generates the keypair if `key_path` does not exist yet, so the very first
/// step on a new node is this one command rather than "start the service,
/// watch it fail on the missing certificate, then export". `name` is what the
/// generated key is named — prefer letting the service generate the key from
/// `[identity] name` when there is a config, and pass the same name here when
/// enrolling before first start.
pub fn cmd_export(key_path: &str, pub_path: &str, name: &str) -> Result<()> {
    let identity = Identity::load_or_create(key_path, name)?;
    identity.export_public(pub_path)?;
    println!(
        "Exported public identity '{}' (key_id={} concealment_id={}) to {}",
        identity.name,
        identity.signing.key_id,
        identity.concealment.public().key_id,
        pub_path
    );
    println!("  carry it to the CA machine and run `birdhub ca issue`");
    Ok(())
}

// endregion: --- Commands

// region:    --- Files

/// Write a file only the owner can read.
///
/// The identity file (and the CA key) is the whole of this node's authority,
/// so a world-readable one is a world-writable identity. Set on the handle
/// before any bytes are written rather than after, so there is no window in
/// which the file exists with default permissions.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                crate::Error::custom(format!("failed to create '{}': {}", parent.display(), e))
            })?;
        }
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|e| {
        crate::Error::custom(format!(
            "failed to create identity '{}': {}",
            path.display(),
            e
        ))
    })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

// endregion: --- Files

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{enroll, TempDir};

    /// The identity file holds secret keys; anyone who can read it can be
    /// this node. The mode is set on the handle before the first byte, so
    /// there is no window where the file exists world-readable.
    #[cfg(unix)]
    #[test]
    fn identity_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("perms");
        let path = dir.file("identity.key");
        Identity::load_or_create(&path, "node.example").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "identity file mode was {:o}",
            mode & 0o777
        );
    }

    #[test]
    fn exported_public_identity_roundtrips() {
        let e = enroll("export", 30);
        let path = e.dir.file("again.pub");
        e.identity.export_public(&path).unwrap();

        let loaded = PublicIdentity::load(&path).unwrap();
        assert_eq!(loaded.name, e.identity.name);
        assert_eq!(loaded.peer.key_id, e.identity.signing.key_id);
        assert_eq!(loaded.peer.mldsa_pk, e.identity.signing.mldsa_public_key);
        assert_eq!(
            loaded.concealment.key_id,
            e.identity.concealment.public().key_id
        );
        // The export is the CA's input, which predates any certificate.
        assert!(loaded.peer.certificate.is_none());
    }

    /// Exporting before first start must generate the key rather than fail:
    /// enrolling a node is otherwise "start it, watch it fail on the missing
    /// certificate, then export".
    #[test]
    fn export_generates_a_missing_key() {
        let dir = TempDir::new("export-first");
        let key = dir.file("identity.key");
        let pub_path = dir.file("node.pub");
        cmd_export(&key, &pub_path, "node.example").unwrap();

        assert!(std::path::Path::new(&key).exists(), "key was not generated");
        let published = PublicIdentity::load(&pub_path).unwrap();
        assert_eq!(published.name, "node.example");
        // A second export uses the existing key, not a fresh one.
        let first = published.peer.key_id;
        cmd_export(&key, &pub_path, "ignored").unwrap();
        assert_eq!(PublicIdentity::load(&pub_path).unwrap().peer.key_id, first);
    }

    /// The mistake this check exists for: a certificate issued for one
    /// keypair, next to the key file of another. Every differing half is
    /// named — reporting only the first would send the operator back for a
    /// second round trip after they fix one file.
    #[test]
    fn swapped_identity_names_every_differing_key() {
        let e = enroll("swapped", 30);
        let other = Identity::load_or_create(e.dir.file("other.key"), "other.example").unwrap();

        let err = check_certificate_matches_identity(&other, &e.cert)
            .unwrap_err()
            .to_string();
        for half in [
            "ML-DSA signing key",
            "SLH-DSA signing key",
            "concealment key",
        ] {
            assert!(err.contains(half), "error missing {}: {}", half, err);
        }
    }
}

// endregion: --- Tests
