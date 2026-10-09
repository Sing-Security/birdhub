// ============================================================================
// CA MODULE: enrollment — which nodes are members of this fleet
// ============================================================================
//
// Enrollment used to be a file copy: the operator carried the hub's published
// keys to every client and pinned them there. That scales as O(nodes²) hand
// copies, and every copy is a chance to pin a stale or wrong key — which is
// why the file-copy model only ever worked for the two-machine case and
// production fleets all grow an identity server sooner or later.
//
// Here the fleet has a CA instead. A node's keys are certified once, by the
// CA, in a `TemperCertificate` that signs both halves of the node's identity
// — its signing keys and its concealment key — plus the name and the validity
// window. Every node then needs exactly two files it did not generate itself:
//
//   - `ca.pub`, the CA's public keys. The whole of the trust model: certify
//     nothing else, and nothing else can be trusted.
//   - its own `<name>.cert`, the proof it carries into every handshake.
//
// A client additionally holds the hub's `hub.cert` — not because it cannot
// verify it (it can, with `ca.pub`) but because "a certificate signed by our
// CA" and "the hub we meant" are different questions, and the second one
// deserves a byte-exact answer.
//
// Revocation is the grant table on the hub (see `hub.rs`) plus certificate
// expiry here; temper certificates are not revocable individually yet.

use crate::identity::{write_private, PublicIdentity};
use crate::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use temper::ca::{verify_certificate, ConcealmentBinding, SubjectKeys, TemperCertificate};
use temper::{TemperCa, TemperEntropy, TemperKeypair};

// region:    --- Constants

/// How far a certificate is backdated at issuance, in seconds.
///
/// Clocks on different machines disagree by seconds, not minutes, and a
/// certificate checked `At(now)` by a peer whose clock is a minute behind
/// would otherwise be "not valid until" and refuse a handshake that is
/// otherwise fine. The window is not a security boundary down to the second;
/// the backdate makes it stop pretending to be one.
const CLOCK_SKEW_SECS: u64 = 300;

/// Seconds in a day, for the `--days` lifetime.
const DAY_SECS: u64 = 24 * 60 * 60;

// endregion: --- Constants

// region:    --- Trust anchor

/// The CA's public half — everything a node needs to verify any peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaPublicKeys {
    /// Human-readable CA name (`issuer_id` of every certificate it signs).
    pub name: String,
    pub mldsa_public_key: Vec<u8>,
    pub slhdsa_public_key: Vec<u8>,
}

impl CaPublicKeys {
    /// Load the trust anchor from `path` (postcard, as written by `ca init`).
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|e| {
            crate::Error::custom(format!(
                "failed to read CA public keys '{}': {}",
                path.display(),
                e
            ))
        })?;
        let keys: Self = postcard::from_bytes(&bytes).map_err(|e| {
            crate::Error::custom(format!(
                "failed to parse CA public keys '{}': {}",
                path.display(),
                e
            ))
        })?;
        Ok(keys)
    }

    /// Write the trust anchor to `path`. Public material, so no mode games.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let bytes = postcard::to_allocvec(self).map_err(crate::Error::custom_from_err)?;
        std::fs::write(path, &bytes).map_err(|e| {
            crate::Error::custom(format!(
                "failed to write CA public keys '{}': {}",
                path.display(),
                e
            ))
        })?;
        Ok(())
    }

    /// Verify a certificate against this trust anchor, including the validity
    /// window at `now_secs`.
    ///
    /// Both halves matter and for different reasons: the seal proves the CA
    /// signed *something*, the window proves it meant it for now. Used for
    /// fail-fast checks at startup; the handshake re-checks both per session
    /// through `PeerPolicy::Cert`.
    pub fn verify(&self, cert: &TemperCertificate, now_secs: u64) -> Result<()> {
        let signed = verify_certificate(cert, &self.mldsa_public_key, &self.slhdsa_public_key)
            .map_err(crate::Error::custom_from_err)?;
        if !signed {
            return Err(crate::Error::custom(format!(
                "certificate for '{}' is not signed by CA '{}'",
                cert.subject_id, self.name
            )));
        }
        cert.check_validity(now_secs)
            .map_err(crate::Error::custom_from_err)
    }
}

// endregion: --- Trust anchor

// region:    --- Certificates

/// Load a certificate from `path` (postcard of `TemperCertificate`).
pub fn load_certificate(path: impl AsRef<Path>) -> Result<TemperCertificate> {
    let path = path.as_ref();
    let bytes = std::fs::read(path).map_err(|e| {
        crate::Error::custom(format!(
            "failed to read certificate '{}': {}",
            path.display(),
            e
        ))
    })?;
    TemperCertificate::from_bytes(&bytes).map_err(|e| {
        crate::Error::custom(format!(
            "failed to parse certificate '{}': {}",
            path.display(),
            e
        ))
    })
}

/// Write a certificate to `path`. Public material.
pub fn write_certificate(path: impl AsRef<Path>, cert: &TemperCertificate) -> Result<()> {
    let path = path.as_ref();
    let bytes = cert.to_bytes().map_err(crate::Error::custom_from_err)?;
    std::fs::write(path, &bytes).map_err(|e| {
        crate::Error::custom(format!(
            "failed to write certificate '{}': {}",
            path.display(),
            e
        ))
    })?;
    Ok(())
}

// endregion: --- Certificates

// region:    --- Commands

/// `birdhub ca init` — generate a CA keypair.
pub fn cmd_init(key_path: &str, pub_path: &str, name: &str) -> Result<()> {
    if Path::new(key_path).exists() {
        return Err(crate::Error::custom(format!(
            "refusing to overwrite existing CA key '{}' — a new CA key invalidates \
             every certificate the old one signed",
            key_path
        )));
    }

    let mut rng = TemperEntropy::new()?;
    let ca = TemperCa::new(&mut rng, name).map_err(crate::Error::custom_from_err)?;

    write_private(Path::new(key_path), &postcard::to_allocvec(&ca.keypair)?)?;

    let public = CaPublicKeys {
        name: name.to_string(),
        mldsa_public_key: ca.keypair.mldsa_public_key.clone(),
        slhdsa_public_key: ca.keypair.slhdsa_public_key.clone(),
    };
    public.save(pub_path)?;

    println!("CA '{}' created.", name);
    println!(
        "  private key: {}  (keep this off every node; it is the fleet)",
        key_path
    );
    println!("  public keys: {}  (copy this to every node)", pub_path);
    Ok(())
}

/// `birdhub ca issue` — certify a node's published keys.
///
/// Reads the subject's `[[public identity]]` file — written by `birdhub
/// identity export` on the subject itself — and issues a certificate binding
/// the name, both signing keys, and the concealment key for `days`.
pub fn cmd_issue(
    ca_key_path: &str,
    identity_pub_path: &str,
    days: u64,
    out_path: &str,
) -> Result<()> {
    let key_bytes = std::fs::read(ca_key_path).map_err(|e| {
        crate::Error::custom(format!("failed to read CA key '{}': {}", ca_key_path, e))
    })?;
    let keypair: TemperKeypair = postcard::from_bytes(&key_bytes).map_err(|e| {
        crate::Error::custom(format!("failed to parse CA key '{}': {}", ca_key_path, e))
    })?;
    let ca = TemperCa { keypair };

    let subject = PublicIdentity::load(identity_pub_path)?;

    // Probe the concealment key before certifying it. `encapsulate` parses
    // both public halves the way a real initiator will; a malformed key that
    // got certified would fail every handshake in a way that looks like a
    // network problem, not a bad file.
    let mut rng = TemperEntropy::new()?;
    subject
        .concealment
        .encapsulate(&mut rng, b"certification probe")
        .map_err(|e| {
            crate::Error::custom(format!(
                "concealment key in '{}' does not parse: {}",
                identity_pub_path, e
            ))
        })?;

    let keys = SubjectKeys {
        mldsa_public_key: subject.peer.mldsa_pk.clone(),
        slhdsa_public_key: subject.peer.slhdsa_pk.clone(),
        concealment: ConcealmentBinding::from_public_key(&subject.concealment),
    };

    let not_before = crate::time::now_secs().saturating_sub(CLOCK_SKEW_SECS);
    let lifetime = days
        .checked_mul(DAY_SECS)
        .ok_or_else(|| crate::Error::custom(format!("--days {} is out of range", days)))?;
    let not_after = not_before.saturating_add(lifetime);

    let cert = ca
        .issue_certificate(&mut rng, &subject.name, &keys, not_before, not_after)
        .map_err(crate::Error::custom_from_err)?;
    write_certificate(out_path, &cert)?;

    println!(
        "Issued certificate for '{}': id={} valid {}..{} ({} days)",
        cert.subject_id, cert.cert_id, cert.not_before, cert.not_after, days
    );
    println!(
        "  copy it to the node as its [identity] certificate = \"{}\"",
        out_path
    );
    Ok(())
}

// endregion: --- Commands

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{enroll, TempDir};
    use crate::time::now_secs;

    /// The whole point of the CA: one file of public keys verifies every
    /// member, and the certificate certifies exactly the keys the node holds
    /// — including the concealment half.
    #[test]
    fn enrollment_roundtrip_verifies() {
        let e = enroll("roundtrip", 30);

        assert_eq!(e.cert.schema_version, 2);
        assert_eq!(e.cert.subject_id, "node.example");
        assert_eq!(e.cert.issuer_id, "roundtrip-ca");
        assert_eq!(e.cert.subject_keys(), e.identity.certified_keys());

        e.ca.verify(&e.cert, now_secs())
            .expect("issued cert verifies");
    }

    #[test]
    fn another_cas_certificate_is_rejected() {
        let a = enroll("fleet-a", 30);
        let b = enroll("fleet-b", 30);

        // Positive control first: each CA verifies its own certificate, so
        // the cross-check below cannot pass because both fail everything.
        a.ca.verify(&a.cert, now_secs()).unwrap();
        b.ca.verify(&b.cert, now_secs()).unwrap();

        let err = b.ca.verify(&a.cert, now_secs()).unwrap_err().to_string();
        assert!(err.contains("not signed by CA"), "error was: {}", err);
        assert!(err.contains("fleet-b-ca"), "error was: {}", err);
    }

    /// `--days 0` issues a certificate that expired before it was written;
    /// the validity window must be what rejects it, since the seal is
    /// perfectly valid.
    #[test]
    fn expired_certificate_is_rejected() {
        let e = enroll("expired", 0);

        let err = e.ca.verify(&e.cert, now_secs()).unwrap_err().to_string();
        assert!(err.contains("expired"), "error was: {}", err);
    }

    #[test]
    fn init_refuses_to_overwrite_an_existing_ca() {
        let dir = TempDir::new("reinit");
        let key = dir.file("ca.key");
        let public = dir.file("ca.pub");
        cmd_init(&key, &public, "first").unwrap();

        let err = cmd_init(&key, &public, "second").unwrap_err().to_string();
        assert!(err.contains("refusing to overwrite"), "error was: {}", err);
    }

    /// A certificate certifies the keys it was handed. If it is handed
    /// anything other than this node's keys, the node must detect it — the
    /// concealment half first among them, because a certificate with the
    /// wrong concealment key verifies perfectly and fails silently.
    #[test]
    fn certificate_for_other_keys_names_the_missing_half() {
        let mut e = enroll("mismatch", 30);

        // Positive control: the untampered pair matches, so the failures
        // below are about the tampering and nothing else.
        crate::identity::check_certificate_matches_identity(&e.identity, &e.cert).unwrap();

        e.cert.concealment.mlkem_public_key[0] ^= 1;
        let err = crate::identity::check_certificate_matches_identity(&e.identity, &e.cert)
            .unwrap_err()
            .to_string();
        assert!(err.contains("concealment key"), "error was: {}", err);

        e.cert.concealment.mlkem_public_key[0] ^= 1;
        e.cert.mldsa_public_key[0] ^= 1;
        let err = crate::identity::check_certificate_matches_identity(&e.identity, &e.cert)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ML-DSA signing key"), "error was: {}", err);
    }
}

// endregion: --- Tests
