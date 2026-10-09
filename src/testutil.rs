// ============================================================================
// TEST UTIL: scratch directories for tests that touch the filesystem
// ============================================================================
//
// The CA flow is a chain of files — key, public identity, certificate — so
// testing it means writing files somewhere. A directory named after the
// process and a counter, removed on drop, is the whole requirement; pulling
// in a dependency for those ten lines would put a crate in the tree that
// ships in `birdhub`'s dependency list for tests that never run in the
// binary.

use crate::ca::{self, CaPublicKeys};
use crate::identity::Identity;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use temper::ca::TemperCertificate;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A scratch directory that removes itself when the test ends.
pub struct TempDir(PathBuf);

impl TempDir {
    /// Create a uniquely named directory under the system temp dir.
    ///
    /// The pid separates concurrent test *processes*; the counter separates
    /// concurrent tests inside one. Leftovers from a crashed run cannot
    /// collide with a live one because the counter only ever counts up.
    pub fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "birdhub-test-{}-{}-{}",
            tag,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create scratch directory");
        Self(path)
    }

    /// A path inside the directory, as the `&str`/`String` the CLI takes.
    pub fn file(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One node, fully enrolled — the state every test about certificates starts
/// from, produced by running the real CLI functions rather than by building
/// the structs by hand, so the tests exercise the flow operators will.
pub struct Enrollment {
    pub dir: TempDir,
    pub identity: Identity,
    pub ca: CaPublicKeys,
    pub cert: TemperCertificate,
}

/// One CA with many members: the two-node tests need one fleet, not two
/// separate enrollment chains. Members are issued from the same CA key, so
/// each verifies the other's certificate exactly as production would.
pub struct Fleet {
    pub dir: TempDir,
    ca_key: String,
    pub ca: CaPublicKeys,
}

impl Fleet {
    pub fn new(tag: &str) -> Self {
        let dir = TempDir::new(tag);
        let ca_key = dir.file("ca.key");
        let ca_pub = dir.file("ca.pub");
        ca::cmd_init(&ca_key, &ca_pub, &format!("{}-ca", tag)).expect("ca init");
        let ca = CaPublicKeys::load(&ca_pub).expect("load ca.pub");
        Self { dir, ca_key, ca }
    }

    /// A new identity, certified by this fleet's CA.
    pub fn enroll(&self, name: &str) -> (Identity, TemperCertificate) {
        let identity = Identity::load_or_create(self.dir.file(&format!("{}.key", name)), name)
            .expect("identity");
        let published = self.dir.file(&format!("{}.pub", name));
        identity.export_public(&published).expect("export");
        let cert_path = self.dir.file(&format!("{}.cert", name));
        ca::cmd_issue(&self.ca_key, &published, 30, &cert_path).expect("issue");
        let cert = ca::load_certificate(&cert_path).expect("load certificate");
        (identity, cert)
    }
}

/// CA init → identity → export → issue, in a fresh directory.
pub fn enroll(tag: &str, days: u64) -> Enrollment {
    let dir = TempDir::new(tag);
    let ca_key = dir.file("ca.key");
    let ca_pub = dir.file("ca.pub");
    ca::cmd_init(&ca_key, &ca_pub, &format!("{}-ca", tag)).expect("ca init");

    let identity =
        Identity::load_or_create(dir.file("node.key"), "node.example").expect("identity");
    let published = dir.file("node.pub");
    identity.export_public(&published).expect("export");

    let cert_path = dir.file("node.cert");
    ca::cmd_issue(&ca_key, &published, days, &cert_path).expect("issue");

    let ca = CaPublicKeys::load(&ca_pub).expect("load ca.pub");
    let cert = ca::load_certificate(&cert_path).expect("load certificate");

    Enrollment {
        dir,
        identity,
        ca,
        cert,
    }
}
