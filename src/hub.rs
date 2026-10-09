// ============================================================================
// HUB MODULE: the relay's server end
// ============================================================================
//
// One listener — the data plane — one session per client, and two questions
// asked of every session:
//
//   1. *Who is this?* Answered by the handshake itself: `PeerPolicy::Cert`
//      refuses any peer that does not present a certificate chaining to the
//      fleet CA, for a covered name, inside its validity window. Failure
//      costs the caller a cookie verification before anything expensive runs.
//   2. *What may they dial?* Answered by the grant table, keyed by the
//      certificate's subject id. No grant, no session; a grant lists exact
//      `host:port` targets and nothing else, so the hub's network position is
//      reachable only along the paths an operator wrote down. The answer is
//      applied per stream, before the dial, for every conversation the
//      session opens — not once for the session.
//
// The old build had a third surface — an unauthenticated `/auth` endpoint
// that handed out the concealment key so a stranger could start a handshake —
// and an `allowed_key_ids` list whose empty default admitted everyone. Both
// are gone: the certificate file replaced the first, and "no grant" denying
// replaced the second. This module no longer speaks HTTP at all.

use crate::ca::{self, CaPublicKeys};
use crate::config::{AppConfig, GrantConfig, HubServerConfig};
use crate::error::Result;
use crate::events::{EventLog, Kind};
use crate::identity::{check_certificate_matches_identity, Identity};
use crate::mux::Mux;
use crate::registry::PeerRegistry;
use crate::relay;
use crate::time::now_secs;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use temper::ca::TemperCertificate;
use temper::transport::{Listener, ResponderConfig};
use temper::{CertValidity, PeerPolicy, SessionCookie, TemperEntropy};

// region:    --- Types

/// One live session with the hub, as the fleet view sees it.
pub struct SessionInfo {
    pub session_id: u64,
    /// The certificate subject — the name the grant table is keyed by.
    pub subject: String,
    pub key_id: String,
    /// The certificate presented at the handshake: what the inspector shows
    /// in full, and where its validity window lives.
    pub certificate: TemperCertificate,
    pub since_unix: u64,
    /// Conversations open right now. A stream is one local connection on the
    /// client's side, so this is what "busy" looks like from here.
    pub streams_open: AtomicU64,
    /// The operator's off switch, set by `run_hub` once the session's mux
    /// exists. `None` only in the sliver between the board entry being made
    /// and the relay task running.
    mux: Mutex<Option<Mux>>,
}

impl SessionInfo {
    /// End the whole session: the mux driver drops the socket, every stream
    /// ends, and the peer sees the hub hang up — after which it reconnects
    /// and is subject to whatever the roster says *now*. `false` when the
    /// relay task has not published its mux yet; the kicker says "try again
    /// in a moment" rather than pretending it did something.
    pub fn kick(&self) -> bool {
        let Some(mux) = self.mux.lock().expect("session mux lock").clone() else {
            return false;
        };
        mux.shutdown();
        true
    }

    /// The relay task's first act: publish the mux the kicker uses.
    pub(crate) fn set_mux(&self, mux: Mux) {
        *self.mux.lock().expect("session mux lock") = Some(mux);
    }
}

/// The hub's live sessions, by session id.
///
/// Keyed by session id rather than by subject even though there is one
/// session per subject in practice: the id is what a session already knows
/// about itself, so an entry never has to be told what it is called, and a
/// session ending can name exactly the entry it owns.
#[derive(Default)]
pub struct SessionBoard {
    sessions: Mutex<BTreeMap<u64, Arc<SessionInfo>>>,
}

impl SessionBoard {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn insert(&self, info: SessionInfo) -> Arc<SessionInfo> {
        let info = Arc::new(info);
        self.sessions
            .lock()
            .expect("session board lock")
            .insert(info.session_id, info.clone());
        info
    }

    pub(crate) fn remove(&self, session_id: u64) {
        self.sessions
            .lock()
            .expect("session board lock")
            .remove(&session_id);
    }

    /// Make the entry for a freshly accepted session. The mux starts `None`:
    /// it exists once the relay task has split the session, and the sliver
    /// between the two is exactly what `SessionInfo::kick` reports as "not
    /// active yet".
    pub(crate) fn add(
        &self,
        session_id: u64,
        subject: &str,
        key_id: &str,
        certificate: TemperCertificate,
        since_unix: u64,
    ) -> Arc<SessionInfo> {
        self.insert(SessionInfo {
            session_id,
            subject: subject.to_string(),
            key_id: key_id.to_string(),
            certificate,
            since_unix,
            streams_open: AtomicU64::new(0),
            mux: Mutex::new(None),
        })
    }

    /// The live sessions, oldest first — the order the fleet table shows,
    /// because the session up longest is the one an operator tends to be
    /// looking for. Sorted by connection time, not by session id: the id is
    /// the handshake's, not the clock's.
    pub fn snapshot(&self) -> Vec<Arc<SessionInfo>> {
        let mut sessions: Vec<Arc<SessionInfo>> = self
            .sessions
            .lock()
            .expect("session board lock")
            .values()
            .cloned()
            .collect();
        sessions.sort_by_key(|info| (info.since_unix, info.session_id));
        sessions
    }

    pub fn get(&self, session_id: u64) -> Option<Arc<SessionInfo>> {
        self.sessions
            .lock()
            .expect("session board lock")
            .get(&session_id)
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.sessions.lock().expect("session board lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Everything the hub's per-session tasks share, and everything a frontend
/// reads: the event log, who is connected, and what they may ask for.
pub struct HubShared {
    pub events: Arc<EventLog>,
    /// Who the hub is — the About view and `/status` read it; the run loop
    /// uses it for the handshakes.
    pub identity: Arc<Identity>,
    /// The hub's own certificate, as verified at startup.
    pub certificate: TemperCertificate,
    /// Who is connected right now: what pairing (`@peer/<subject>`) and
    /// certificate lookups (`@cert/<subject>`) consult. Entries live exactly
    /// as long as the session that made them.
    pub registry: Arc<PeerRegistry>,
    /// The sessions the hub is serving, for the fleet view and for kicking.
    pub sessions: Arc<SessionBoard>,
    /// The authorization table: certified name → exact targets. Lookups
    /// happen after the handshake proves the name, and a session is handed
    /// the list it started with (see `relay::run_hub`).
    ///
    /// Behind a `RwLock` because the table is no longer fixed at startup:
    /// the control API replaces it on a roster edit or a reload, and the
    /// replace must be atomic — a handshake may be looking up a subject at
    /// the same moment. The read side (handshakes, views) is the common one.
    /// Crate-visible so the API's tests can build a shared state directly;
    /// writes go through `replace_grants` even then.
    pub(crate) grants: RwLock<BTreeMap<String, Vec<String>>>,
    /// Where the config file lives, so a roster edit knows what to rewrite
    /// and a reload what to re-read.
    pub config_path: String,
}

impl HubShared {
    /// The grant rows as written, in subject order — the roster view's data,
    /// and what a reload replaces.
    pub fn grants_snapshot(&self) -> Vec<(String, Vec<String>)> {
        self.grants
            .read()
            .expect("grants lock")
            .iter()
            .map(|(client, targets)| (client.clone(), targets.clone()))
            .collect()
    }

    /// The targets one subject may ask for, or `None` when no grant names it.
    /// `Some(vec![])` is a serve-only row: admitted, may ask for nothing.
    pub fn targets_for(&self, subject: &str) -> Option<Vec<String>> {
        self.grants
            .read()
            .expect("grants lock")
            .get(subject)
            .cloned()
    }

    /// Swap the whole authorization table at once.
    ///
    /// The swap is what makes a roster edit reach running sessions without
    /// racing them: a handshake either reads the old table or the new one,
    /// never a mix. Sessions already up keep the list they were handed —
    /// admission applies to the *next* session, and an operator who wants
    /// the edit to reach a client that is already connected kicks its
    /// session (`SessionInfo::kick`) so the client reconnects under the new
    /// roster.
    pub fn replace_grants(&self, grants: BTreeMap<String, Vec<String>>) {
        *self.grants.write().expect("grants lock") = grants;
    }
}

pub struct Hub {
    identity: Arc<Identity>,
    certificate: TemperCertificate,
    ca: CaPublicKeys,
    server: HubServerConfig,
    /// The control API's address, if the config writes one.
    control: Option<crate::config::ControlConfig>,
    shared: Arc<HubShared>,
}

// endregion: --- Types

// region:    --- Hub

impl Hub {
    /// Build a hub from a parsed configuration — identity, certificates,
    /// trust anchors and grants checked — without binding anything yet.
    ///
    /// Split from `run` so a frontend can hold the hub's state (board,
    /// registry, events) before the listener exists, which is what lets the
    /// console render a hub whose data plane failed to bind.
    pub fn build(config: AppConfig, config_path: &str, events: Arc<EventLog>) -> Result<Self> {
        let identity = Identity::load_or_create(
            config.identity.key_file.clone(),
            &config.identity.name.clone(),
        )?;

        let certificate = ca::load_certificate(&config.identity.certificate)?;
        check_certificate_matches_identity(&identity, &certificate)?;

        let ca = CaPublicKeys::load(&config.ca.public)?;
        // The hub's own certificate must chain to the CA it is about to trust
        // others through — otherwise it serves a fleet it is not a member of,
        // and every client refusal looks like a network problem.
        ca.verify(&certificate, now_secs())?;

        let server = config.hub_server.unwrap_or_default();
        let grants = build_grants(&config.grants);
        let control = config.control.clone();

        let identity = Arc::new(identity);
        let shared = Arc::new(HubShared {
            events,
            identity: identity.clone(),
            certificate: certificate.clone(),
            registry: Arc::new(PeerRegistry::new()),
            sessions: Arc::new(SessionBoard::new()),
            grants: RwLock::new(grants),
            config_path: config_path.to_string(),
        });

        Ok(Self {
            identity,
            certificate,
            ca,
            server,
            control,
            shared,
        })
    }

    pub fn shared(&self) -> Arc<HubShared> {
        self.shared.clone()
    }

    /// The `[control]` section as written, for the caller that serves the API.
    pub fn control_config(&self) -> Option<crate::config::ControlConfig> {
        self.control.clone()
    }

    /// Run until the process is killed.
    pub async fn run(self) -> Result<()> {
        let events = self.shared.events.clone();
        events.info(
            Kind::Other,
            format!(
                "Hub: serving as '{}' cert={} valid {}..{}",
                self.certificate.subject_id,
                self.certificate.cert_id,
                self.certificate.not_before,
                self.certificate.not_after
            ),
        );
        events.info(
            Kind::Other,
            format!("Hub: trust anchor CA '{}'", self.ca.name),
        );
        if self.shared.grants_snapshot().is_empty() {
            events.info(
                Kind::Other,
                "Hub: no [[grants]] — every client will be refused (this is the default)",
            );
        }
        for (client, targets) in self.shared.grants_snapshot() {
            if targets.is_empty() {
                // A serve-only node's row: admitted and reachable by peers,
                // permitted to ask for nothing.
                events.info(
                    Kind::Other,
                    format!(
                        "Hub: grant '{}' → (serves only; may ask for nothing)",
                        client
                    ),
                );
            } else {
                events.info(
                    Kind::Other,
                    format!("Hub: grant '{}' → {}", client, targets.join(", ")),
                );
            }
        }

        let mut listener = Listener::bind_with_replay(
            self.server.data_address.as_str(),
            self.server.handshake_ttl_secs,
            self.server.replay_capacity,
        )
        .await?;
        events.info(
            Kind::Listener,
            format!("Hub: data plane on {}", self.server.data_address),
        );

        let cookie = SessionCookie::new(random_cookie_secret(), self.server.handshake_ttl_secs);
        let cookie = self.server.require_cookie.then_some(cookie);
        if cookie.is_some() {
            events.info(
                Kind::Listener,
                "Hub: anti-DoS cookie required (one extra round trip per session)",
            );
        }

        loop {
            let now = now_secs();
            // Rebuilt per session so the validity window is checked against
            // the clock as it is now, not as it was at startup: a hub that
            // outlives a certificate must stop accepting it.
            let policy = PeerPolicy::Cert {
                ca_mldsa_pk: self.ca.mldsa_public_key.clone(),
                ca_slhdsa_pk: self.ca.slhdsa_public_key.clone(),
                validity: CertValidity::At(now),
            };
            let config = ResponderConfig {
                keypair: &self.identity.signing,
                certificate: Some(&self.certificate),
                policy: &policy,
                concealment: &self.identity.concealment,
                cookie: cookie.as_ref(),
                // Overwritten by the listener, which is the only party that
                // can see the address the peer actually connected from.
                peer_tag: None,
                now_secs: now,
            };

            let mut rng = TemperEntropy::new()?;
            let session = match listener.accept(&mut rng, &config).await {
                Ok(session) => session,
                Err(e) => {
                    // A failed handshake is an ordinary event on a public
                    // port. Say so and keep the listener.
                    events.warn(Kind::Refusal, format!("Hub: handshake refused: {}", e));
                    continue;
                }
            };

            let peer = session.peer_identity();
            let key_id = peer.key_id.clone();
            let Some(cert) = peer.certificate.as_deref() else {
                // Unreachable while the policy above is `Cert`, which refuses
                // a peer presenting none. Dropping the session is still the
                // right shape for the impossible branch: no certificate,
                // nothing to look up.
                events.warn(
                    Kind::Refusal,
                    format!("Hub: peer {} presented no certificate; dropping", key_id),
                );
                continue;
            };
            let subject = cert.subject_id.clone();

            let Some(targets) = self.shared.targets_for(&subject) else {
                // Authenticated but not enrolled. The session is dropped
                // before the relay sees it, and nothing about the grant
                // table is told to a node that has no entry in it.
                //
                // The hint matters: a node that only serves has no targets
                // to write down, and its operator is the one most likely to
                // read "no grant names it" as "this is not about me".
                events.warn(
                    Kind::Refusal,
                    format!(
                        "Hub: refusing '{}' (key_id={}) — no grant names it \
                         (a node that only serves still needs an entry, with no targets)",
                        subject, key_id
                    ),
                );
                continue;
            };

            let session_id = session.session_id();
            events.info(
                Kind::Session,
                format!(
                    "Hub: session {} with '{}' (key_id={})",
                    session_id, subject, key_id
                ),
            );
            // The session outlives any one conversation: `run_hub` multiplexes
            // every stream the client opens over it, each checked against the
            // granted list *this* session was handed (relay.rs) — and
            // registers it for as long as it serves it, which is what "this
            // peer is online" means.
            let shared = self.shared.clone();
            let info = shared
                .sessions
                .add(session_id, &subject, &key_id, cert.clone(), now);
            tokio::spawn(async move {
                if let Err(e) = relay::run_hub(session, info, targets, shared.clone()).await {
                    shared
                        .events
                        .warn(Kind::Session, format!("Hub: session ended: {}", e));
                }
            });
        }
    }
}

// endregion: --- Hub

// region:    --- Entry point

/// Build a hub from a parsed configuration and run it, printing its log —
/// the headless binary's entry point. The control API, if `[control]` is
/// configured, is served from the same runtime.
pub async fn start(path: &str, config: AppConfig) -> Result<()> {
    let hub = Hub::build(config, path, EventLog::console())?;
    crate::control::spawn(
        crate::control::ApiState::Hub {
            shared: hub.shared(),
        },
        hub.control_config(),
    )
    .await?;
    hub.run().await
}

/// Fold the grant list into its lookup shape.
///
/// Duplicate names were rejected in `AppConfig::validate`; this collects
/// without re-checking. Shared with `control.rs`, which applies the same
/// fold to a roster it just validated.
pub(crate) fn build_grants(grants: &[GrantConfig]) -> BTreeMap<String, Vec<String>> {
    grants
        .iter()
        .map(|grant| (grant.client.clone(), grant.targets.clone()))
        .collect()
}

// endregion: --- Entry point

// region:    --- Helpers

fn random_cookie_secret() -> [u8; 32] {
    // Seeded from the OS through the same DRBG the identity uses, so the
    // cookie secret is no weaker than the keys beside it.
    use rand_core::RngCore;
    let mut rng = TemperEntropy::new().expect("OS entropy for the cookie secret");
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    secret
}

// endregion: --- Helpers
