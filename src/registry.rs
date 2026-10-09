// ============================================================================
// REGISTRY MODULE: who is connected to the hub right now
// ============================================================================
//
// Presence is a property of a live session, not of a stored record: a peer is
// in this table exactly while its hub session is being served, and the entry
// is removed when that session ends. Nothing here survives a restart, which
// is the point — a stale presence is worse than no presence, because it makes
// the hub pair two nodes and fail at the handshake instead of saying "not
// connected".
//
// The certificate rides along because the hub already has it: every peer
// presents one at its handshake, so the hub can answer `@cert/<subject>`
// without any node having to publish anything. A requester verifies that
// certificate against the CA before using it, so the hub vouches for nothing
// — it is a distribution point for signed public documents, and a liar only
// earns a failed handshake.
//
// One peer, one session, is the intended shape. The session id is stored and
// checked on removal so a reconnect cannot be un-registered by the tail of the
// session it replaced — the race that would otherwise make a peer flap out of
// the table every time its connection was re-established.

use crate::mux::Mux;
use std::collections::HashMap;
use std::sync::Mutex;
use temper::ca::TemperCertificate;

/// One peer's presence, as the fleet view reads it — everything an operator
/// asks about a connected peer except the mux itself.
#[derive(Clone, Debug)]
pub struct PeerSnapshot {
    pub subject: String,
    pub session_id: u64,
    pub cert_id: String,
    pub since_unix: u64,
}

struct Entry {
    session_id: u64,
    certificate: TemperCertificate,
    mux: Mux,
    since_unix: u64,
}

#[derive(Default)]
pub struct PeerRegistry {
    peers: Mutex<HashMap<String, Entry>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a peer's live session, replacing any previous session from the
    /// same subject. `since_unix` is when the session this entry describes
    /// arrived — passed in rather than read here so it is the same instant the
    /// rest of that session's record carries.
    pub fn insert(
        &self,
        subject: &str,
        session_id: u64,
        since_unix: u64,
        certificate: TemperCertificate,
        mux: Mux,
    ) {
        self.peers.lock().expect("peer registry lock").insert(
            subject.to_string(),
            Entry {
                session_id,
                certificate,
                mux,
                since_unix,
            },
        );
    }

    /// Every connected peer, sorted by subject.
    ///
    /// Sorted because the map is a `HashMap`: an unsorted snapshot would list
    /// the same fleet in a different order every time a view polled it.
    pub fn snapshot(&self) -> Vec<PeerSnapshot> {
        let peers = self.peers.lock().expect("peer registry lock");
        let mut rows: Vec<PeerSnapshot> = peers
            .iter()
            .map(|(subject, entry)| PeerSnapshot {
                subject: subject.clone(),
                session_id: entry.session_id,
                cert_id: entry.certificate.cert_id.clone(),
                since_unix: entry.since_unix,
            })
            .collect();
        rows.sort_by(|a, b| a.subject.cmp(&b.subject));
        rows
    }

    /// Remove a peer's entry, but only if it is still *this* session's —
    /// a reconnected peer must not be un-registered by the session that died.
    pub fn remove_if(&self, subject: &str, session_id: u64) {
        let mut peers = self.peers.lock().expect("peer registry lock");
        if peers
            .get(subject)
            .is_some_and(|entry| entry.session_id == session_id)
        {
            peers.remove(subject);
        }
    }

    /// The peer's live mux and certificate, if it is connected.
    pub fn get(&self, subject: &str) -> Option<(Mux, TemperCertificate)> {
        self.peers
            .lock()
            .expect("peer registry lock")
            .get(subject)
            .map(|entry| (entry.mux.clone(), entry.certificate.clone()))
    }

    /// Presence questions are answered by `get`; the size is only read by
    /// the tests that assert an entry survived (or did not) a reconnect.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.peers.lock().expect("peer registry lock").len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mux::MuxSession;
    use crate::relay::{MessageRx, MessageTx, RelayMessage};
    use crate::testutil::enroll;
    use tokio::sync::mpsc;

    /// A mux handle with no driver that matters — the registry never speaks
    /// on it, it only hands it back. Building one spawns the mux driver, so
    /// the tests that call this run on a Tokio runtime.
    fn any_mux() -> Mux {
        struct Tx(mpsc::UnboundedSender<RelayMessage>);
        struct Rx(mpsc::UnboundedReceiver<RelayMessage>);
        impl MessageTx for Tx {
            async fn send_msg(&mut self, message: &RelayMessage) -> crate::Result<()> {
                self.0
                    .send(message.clone())
                    .map_err(|_| crate::Error::custom("closed"))
            }
        }
        impl MessageRx for Rx {
            async fn recv_msg(&mut self) -> crate::Result<Option<RelayMessage>> {
                Ok(self.0.recv().await)
            }
        }
        let (tx, _tx_rx) = mpsc::unbounded_channel();
        let (_rx_tx, rx) = mpsc::unbounded_channel();
        MuxSession::initiator(Tx(tx), Rx(rx)).handle()
    }

    #[tokio::test]
    async fn a_replaced_session_cannot_remove_its_successor() {
        let registry = PeerRegistry::new();
        let cert = enroll("peer.example", 30).cert;

        registry.insert("peer.example", 1, 100, cert.clone(), any_mux());
        registry.insert("peer.example", 2, 200, cert.clone(), any_mux());
        assert_eq!(registry.len(), 1);

        // The old session ends *after* the reconnect: it must not evict it.
        registry.remove_if("peer.example", 1);
        assert_eq!(registry.len(), 1, "the live session was evicted");

        // The live session ending does remove it.
        registry.remove_if("peer.example", 2);
        assert!(registry.is_empty());
    }

    /// The snapshot is the fleet view's data: the live session's id, the
    /// certificate's id, and the arrival time of the entry as it stands.
    #[tokio::test]
    async fn the_snapshot_names_the_live_session_and_sorts() {
        let registry = PeerRegistry::new();
        let cert = enroll("z.example", 30).cert.clone();
        registry.insert("z.example", 7, 1000, cert.clone(), any_mux());
        registry.insert("a.example", 9, 2000, cert.clone(), any_mux());

        let rows = registry.snapshot();
        assert_eq!(
            rows.iter()
                .map(|row| row.subject.as_str())
                .collect::<Vec<_>>(),
            vec!["a.example", "z.example"],
            "snapshot order is stable"
        );
        assert_eq!(rows[0].session_id, 9);
        assert_eq!(rows[0].since_unix, 2000);
        assert_eq!(rows[0].cert_id, cert.cert_id);

        // A reconnect replaces the record, including its arrival time.
        registry.insert("z.example", 11, 3000, cert.clone(), any_mux());
        let rows = registry.snapshot();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].session_id, 11);
        assert_eq!(rows[1].since_unix, 3000);
    }

    #[test]
    fn an_unknown_peer_is_absent() {
        let registry = PeerRegistry::new();
        assert!(registry.get("nobody.example").is_none());
        registry.remove_if("nobody.example", 7);
        assert!(registry.is_empty());
    }
}

// endregion: --- Tests
