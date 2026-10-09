//! The console's handle on the running core, and the one action surface
//! every caller goes through.
//!
//! The console embeds the core it renders: the backend holds the live hub or
//! node (built on the console's own tokio thread), and `apply` calls the
//! same free functions the control API's routes call (`control::edit_roster`,
//! `disconnect_session`, `NodeLink::reconnect`) — there is exactly one
//! implementation of each action, shared by the buttons, the API and the
//! tests.
//!
//! `Fixture` is the test backend: the views render from `ConsoleData` built
//! by hand, so a screenshot test never needs a fleet.

use crate::data::{ConsoleData, GrantRow};
use birdhub::config::GrantConfig;
use birdhub::control;
use birdhub::hub::HubShared;
use birdhub::node::{NodeContext, NodeLink};
use std::net::SocketAddr;
use std::sync::Arc;

/// What the console is managing.
pub enum Backend {
    Hub {
        shared: Arc<HubShared>,
        /// The control API's bound address, if `[control]` was configured —
        /// shown in the shell so an operator knows where scripts reach in.
        api: Option<SocketAddr>,
    },
    Node {
        link: Arc<NodeLink>,
        ctx: Arc<NodeContext>,
        api: Option<SocketAddr>,
    },
    /// No core: the views render from fixture data (the screenshot tests).
    /// The recorder holds every action applied, so the action-layer test can
    /// assert on what a click asked for rather than on a core that is not
    /// there.
    Fixture(Arc<std::sync::Mutex<Vec<Action>>>),
}

/// One thing an operator asked for. The buttons build these; `apply` runs
/// them; the tests assert on them. Nothing else mutates the core.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// Hub: end one session; the client reconnects under the current roster.
    Kick(u64),
    /// Hub: rewrite the config's grants and apply them.
    SaveRoster(Vec<GrantRow>),
    /// Hub: re-read the config file's grants.
    ReloadRoster,
    /// Node: drop the live hub session; the supervisor reconnects.
    Reconnect,
}

impl Backend {
    /// Run one action against the core. The error is shown in the status
    /// bar; the core's own event says what succeeded.
    pub fn apply(&self, action: &Action) -> Result<(), String> {
        match (self, action) {
            (Backend::Hub { shared, .. }, Action::Kick(session_id)) => {
                control::disconnect_session(shared, *session_id).map_err(|(_, message)| message)
            }
            (Backend::Hub { shared, .. }, Action::SaveRoster(rows)) => {
                let grants: Vec<GrantConfig> = rows
                    .iter()
                    .filter(|row| !row.client.trim().is_empty())
                    .map(|row| GrantConfig {
                        client: row.client.trim().to_string(),
                        targets: row.targets.clone(),
                    })
                    .collect();
                control::edit_roster(shared, grants)
            }
            (Backend::Hub { shared, .. }, Action::ReloadRoster) => control::reload_roster(shared),
            (Backend::Node { link, .. }, Action::Reconnect) => {
                link.reconnect();
                Ok(())
            }
            (Backend::Fixture(recorder), action) => {
                recorder
                    .lock()
                    .expect("fixture recorder lock")
                    .push(action.clone());
                Ok(())
            }
            _ => Err("that action does not belong to this mode".to_string()),
        }
    }

    /// Pull the core's live state into the view data. Called on the console's
    /// poll cadence and right after an action, never per frame: the
    /// snapshots allocate, and 300 ms of staleness is below what an
    /// operator's eye can use.
    pub fn refresh(&self, data: &mut ConsoleData) {
        match self {
            Backend::Hub { shared, api } => {
                data.api = *api;
                data.mode = "hub".to_string();
                data.subject = shared.certificate.subject_id.clone();
                data.key_id = shared.identity.signing.key_id.clone();
                data.cert_id = shared.certificate.cert_id.clone();
                data.not_before = shared.certificate.not_before;
                data.not_after = shared.certificate.not_after;
                data.config_path = Some(shared.config_path.clone());
                data.sessions = shared
                    .sessions
                    .snapshot()
                    .iter()
                    .map(|info| crate::data::SessionRow::of(info))
                    .collect();
                data.roster = shared
                    .grants_snapshot()
                    .into_iter()
                    .map(|(client, targets)| GrantRow { client, targets })
                    .collect();
                if let Ok(text) = std::fs::read_to_string(&shared.config_path) {
                    data.config_text = Some(text);
                }
            }
            Backend::Node { link, ctx, api } => {
                data.api = *api;
                data.mode = "client".to_string();
                data.subject = ctx.identity.name.clone();
                data.key_id = ctx.identity.signing.key_id.clone();
                data.cert_id = ctx.certificate.cert_id.clone();
                data.not_before = ctx.certificate.not_before;
                data.not_after = ctx.certificate.not_after;
                data.hub_address = Some(link.server_address().to_string());
                data.hub_subject = Some(ctx.hub_certificate.subject_id.clone());
                let (state, session_id, retry_in_secs, last_error) = match link.link_state() {
                    birdhub::node::LinkState::Connecting => {
                        ("connecting".to_string(), None, None, None)
                    }
                    birdhub::node::LinkState::Connected { session_id } => {
                        ("connected".to_string(), Some(session_id), None, None)
                    }
                    birdhub::node::LinkState::Backoff {
                        retry_in_secs,
                        last_error,
                    } => (
                        "backoff".to_string(),
                        None,
                        Some(retry_in_secs),
                        Some(last_error),
                    ),
                };
                data.link = crate::data::LinkRow {
                    state,
                    session_id,
                    retry_in_secs,
                    last_error,
                };
                data.transports = link
                    .transports()
                    .iter()
                    .map(|runtime| crate::data::TransportRow::of(runtime))
                    .collect();
                data.services = ctx
                    .services
                    .values()
                    .map(|service| crate::data::ServiceRow {
                        name: service.name.clone(),
                        target: service.target.clone(),
                        clients: service.clients.clone(),
                    })
                    .collect();
                data.peers = match link.peers_snapshot() {
                    Some(rows) => crate::data::PeersRow {
                        locked: false,
                        peers: rows
                            .into_iter()
                            .map(|row| crate::data::PeerRow {
                                subject: row.subject,
                                session_id: row.session_id,
                                since_unix: row.since_unix,
                                live: row.live,
                            })
                            .collect(),
                    },
                    None => crate::data::PeersRow {
                        locked: true,
                        peers: Vec::new(),
                    },
                };
            }
            Backend::Fixture(_) => {}
        }
        // The event tail, appended with the same cursor the API uses: a
        // frame never repeats or misses a line.
        if let Some(events) = &self.events() {
            let fresh = events.since(data.events_cursor);
            data.events_cursor = fresh
                .last()
                .map(|event| event.seq)
                .unwrap_or(data.events_cursor);
            for event in fresh {
                data.events.push_back(crate::data::EventRow::of(&event));
            }
            while data.events.len() > crate::data::EVENT_RING {
                data.events.pop_front();
            }
        }
    }

    fn events(&self) -> Option<Arc<birdhub::events::EventLog>> {
        match self {
            Backend::Hub { shared, .. } => Some(shared.events.clone()),
            Backend::Node { link, .. } => Some(link.events()),
            Backend::Fixture(_) => None,
        }
    }
}
