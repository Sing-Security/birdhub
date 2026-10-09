// ============================================================================
// CONTROL MODULE: the local read/write API
// ============================================================================
//
// A JSON API beside the core, so anything that is not a person clicking the
// console — a web portal, a script, a test — can read the same state and call
// the same actions the console does. It is the same surface the GUI drives:
// the handlers below call `HubShared`/`NodeLink` methods directly, never a
// second implementation, so the API and the console cannot drift apart.
//
// Two decisions worth the words:
//
// * **Loopback-only, opt-in, unauthenticated.** The API can read fleet state
//   and end sessions, so it is disabled unless the config writes a `[control]
//   address` — and that address is bound exactly as written, which the config
//   validation and the comment in `config.rs` steer toward the loopback. An
//   authenticated remote admin is a later step; when it exists it will be a
//   Temper session like every other, and this listener stays local.
//
// * **The API writes the config file for the roster.** `PUT /grants` loads
//   the config, swaps the grants, validates, rewrites the file, and applies.
//   The rewrite loses the file's comments — the price of a save button; an
//   operator who keeps a hand-written file edits it and calls
//   `POST /grants/reload` instead.
//
// Everything that acts logs an event first — an action taken through the API
// must read the same in the log as one taken at the console.

use crate::config::{AppConfig, ControlConfig, GrantConfig, ServiceConfig};
use crate::error::{Error, Result};
use crate::events::{Event, EventLog, Kind};
use crate::hub::HubShared;
use crate::node::{NodeContext, NodeLink, PeerRow};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

// region:    --- Types

/// The half of the core this API reads and drives — one state, either mode.
/// The enum is the dispatch: a hub's router gets the hub's routes, a node's
/// the node's, and asking one side for the other's surface is a 404, not a
/// wrong answer.
pub enum ApiState {
    Hub {
        shared: Arc<HubShared>,
    },
    Node {
        ctx: Arc<NodeContext>,
        link: Arc<NodeLink>,
    },
}

impl ApiState {
    fn events(&self) -> Arc<EventLog> {
        match self {
            ApiState::Hub { shared } => shared.events.clone(),
            ApiState::Node { link, .. } => link.events(),
        }
    }

    /// The router for this mode.
    pub fn router(self) -> Router {
        match self {
            ApiState::Hub { shared } => Router::new()
                .route("/status", get(hub_status))
                .route("/fleet", get(fleet))
                .route("/grants", get(grants).put(put_grants))
                .route("/grants/reload", post(reload_grants))
                .route("/sessions/{id}/disconnect", post(disconnect))
                .route("/events", get(hub_events))
                .with_state(shared),
            ApiState::Node { ctx, link } => Router::new()
                .route("/status", get(node_status))
                .route("/link", get(link_view))
                .route("/link/reconnect", post(reconnect))
                .route("/transports", get(transports))
                .route("/services", get(services))
                .route("/peers", get(peers))
                .route("/events", get(node_events))
                .with_state((ctx, link)),
        }
    }
}

/// Bind the configured address and serve. `None` when no `[control]` section
/// or no address is configured — the API is opt-in, so "not written down" is
/// "not running", not a bind failure.
pub async fn spawn(state: ApiState, control: Option<ControlConfig>) -> Result<Option<SocketAddr>> {
    let Some(address) = control.and_then(|control| control.address) else {
        return Ok(None);
    };
    // `AppConfig::validate` already proved this parses; binding proves it is
    // free. Both failures belong to the operator's config, not the runtime.
    let address: SocketAddr = address.parse().map_err(|_| {
        Error::custom(format!(
            "[control] address '{}' is not a socket address",
            address
        ))
    })?;
    let events = state.events();
    let router = state.router();
    let listener = tokio::net::TcpListener::bind(address).await.map_err(|e| {
        Error::custom(format!(
            "cannot bind [control] address '{}': {}",
            address, e
        ))
    })?;
    let local = listener.local_addr()?;
    events.info(Kind::Listener, format!("control API on http://{}", local));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(Some(local))
}

// endregion: --- Types

// region:    --- Shared response shapes

/// One session, as the fleet table and the inspector read it.
#[derive(Serialize)]
struct SessionView {
    session_id: u64,
    subject: String,
    key_id: String,
    cert_id: String,
    not_before: u64,
    not_after: u64,
    since_unix: u64,
    streams_open: u64,
}

impl SessionView {
    fn of(info: &crate::hub::SessionInfo) -> Self {
        Self {
            session_id: info.session_id,
            subject: info.subject.clone(),
            key_id: info.key_id.clone(),
            cert_id: info.certificate.cert_id.clone(),
            not_before: info.certificate.not_before,
            not_after: info.certificate.not_after,
            since_unix: info.since_unix,
            streams_open: info.streams_open.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

/// One roster row, as written.
#[derive(Serialize)]
struct GrantView {
    client: String,
    targets: Vec<String>,
}

fn roster(shared: &HubShared) -> Vec<GrantView> {
    shared
        .grants_snapshot()
        .into_iter()
        .map(|(client, targets)| GrantView { client, targets })
        .collect()
}

fn bad_request(message: String) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, message)
}

// endregion: --- Shared response shapes

// region:    --- Hub routes

#[derive(Serialize)]
struct HubStatus {
    mode: &'static str,
    subject: String,
    key_id: String,
    cert_id: String,
    not_before: u64,
    not_after: u64,
    config_path: String,
}

async fn hub_status(State(shared): State<Arc<HubShared>>) -> Json<HubStatus> {
    Json(HubStatus {
        mode: "hub",
        subject: shared.certificate.subject_id.clone(),
        key_id: shared.identity.signing.key_id.clone(),
        cert_id: shared.certificate.cert_id.clone(),
        not_before: shared.certificate.not_before,
        not_after: shared.certificate.not_after,
        config_path: shared.config_path.clone(),
    })
}

/// The live sessions, oldest first — the same order the fleet table shows.
async fn fleet(State(shared): State<Arc<HubShared>>) -> Json<Vec<SessionView>> {
    Json(
        shared
            .sessions
            .snapshot()
            .iter()
            .map(|info| SessionView::of(info))
            .collect(),
    )
}

async fn grants(State(shared): State<Arc<HubShared>>) -> Json<Vec<GrantView>> {
    Json(roster(&shared))
}

/// Apply a validated grant list: fold it, swap it, and log the new table's
/// shape the way startup does.
fn apply_grants(shared: &HubShared, grants: &[GrantConfig]) {
    let table = crate::hub::build_grants(grants);
    let rows = table.len();
    shared.replace_grants(table);
    shared
        .events
        .info(Kind::Other, format!("Hub: grants applied ({} rows)", rows));
    for (client, targets) in shared.grants_snapshot() {
        if targets.is_empty() {
            shared.events.info(
                Kind::Other,
                format!(
                    "Hub: grant '{}' → (serves only; may ask for nothing)",
                    client
                ),
            );
        } else {
            shared.events.info(
                Kind::Other,
                format!("Hub: grant '{}' → {}", client, targets.join(", ")),
            );
        }
    }
}

/// Re-read the config file and apply its grants. The operator edited the
/// file by hand; nothing is written here. Shared by `POST /grants/reload`
/// and the console's Reload button — one implementation, so the two surfaces
/// cannot drift.
pub fn reload_roster(shared: &HubShared) -> std::result::Result<(), String> {
    let config =
        AppConfig::load_from_file(&shared.config_path).map_err(|e| e.message())?;
    config.validate().map_err(|e| e.message())?;
    apply_grants(shared, &config.grants);
    shared.events.info(
        Kind::Other,
        format!("Hub: grants reloaded from '{}'", shared.config_path),
    );
    Ok(())
}

/// Replace the roster: load the config, swap the grants, validate, rewrite
/// the file, apply. The rewrite loses the file's comments — see the module
/// comment. Sessions already up keep the list they were handed; kick them
/// (`disconnect_session`) to make the edit reach a connected client. Shared
/// by `PUT /grants` and the console's Save button.
pub fn edit_roster(
    shared: &HubShared,
    grants: Vec<GrantConfig>,
) -> std::result::Result<(), String> {
    let mut config =
        AppConfig::load_from_file(&shared.config_path).map_err(|e| e.message())?;
    config.grants = grants;
    config.validate().map_err(|e| e.message())?;
    let text = toml::to_string_pretty(&config)
        .map_err(|e| format!("cannot serialize the config: {}", e))?;
    std::fs::write(&shared.config_path, text)
        .map_err(|e| format!("cannot write '{}': {}", shared.config_path, e))?;
    apply_grants(shared, &config.grants);
    Ok(())
}

/// The operator's kick: end one session, whose client then reconnects and is
/// subject to whatever the roster says now. Shared by the API route and the
/// console's Disconnect button.
pub fn disconnect_session(
    shared: &HubShared,
    session_id: u64,
) -> std::result::Result<(), (StatusCode, String)> {
    let Some(info) = shared.sessions.get(session_id) else {
        return Err((StatusCode::NOT_FOUND, format!("no session {}", session_id)));
    };
    if !info.kick() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "session {} is not active yet — try again in a moment",
                session_id
            ),
        ));
    }
    shared.events.info(
        Kind::Session,
        format!(
            "Hub: session {} with '{}' disconnected by operator",
            session_id, info.subject
        ),
    );
    Ok(())
}

async fn reload_grants(
    State(shared): State<Arc<HubShared>>,
) -> std::result::Result<Json<Vec<GrantView>>, (StatusCode, String)> {
    reload_roster(&shared).map_err(bad_request)?;
    Ok(Json(roster(&shared)))
}

#[derive(Deserialize)]
struct GrantsBody {
    grants: Vec<GrantConfig>,
}

async fn put_grants(
    State(shared): State<Arc<HubShared>>,
    Json(body): Json<GrantsBody>,
) -> std::result::Result<Json<Vec<GrantView>>, (StatusCode, String)> {
    edit_roster(&shared, body.grants).map_err(bad_request)?;
    Ok(Json(roster(&shared)))
}

async fn disconnect(
    State(shared): State<Arc<HubShared>>,
    Path(session_id): Path<u64>,
) -> std::result::Result<Json<serde_json::Value>, (StatusCode, String)> {
    disconnect_session(&shared, session_id)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// endregion: --- Hub routes

// region:    --- Node routes

#[derive(Serialize)]
struct NodeStatus {
    mode: &'static str,
    subject: String,
    key_id: String,
    cert_id: String,
    not_before: u64,
    not_after: u64,
    hub: String,
    hub_subject: String,
}

async fn node_status(
    State((ctx, link)): State<(Arc<NodeContext>, Arc<NodeLink>)>,
) -> Json<NodeStatus> {
    Json(NodeStatus {
        mode: "client",
        subject: ctx.identity.name.clone(),
        key_id: ctx.identity.signing.key_id.clone(),
        cert_id: ctx.certificate.cert_id.clone(),
        not_before: ctx.certificate.not_before,
        not_after: ctx.certificate.not_after,
        hub: link.server_address().to_string(),
        hub_subject: ctx.hub_certificate.subject_id.clone(),
    })
}

#[derive(Serialize)]
struct LinkView {
    address: String,
    state: String,
    session_id: Option<u64>,
    retry_in_secs: Option<u64>,
    last_error: Option<String>,
}

async fn link_view(
    State((_ctx, link)): State<(Arc<NodeContext>, Arc<NodeLink>)>,
) -> Json<LinkView> {
    let (session_id, retry_in_secs, last_error) = match link.link_state() {
        crate::node::LinkState::Connecting => (None, None, None),
        crate::node::LinkState::Connected { session_id } => (Some(session_id), None, None),
        crate::node::LinkState::Backoff {
            retry_in_secs,
            last_error,
        } => (None, Some(retry_in_secs), Some(last_error)),
    };
    Json(LinkView {
        address: link.server_address().to_string(),
        state: link.link_state().label().to_string(),
        session_id,
        retry_in_secs,
        last_error,
    })
}

/// Drop the live hub session; the supervisor reconnects on its own backoff.
async fn reconnect(
    State((_ctx, link)): State<(Arc<NodeContext>, Arc<NodeLink>)>,
) -> Json<serde_json::Value> {
    link.events()
        .info(Kind::Session, "Node: reconnect requested by operator");
    link.reconnect();
    Json(serde_json::json!({ "ok": true }))
}

#[derive(Serialize)]
struct TransportView {
    name: String,
    local_address: String,
    forward_to: String,
    accepted: u64,
    last_error: Option<String>,
}

async fn transports(
    State((_ctx, link)): State<(Arc<NodeContext>, Arc<NodeLink>)>,
) -> Json<Vec<TransportView>> {
    Json(
        link.transports()
            .iter()
            .map(|runtime| TransportView {
                name: runtime.config().name.clone(),
                local_address: runtime.config().local_address.clone(),
                forward_to: runtime.config().forward_to.clone(),
                accepted: runtime.accepted(),
                last_error: runtime.last_error(),
            })
            .collect(),
    )
}

async fn services(
    State((ctx, _link)): State<(Arc<NodeContext>, Arc<NodeLink>)>,
) -> Json<Vec<ServiceConfig>> {
    Json(ctx.services.values().cloned().collect())
}

/// Cached peer sessions. `locked: true` means a handshake is mid-flight and
/// holds the map — the reader learns that it could not look, rather than
/// being told "no peers" for a fleet it simply could not see.
#[derive(Serialize)]
struct PeersView {
    locked: bool,
    peers: Vec<PeerRowView>,
}

#[derive(Serialize)]
struct PeerRowView {
    subject: String,
    session_id: u64,
    since_unix: u64,
    live: bool,
}

fn peer_rows(rows: Vec<PeerRow>) -> Vec<PeerRowView> {
    rows.into_iter()
        .map(|row| PeerRowView {
            subject: row.subject,
            session_id: row.session_id,
            since_unix: row.since_unix,
            live: row.live,
        })
        .collect()
}

async fn peers(State((_ctx, link)): State<(Arc<NodeContext>, Arc<NodeLink>)>) -> Json<PeersView> {
    match link.peers_snapshot() {
        Some(rows) => Json(PeersView {
            locked: false,
            peers: peer_rows(rows),
        }),
        None => Json(PeersView {
            locked: true,
            peers: Vec::new(),
        }),
    }
}

// endregion: --- Node routes

// region:    --- Shared routes

#[derive(Deserialize)]
struct EventsQuery {
    /// Cursor: events with `seq > after` are returned, oldest first.
    #[serde(default)]
    after: u64,
    /// Case-insensitive substring against the line text.
    #[serde(default)]
    filter: Option<String>,
    /// At most this many of the newest matches.
    #[serde(default)]
    limit: Option<usize>,
}

fn events_impl(log: Arc<EventLog>, query: EventsQuery) -> Json<Vec<Event>> {
    Json(log.matching(query.after, query.filter.as_deref(), query.limit))
}

async fn hub_events(
    State(shared): State<Arc<HubShared>>,
    Query(query): Query<EventsQuery>,
) -> Json<Vec<Event>> {
    events_impl(shared.events.clone(), query)
}

async fn node_events(
    State((_ctx, link)): State<(Arc<NodeContext>, Arc<NodeLink>)>,
    Query(query): Query<EventsQuery>,
) -> Json<Vec<Event>> {
    events_impl(link.events(), query)
}

// endregion: --- Shared routes

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mux::MuxSession;
    use crate::relay::{MessageRx, MessageTx, RelayMessage};
    use crate::testutil::Fleet;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::collections::BTreeMap;
    use tower::ServiceExt;

    /// The full hub router — the routes under test are the real ones.
    fn router(shared: Arc<HubShared>) -> Router {
        ApiState::Hub { shared }.router()
    }

    /// A hub state with a real temp config file, so the grant routes read
    /// and write the thing they will in production.
    fn hub_state(tag: &str) -> (Arc<HubShared>, Fleet) {
        let fleet = Fleet::new(tag);
        let (identity, cert) = fleet.enroll("hub.example");
        let config_path = fleet.dir.file("hub.toml");
        std::fs::write(
            &config_path,
            r#"
[app]
mode = "hub"

[identity]
key_file = "unused"
name = "hub.example"
certificate = "unused"

[ca]
public = "unused"

[[grants]]
client = "laptop.example"
targets = ["origin.internal:80"]
"#,
        )
        .expect("write hub config");
        let shared = Arc::new(HubShared {
            events: EventLog::quiet(),
            identity: Arc::new(identity),
            certificate: cert,
            registry: Arc::new(crate::registry::PeerRegistry::new()),
            sessions: Arc::new(crate::hub::SessionBoard::new()),
            grants: std::sync::RwLock::new(BTreeMap::from([(
                "laptop.example".to_string(),
                vec!["origin.internal:80".to_string()],
            )])),
            config_path,
        });
        (shared, fleet)
    }

    fn request(method: &str, uri: &str, body: Option<String>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        builder
            .body(Body::from(body.unwrap_or_default()))
            .expect("request")
    }

    async fn body_text(body: Body) -> String {
        let bytes = axum::body::to_bytes(body, 1 << 20)
            .await
            .expect("read body");
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let body = body_text(response.into_body()).await;
        serde_json::from_str(&body).expect("json body")
    }

    #[tokio::test]
    async fn status_names_the_hub() {
        let (shared, _fleet) = hub_state("status");
        let response = router(shared.clone())
            .oneshot(request("GET", "/status", None))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let value = body_json(response).await;
        assert_eq!(value["mode"], "hub");
        assert_eq!(value["subject"], "hub.example");
        assert_eq!(value["key_id"], shared.identity.signing.key_id);
    }

    #[tokio::test]
    async fn fleet_lists_the_live_sessions_oldest_first() {
        let (shared, _fleet) = hub_state("fleet");
        let cert = shared.certificate.clone();
        // Added newest-first on purpose: the board sorts by connection
        // time, so the entry made later floats to the end.
        shared
            .sessions
            .add(1, "newer.example", "k2", cert.clone(), 200);
        shared.sessions.add(2, "older.example", "k1", cert, 100);

        let response = router(shared)
            .oneshot(request("GET", "/fleet", None))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let value = body_json(response).await;
        let subjects: Vec<&str> = value
            .as_array()
            .expect("array")
            .iter()
            .map(|session| session["subject"].as_str().expect("subject"))
            .collect();
        assert_eq!(subjects, vec!["older.example", "newer.example"]);
        assert_eq!(value[0]["streams_open"], 0);
    }

    /// A kick ends the session's mux: the handle goes closed the moment the
    /// driver processes the shutdown, and the route reports success.
    #[tokio::test]
    async fn disconnect_kicks_the_session() {
        let (shared, _fleet) = hub_state("kick");
        let cert = shared.certificate.clone();
        let info = shared.sessions.add(7, "laptop.example", "k", cert, 100);

        // A real mux, over in-memory channels: the kick's whole point is the
        // driver dying, which needs a driver.
        struct Tx(tokio::sync::mpsc::UnboundedSender<RelayMessage>);
        struct Rx(tokio::sync::mpsc::UnboundedReceiver<RelayMessage>);
        impl MessageTx for Tx {
            async fn send_msg(&mut self, message: &RelayMessage) -> crate::Result<()> {
                self.0
                    .send(message.clone())
                    .map_err(|_| Error::custom("closed"))
            }
        }
        impl MessageRx for Rx {
            async fn recv_msg(&mut self) -> crate::Result<Option<RelayMessage>> {
                Ok(self.0.recv().await)
            }
        }
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (_, rx) = tokio::sync::mpsc::unbounded_channel();
        let session = MuxSession::initiator(Tx(tx), Rx(rx));
        let mux = session.handle();
        info.set_mux(mux.clone());

        let response = router(shared)
            .oneshot(request("POST", "/sessions/7/disconnect", None))
            .await
            .expect("response");
        // The kick is delivered; the request must not wait on the driver.
        assert_eq!(response.status(), StatusCode::OK);

        // The driver dies on the shutdown; give it a beat and the handle
        // reports the session closed.
        for _ in 0..100 {
            if mux.is_closed() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(mux.is_closed(), "the kicked session's mux must close");
    }

    #[tokio::test]
    async fn disconnect_reports_unknown_and_unready_sessions() {
        let (shared, _fleet) = hub_state("kick-miss");

        let unknown = router(shared.clone())
            .oneshot(request("POST", "/sessions/99/disconnect", None))
            .await
            .expect("response");
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

        // A board entry whose mux does not exist yet (the relay task has not
        // run) is told apart from one that is gone.
        let cert = shared.certificate.clone();
        shared.sessions.add(8, "new.example", "k", cert, 100);
        let unready = router(shared)
            .oneshot(request("POST", "/sessions/8/disconnect", None))
            .await
            .expect("response");
        assert_eq!(unready.status(), StatusCode::CONFLICT);
    }

    /// Reload re-reads the file; PUT rewrites it — and a PUT that fails
    /// validation changes nothing, file or table.
    #[tokio::test]
    async fn the_roster_reads_reloads_and_edits_the_file() {
        let (shared, _fleet) = hub_state("roster");
        let config_path = shared.config_path.clone();

        // Hand-edit the file the way an operator would, then reload.
        let edited = std::fs::read_to_string(&config_path)
            .expect("read config")
            .replace(
                "targets = [\"origin.internal:80\"]",
                "targets = [\"origin.internal:80\", \"origin.internal:443\"]",
            );
        std::fs::write(&config_path, edited).expect("write config");

        let response = router(shared.clone())
            .oneshot(request("POST", "/grants/reload", None))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let value = body_json(response).await;
        assert_eq!(value[0]["targets"].as_array().expect("array").len(), 2);
        assert_eq!(
            shared.targets_for("laptop.example"),
            Some(vec![
                "origin.internal:80".to_string(),
                "origin.internal:443".to_string()
            ])
        );

        // A PUT with a duplicate client fails validation and leaves both the
        // file and the live table alone.
        let bad = r#"{"grants":[{"client":"laptop.example","targets":[]},{"client":"laptop.example","targets":[]}]}"#;
        let response = router(shared.clone())
            .oneshot(request("PUT", "/grants", Some(bad.to_string())))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // The refusal is a plain-text message, not a JSON body.
        let body = body_text(response.into_body()).await;
        assert!(body.contains("two grants"), "error was: {body}");
        assert_eq!(
            shared
                .targets_for("laptop.example")
                .expect("unchanged")
                .len(),
            2,
            "a failed PUT must not change the table"
        );

        // A good PUT rewrites the file and applies.
        let good = r#"{"grants":[{"client":"laptop.example","targets":["origin.internal:80"]},{"client":"serve.example","targets":[]}]}"#;
        let response = router(shared.clone())
            .oneshot(request("PUT", "/grants", Some(good.to_string())))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let value = body_json(response).await;
        assert_eq!(value.as_array().expect("array").len(), 2);
        assert_eq!(
            shared.targets_for("serve.example"),
            Some(Vec::new()),
            "a serve-only row is admitted with nothing to ask for"
        );
        let on_disk = std::fs::read_to_string(&config_path).expect("read config");
        assert!(
            on_disk.contains("serve.example"),
            "the file carries the edit"
        );
        // The rewritten file still parses as the config it is.
        AppConfig::load_from_file(&config_path)
            .expect("rewritten file loads")
            .validate()
            .expect("rewritten file validates");
    }

    /// The event cursor: everything after `after`, filtered, newest kept.
    #[tokio::test]
    async fn events_serve_the_ring_with_a_cursor() {
        let (shared, _fleet) = hub_state("events");
        shared
            .events
            .info(Kind::Session, "Hub: session 1 with 'a.example'");
        shared
            .events
            .warn(Kind::Refusal, "Hub: refusing 'b.example'");
        shared
            .events
            .info(Kind::Session, "Hub: session 2 with 'c.example'");

        let response = router(shared)
            .oneshot(request("GET", "/events?after=1&filter=session", None))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let value = body_json(response).await;
        let array = value.as_array().expect("array");
        assert_eq!(array.len(), 1, "the filter keeps one: {value}");
        assert!(array[0]["text"]
            .as_str()
            .expect("text")
            .contains("c.example"));
    }
}

// endregion: --- Tests
