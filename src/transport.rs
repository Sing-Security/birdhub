// ============================================================================
// TRANSPORT MODULE: a node's local listeners
// ============================================================================
//
// One task per `[[transports]]` entry, and nothing else. Each binds a local
// address; every connection it accepts is carried to the tunnel's destination
// — a `host:port` the hub dials, or `<subject>/<service>` on a peer — through
// the node's single hub session (node.rs). The listener does not own a
// session, does not handshake, and does not know which of the two shapes it
// is forwarding: `NodeLink::serve_local` decides, and the pump is the same
// either way.
//
// The first version gave every transport its own session to the hub, because
// a transport was the only thing that knew the hub's address. Now `[peer]`
// names the hub — one address, one pinned certificate, one session — which is
// also what lets the hub registry treat a node as one presence rather than
// one per transport.
//
// Everything checkable is checked at startup — both certificates chain to the
// configured CA, both are inside their validity windows, and this node's
// certificate certifies exactly the keys this node holds. All three otherwise
// surface later as a handshake refusal on the *other* machine, reported about
// a node whose operator believes it is configured correctly.

use crate::ca::{self, CaPublicKeys};
use crate::config::{AppConfig, ServiceConfig};
use crate::error::{Error, Result};
use crate::events::{EventLog, Kind};
use crate::identity::{check_certificate_matches_identity, Identity};
use crate::node::{NodeContext, NodeLink, TransportRuntime};
use crate::time::now_secs;
use std::collections::BTreeMap;
use std::sync::Arc;

// region:    --- Client

/// Start every configured listener and run until the process is killed —
/// the headless binary's entry point. The control API, if `[control]` is
/// configured, is served from the same runtime. (`_path` is the config path,
/// kept in the signature so both modes start the same way; the node's API
/// never writes its config, so nothing reads it here.)
pub async fn start(_path: &str, config: AppConfig) -> Result<()> {
    let events = EventLog::console();
    let control = config.control.clone();
    let link = Arc::new(build(config, events.clone())?);
    crate::control::spawn(
        crate::control::ApiState::Node {
            ctx: link.context(),
            link: link.clone(),
        },
        control,
    )
    .await?;
    spawn_all(&link);
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| Error::custom(format!("failed to listen for shutdown: {}", e)))?;
    events.info(Kind::Other, "Node: shutting down.");
    Ok(())
}

/// Spawn the supervisor and every transport's listener. Shared by the
/// headless binary and the console — one way to start a node, so the two
/// cannot drift.
pub fn spawn_all(link: &Arc<NodeLink>) {
    link.spawn_supervisor();
    for runtime in link.transports() {
        let link = link.clone();
        let events = link.events();
        tokio::spawn(async move {
            if let Err(e) = listen(link, runtime).await {
                events.warn(
                    Kind::Listener,
                    format!("Node: listener stopped: {}", e.message()),
                );
            }
        });
    }

    link.events().info(
        Kind::Listener,
        format!("Node: {} listener(s) starting.", link.transports().len()),
    );
}

/// Build the node — identity, certificates, context, link — without binding
/// a listener, so a frontend can hold the node's state (link state, events)
/// before anything is spawned.
pub fn build(config: AppConfig, events: Arc<EventLog>) -> Result<NodeLink> {
    let identity = Identity::load_or_create(
        config.identity.key_file.clone(),
        &config.identity.name.clone(),
    )?;
    events.info(
        Kind::Other,
        format!(
            "Node: identity '{}' key_id={}",
            identity.name, identity.signing.key_id
        ),
    );

    let ca = CaPublicKeys::load(&config.ca.public)?;

    // This node's certificate must certify exactly the keys this node holds,
    // and chain to the CA this node is about to trust peers through. Checking
    // both here moves two failures that would otherwise appear on the hub —
    // as anonymous handshake refusals — to the machine holding the problem.
    let certificate = ca::load_certificate(&config.identity.certificate)?;
    check_certificate_matches_identity(&identity, &certificate)?;
    ca.verify(&certificate, now_secs())?;

    // `validate` rejects client mode without [peer]; this extraction is the
    // one place that has to re-state the invariant to the compiler.
    let peer = config
        .peer
        .as_ref()
        .ok_or_else(|| Error::custom("client mode requires [peer] hub_cert"))?;
    let hub_certificate = ca::load_certificate(&peer.hub_cert)?;
    ca.verify(&hub_certificate, now_secs())?;

    events.info(
        Kind::Other,
        format!(
            "Node: hub '{}' cert={} concealment_id={} at {}",
            hub_certificate.subject_id,
            hub_certificate.cert_id,
            hub_certificate.concealment.to_public_key().key_id,
            peer.address
        ),
    );
    for service in &config.services {
        events.info(
            Kind::Other,
            format!(
                "Node: serving '{}' -> {} for [{}]",
                service.name,
                service.target,
                service.clients.join(", ")
            ),
        );
    }

    // `validate` rejected duplicate service names, so this collect is exact.
    let services: BTreeMap<String, ServiceConfig> = config
        .services
        .iter()
        .map(|service| (service.name.clone(), service.clone()))
        .collect();

    let ctx = Arc::new(NodeContext::new(
        identity,
        certificate,
        ca,
        hub_certificate,
        services,
        events,
    )?);
    Ok(NodeLink::new(ctx, peer.address.clone(), &config.transports))
}

/// Bind one transport's local address and carry every connection it accepts.
async fn listen(link: Arc<NodeLink>, runtime: Arc<TransportRuntime>) -> Result<()> {
    let events = link.events();
    let config = runtime.config();
    let listener = tokio::net::TcpListener::bind(config.local_address.as_str())
        .await
        .map_err(|e| {
            runtime.failed(format!("cannot bind: {}", e));
            Error::custom(format!(
                "cannot bind '{}' on {}: {}",
                config.name, config.local_address, e
            ))
        })?;
    events.info(
        Kind::Listener,
        format!(
            "Node: '{}' listening on {} -> {}",
            config.name, config.local_address, config.forward_to
        ),
    );

    loop {
        let (local, from) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                runtime.failed(format!("accept failed: {}", e));
                events.warn(Kind::Listener, format!("Node: accept failed: {}", e));
                continue;
            }
        };
        runtime.count_connection();
        let link = link.clone();
        let events = events.clone();
        let forward_to = config.forward_to.clone();
        tokio::spawn(async move {
            if let Err(e) = link.serve_local(&forward_to, local).await {
                events.warn(
                    Kind::Session,
                    format!("Node: connection from {} ended: {}", from, e.message()),
                );
            }
        });
    }
}

// endregion: --- Client
