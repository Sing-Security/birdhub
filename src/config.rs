// ============================================================================
// CONFIG MODULE: birdhub's on-disk configuration
// ============================================================================
//
// Two shapes, one file each, and the shapes do not overlap. A hub reads
// `[identity]`, `[ca]`, `[hub_server]`, and its `[[grants]]`; a client node
// reads `[identity]`, `[ca]`, `[peer]` (its hub: address and pinned
// certificate), `[[transports]]` (local listeners), and `[[services]]` (what
// it serves to peers). A section belonging to the other mode is an error, not
// a no-op: the first version ignored unknown and misplaced keys, and "I set
// data_address in the client config and it did nothing" is a configuration
// bug the parser was fully capable of catching.
//
// Targets are validated by grammar here (`target.rs`): a grant or forward_to
// that could not mean anything is a startup error naming the fix, rather than
// a runtime refusal an operator has to trace back to a typo.
//
// There is no `[netbird]` section, no control-plane address, and no exit or
// routing section. Identity is a Temper keypair certified by the fleet CA
// (`ca.rs`), trust is the CA public keys plus the hub certificate, and the
// only authorization questions — who may connect, and what they may dial —
// are answered by the hub's grant table, never by an address or a range.

use crate::Result;
use serde::{Deserialize, Serialize};

// region:    --- Types

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AppMode {
    #[default]
    Client,
    Hub,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfigSection {
    #[serde(default)]
    pub mode: AppMode,
}

/// This node's long-term Temper identity and its certificate.
///
/// `key_file` is generated on first start with owner-only permissions. It
/// holds secret keys and must never leave the machine. `certificate` is the
/// file `birdhub ca issue` produced for this node's exported keys; startup
/// checks it certifies exactly those keys, because a certificate for some
/// other keypair is the mistake that otherwise surfaces as another node
/// refusing *this* one for reasons that make no sense locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    #[serde(default = "default_key_file")]
    pub key_file: String,
    #[serde(default = "default_identity_name")]
    pub name: String,
    /// Path to this node's certificate. Required in both modes.
    pub certificate: String,
}

fn default_key_file() -> String {
    "identity.key".to_string()
}

fn default_identity_name() -> String {
    "birdhub".to_string()
}

/// The fleet's trust anchor: the CA's public keys.
///
/// Required in both modes. This file is the whole of the trust model — a node
/// that has it can verify every member's certificate, and a node that trusts
/// the wrong one trusts a different fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaConfig {
    /// Path to `ca.pub`, as written by `birdhub ca init`.
    pub public: String,
}

/// Client side: which hub this node talks to.
///
/// One address and one certificate, for the whole node: the session is the
/// node's presence at the hub, so there is exactly one of it, shared by every
/// listener and by everyone reaching this node's services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// The hub's data-plane address, `host:port`.
    pub address: String,
    /// Path to the hub's certificate.
    ///
    /// The session already verifies the hub's certificate against `[ca]`,
    /// which answers "is this a member of the fleet". This file answers the
    /// different question "is this *our* hub" — byte-exact, so a second valid
    /// certificate from the same CA cannot take the hub's place.
    pub hub_cert: String,
}

/// One service this node serves to other nodes — the answer to "what may a
/// peer ask this node for".
///
/// The `clients` list is the authorization: the peer's *certificate subject*,
/// proved by the node-to-node handshake, must be named here before anything
/// is dialed. Empty means the service serves nobody — the same default-deny
/// shape as the hub's grant table, and the reason a service with no clients
/// is a configuration error rather than a public one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// The name peers ask for, e.g. `web`. Lowercase letters, digits, dashes.
    pub name: String,
    /// The local `host:port` this node dials when the service is granted.
    pub target: String,
    /// Certificate subjects permitted to use it. Never empty.
    pub clients: Vec<String>,
}

/// The local read/write control API (`control.rs`).
///
/// Optional in both modes, and off when absent: a new surface that can read
/// state and end sessions should be a written-down choice, not a default.
/// The address must be a local one — the API has no authentication of its
/// own, so it is only ever bound to the loopback the operator wrote down.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    /// `host:port` to serve the JSON API on. Absent = no API at all.
    #[serde(default)]
    pub address: Option<String>,
}

/// Where the hub listens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubServerConfig {
    #[serde(default = "default_data_address")]
    pub data_address: String,
    /// Issue a stateless anti-DoS cookie, forcing flight 0 before the hub
    /// spends two SLH-DSA signatures on a caller. On by default: it costs a
    /// client one extra round trip and costs an attacker a round trip per
    /// attempt.
    #[serde(default = "default_true")]
    pub require_cookie: bool,
    /// Lifetimes of the cookie and of the replay window, in seconds.
    #[serde(default = "default_handshake_ttl")]
    pub handshake_ttl_secs: u64,
    /// How many recently-accepted session ids the replay guard remembers.
    #[serde(default = "default_replay_capacity")]
    pub replay_capacity: usize,
}

fn default_data_address() -> String {
    "0.0.0.0:8388".to_string()
}

fn default_true() -> bool {
    true
}

fn default_handshake_ttl() -> u64 {
    60
}

fn default_replay_capacity() -> usize {
    4096
}

impl Default for HubServerConfig {
    fn default() -> Self {
        Self {
            data_address: default_data_address(),
            require_cookie: default_true(),
            handshake_ttl_secs: default_handshake_ttl(),
            replay_capacity: default_replay_capacity(),
        }
    }
}

/// One row of the fleet roster: a client, and what it may ask the hub for.
///
/// Keyed by the client's certificate `subject_id` — the *authenticated* name,
/// proved by transcript signature before any lookup happens. The targets are
/// exact strings; there is no wildcard and no range, deliberately, because
/// "which hosts may this client reach" is the question this table exists to
/// answer and a pattern language is a way to answer it differently than the
/// operator read it.
///
/// The row is also the admission: a client named here may hold a session at
/// all (and is therefore visible to peers), and one named nowhere is refused
/// at the handshake. An empty `targets` is the row a node that only *serves*
/// needs — it may hold a session and be reached by peers whose own grants
/// name it, and may ask the hub for nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantConfig {
    /// Certificate `subject_id` of the client.
    pub client: String,
    /// `host:port` strings this client may dial through the hub, or
    /// `@peer/<subject>` entries letting it pair with a peer. Empty admits
    /// the node without letting it ask for anything.
    pub targets: Vec<String>,
}

/// One local listener and the one destination it carries to.
///
/// A tunnel is a single fixed destination on purpose: no SOCKS parsing, no
/// per-connection negotiation. Two destinations are two entries. The
/// destination is either `host:port`, which the hub dials, or
/// `<subject>/<service>`, which reaches a service on a peer through the hub's
/// pairing — the grammar is `target.rs`, and validation here is what keeps an
/// unparseable string from becoming a runtime refusal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub name: String,
    /// Local address the tunnel listens on, `host:port`.
    pub local_address: String,
    /// `host:port`, or `<subject>/<service>` on a peer.
    pub forward_to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub app: AppConfigSection,
    /// Required: no node runs without an identity, a certificate, and a CA.
    pub identity: IdentityConfig,
    /// Required in both modes.
    pub ca: CaConfig,
    /// Client mode only.
    #[serde(default)]
    pub peer: Option<PeerConfig>,
    /// Hub mode only. Optional so a client that sets it is caught by
    /// `validate` rather than silently ignored.
    #[serde(default)]
    pub hub_server: Option<HubServerConfig>,
    /// Hub mode only.
    #[serde(default)]
    pub grants: Vec<GrantConfig>,
    /// Client mode only.
    #[serde(default)]
    pub transports: Vec<TransportConfig>,
    /// Client mode only: what this node serves to peers.
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    /// Either mode: the local control API, if one is wanted.
    #[serde(default)]
    pub control: Option<ControlConfig>,
}

// endregion: --- Types

// region:    --- Loading and validation

impl AppConfig {
    /// Loads configuration from a TOML file.
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::Error::custom(format!("failed to read config file '{}': {}", path, e))
        })?;
        let config: AppConfig = toml::from_str(&content).map_err(|e| {
            crate::Error::custom(format!("failed to parse config file '{}': {}", path, e))
        })?;
        Ok(config)
    }

    /// Reject configurations whose sections belong to the other mode, and the
    /// grant shapes that cannot mean anything.
    ///
    /// Called before anything binds or reads a key file, so every one of
    /// these is reported as a configuration line to fix rather than as a
    /// runtime symptom to debug.
    pub fn validate(&self) -> Result<()> {
        match self.app.mode {
            AppMode::Hub => {
                if self.peer.is_some() {
                    return Err(crate::Error::custom(
                        "[peer] hub_cert is client-only; a hub learns its clients from \
                         their certificates and its [[grants]]",
                    ));
                }
                if !self.transports.is_empty() {
                    return Err(crate::Error::custom(
                        "[[transports]] is client-only; a hub forwards for clients, \
                         it does not listen locally",
                    ));
                }
                if !self.services.is_empty() {
                    return Err(crate::Error::custom(
                        "[[services]] is client-only; a hub serves no services itself, \
                         it pairs the nodes that do",
                    ));
                }
                let mut seen: Vec<&str> = Vec::new();
                for grant in &self.grants {
                    // An empty `targets` is allowed on purpose: it is how a
                    // node that only serves is named in the roster — present
                    // to peers, permitted to ask for nothing.
                    if seen.contains(&grant.client.as_str()) {
                        return Err(crate::Error::custom(format!(
                            "two grants for '{}' — one grant per client with all its \
                             targets, or the second silently wins",
                            grant.client
                        )));
                    }
                    seen.push(&grant.client);
                    for target in &grant.targets {
                        match crate::target::parse(target) {
                            Ok(crate::target::Target::Dial { .. })
                            | Ok(crate::target::Target::Carrier { .. }) => {}
                            Ok(crate::target::Target::Peer { subject, .. }) => {
                                return Err(crate::Error::custom(format!(
                                    "grant for '{}' names '{}': service targets belong \
                                     to the serving node's [[services]]; to let this \
                                     client reach that peer, grant the peer instead — \
                                     targets = [\"@peer/{}\"]",
                                    grant.client, target, subject
                                )));
                            }
                            Ok(crate::target::Target::Directory { .. }) => {
                                return Err(crate::Error::custom(format!(
                                    "grant for '{}' names '{}': @cert is what a client \
                                     asks for; the grant that permits it is \
                                     \"@peer/{}\"",
                                    grant.client,
                                    target,
                                    target.trim_start_matches("@cert/")
                                )));
                            }
                            Err(reason) => {
                                return Err(crate::Error::custom(format!(
                                    "grant for '{}' has an invalid target: {}",
                                    grant.client, reason
                                )));
                            }
                        }
                    }
                }
            }
            AppMode::Client => {
                if self.hub_server.is_some() {
                    return Err(crate::Error::custom(
                        "[hub_server] is hub-only; a client dials `[peer] address`",
                    ));
                }
                if !self.grants.is_empty() {
                    return Err(crate::Error::custom(
                        "[[grants]] is hub-only; which targets *this* client may reach \
                         is written down on the hub",
                    ));
                }
                if self.peer.is_none() {
                    return Err(crate::Error::custom(
                        "client mode requires [peer] hub_cert — without it the client \
                         cannot tell the hub from any other CA member",
                    ));
                }
                if self.transports.is_empty() && self.services.is_empty() {
                    return Err(crate::Error::custom(
                        "no [[transports]] and no [[services]] configured — nothing to \
                         relay and nothing to serve",
                    ));
                }
                for transport in &self.transports {
                    match crate::target::parse(&transport.forward_to) {
                        Ok(crate::target::Target::Dial { .. })
                        | Ok(crate::target::Target::Peer { .. }) => {}
                        Ok(crate::target::Target::Carrier { .. })
                        | Ok(crate::target::Target::Directory { .. }) => {
                            return Err(crate::Error::custom(format!(
                                "transport '{}' forwards to '{}': @ targets are the \
                                 node's own conversation with the hub; forward to \
                                 host:port or <subject>/<service>",
                                transport.name, transport.forward_to
                            )));
                        }
                        Err(reason) => {
                            return Err(crate::Error::custom(format!(
                                "transport '{}' has an invalid forward_to: {}",
                                transport.name, reason
                            )));
                        }
                    }
                }
                let mut seen: Vec<&str> = Vec::new();
                for service in &self.services {
                    if !crate::target::is_service_name(&service.name) {
                        return Err(crate::Error::custom(format!(
                            "service name '{}' is not valid — lowercase letters, digits \
                             and dashes",
                            service.name
                        )));
                    }
                    if seen.contains(&service.name.as_str()) {
                        return Err(crate::Error::custom(format!(
                            "two services named '{}' — one entry per service",
                            service.name
                        )));
                    }
                    seen.push(&service.name);
                    if service.target.is_empty() {
                        return Err(crate::Error::custom(format!(
                            "service '{}' has no target — it would have nothing to dial",
                            service.name
                        )));
                    }
                    if service.clients.is_empty() {
                        return Err(crate::Error::custom(format!(
                            "service '{}' lists no clients — it would serve nobody; \
                             name the certificate subjects that may use it, or remove \
                             the entry",
                            service.name
                        )));
                    }
                }
            }
        }
        if let Some(control) = &self.control {
            if let Some(address) = &control.address {
                address.parse::<std::net::SocketAddr>().map_err(|_| {
                    crate::Error::custom(format!(
                        "[control] address '{}' is not a socket address — write it as \
                         host:port, e.g. 127.0.0.1:8399",
                        address
                    ))
                })?;
            }
        }
        Ok(())
    }
}

// endregion: --- Loading and validation

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    /// A hub config with the required sections; `extra` is appended so each
    /// test can add exactly the section it is about.
    fn hub_toml(extra: &str) -> String {
        format!(
            r#"
[app]
mode = "hub"

[identity]
key_file = "hub.key"
name = "hub.example"
certificate = "hub.cert"

[ca]
public = "ca.pub"
{extra}
"#
        )
    }

    /// A client config with the required sections.
    fn client_toml(extra: &str) -> String {
        format!(
            r#"
[app]
mode = "client"

[identity]
key_file = "laptop.key"
name = "laptop.example"
certificate = "laptop.cert"

[ca]
public = "ca.pub"

[peer]
address = "hub.example:8388"
hub_cert = "hub.cert"
{extra}
"#
        )
    }

    const ONE_TRANSPORT: &str = r#"
[[transports]]
name = "web"
local_address = "127.0.0.1:8080"
forward_to = "origin.internal:80"
"#;

    fn parse(toml: &str) -> AppConfig {
        toml::from_str(toml).expect("test config should parse")
    }

    #[test]
    fn client_config_parses_and_validates() {
        let config = parse(&client_toml(ONE_TRANSPORT));
        assert_eq!(config.app.mode, AppMode::Client);
        assert_eq!(config.identity.name, "laptop.example");
        assert_eq!(config.identity.certificate, "laptop.cert");
        assert_eq!(config.ca.public, "ca.pub");
        config.validate().unwrap();
        let peer = config.peer.unwrap();
        assert_eq!(peer.hub_cert, "hub.cert");
        assert_eq!(peer.address, "hub.example:8388");
        assert_eq!(config.transports[0].forward_to, "origin.internal:80");
    }

    #[test]
    fn hub_config_parses_and_validates() {
        let config = parse(&hub_toml(
            r#"
[hub_server]
data_address = "0.0.0.0:9000"

[[grants]]
client = "laptop.example"
targets = ["origin.internal:80", "origin.internal:443"]
"#,
        ));
        assert_eq!(config.app.mode, AppMode::Hub);
        let server = config.hub_server.clone().unwrap();
        assert_eq!(server.data_address, "0.0.0.0:9000");
        assert!(server.require_cookie, "cookie default must stay on");
        assert_eq!(config.grants[0].targets.len(), 2);
        config.validate().unwrap();
    }

    /// A hub with no `[hub_server]` is a hub on the defaults — and, with no
    /// grants, one that serves nobody.
    #[test]
    fn hub_config_without_optional_sections() {
        let config = parse(&hub_toml(""));
        assert!(config.hub_server.is_none());
        assert!(config.grants.is_empty());
        config.validate().unwrap();

        let server = config.hub_server.unwrap_or_default();
        assert_eq!(server.data_address, "0.0.0.0:8388");
        assert!(server.require_cookie);
    }

    #[test]
    fn hub_mode_rejects_client_sections() {
        let with_peer = parse(&hub_toml(
            r#"
[peer]
address = "hub.example:8388"
hub_cert = "hub.cert"
"#,
        ));
        let err = with_peer.validate().unwrap_err().to_string();
        assert!(err.contains("[peer]"), "error was: {}", err);

        let with_transport = parse(&hub_toml(ONE_TRANSPORT));
        let err = with_transport.validate().unwrap_err().to_string();
        assert!(err.contains("[[transports]]"), "error was: {}", err);

        let with_services = parse(&hub_toml(
            r#"
[[services]]
name = "web"
target = "127.0.0.1:8080"
clients = ["laptop.example"]
"#,
        ));
        let err = with_services.validate().unwrap_err().to_string();
        assert!(err.contains("[[services]]"), "error was: {}", err);
    }

    /// A row with no targets is a serve-only node in the roster: it may hold
    /// a session (that is what makes it reachable) while being permitted to
    /// ask the hub for nothing.
    #[test]
    fn an_empty_grant_admits_a_serving_node() {
        let config = parse(&hub_toml(
            r#"
[[grants]]
client = "node-b.example"
targets = []
"#,
        ));
        config.validate().unwrap();
    }

    #[test]
    fn hub_mode_rejects_unusable_grants() {
        let duplicate = parse(&hub_toml(
            r#"
[[grants]]
client = "laptop.example"
targets = ["a.internal:1"]

[[grants]]
client = "laptop.example"
targets = ["b.internal:2"]
"#,
        ));
        let err = duplicate.validate().unwrap_err().to_string();
        assert!(err.contains("two grants"), "error was: {}", err);
    }

    #[test]
    fn client_mode_rejects_hub_sections() {
        let with_hub_server = parse(&client_toml(
            r#"
[hub_server]
data_address = "0.0.0.0:8388"
"#,
        ));
        let err = with_hub_server.validate().unwrap_err().to_string();
        assert!(err.contains("[hub_server]"), "error was: {}", err);

        let with_grants = parse(&client_toml(
            r#"
[[grants]]
client = "someone"
targets = ["a.internal:1"]
"#,
        ));
        let err = with_grants.validate().unwrap_err().to_string();
        assert!(err.contains("[[grants]]"), "error was: {}", err);
    }

    #[test]
    fn a_forward_to_can_name_a_peer_service() {
        let config = parse(&client_toml(
            r#"
[[transports]]
name = "web"
local_address = "127.0.0.1:8080"
forward_to = "peer.example/web"
"#,
        ));
        config.validate().unwrap();
    }

    /// `@` targets are the node's private conversation with the hub — a
    /// transport that names one is a mistake worth catching at startup, not a
    /// runtime refusal.
    #[test]
    fn a_transport_cannot_forward_to_a_hub_target() {
        for forward_to in ["@peer/peer.example", "@cert/peer.example", "@nonsense"] {
            let config = parse(&client_toml(&format!(
                r#"
[[transports]]
name = "web"
local_address = "127.0.0.1:8080"
forward_to = "{}"
"#,
                forward_to
            )));
            let err = config.validate().unwrap_err().to_string();
            assert!(
                err.contains("invalid forward_to") || err.contains("@ targets"),
                "{} was accepted: {}",
                forward_to,
                err
            );
        }
    }

    #[test]
    fn services_are_validated() {
        let cases = [
            (
                r#"
[[services]]
name = "Web"
target = "127.0.0.1:8080"
clients = ["laptop.example"]
"#,
                "lowercase",
            ),
            (
                r#"
[[services]]
name = "web"
target = "127.0.0.1:8080"
clients = []
"#,
                "serve nobody",
            ),
            (
                r#"
[[services]]
name = "web"
target = ""
clients = ["laptop.example"]
"#,
                "no target",
            ),
            (
                r#"
[[services]]
name = "web"
target = "127.0.0.1:8080"
clients = ["laptop.example"]

[[services]]
name = "web"
target = "127.0.0.1:8081"
clients = ["laptop.example"]
"#,
                "two services",
            ),
        ];
        for (extra, expected) in cases {
            let config = parse(&client_toml(extra));
            let err = config.validate().unwrap_err().to_string();
            assert!(
                err.contains(expected),
                "expected {:?}, got: {}",
                expected,
                err
            );
        }
    }

    /// A serving node with no local listeners is legitimate — the session
    /// exists for the services.
    #[test]
    fn services_alone_are_enough_to_run_a_node() {
        let config = parse(&client_toml(
            r#"
[[services]]
name = "web"
target = "127.0.0.1:8080"
clients = ["laptop.example"]
"#,
        ));
        config.validate().unwrap();
    }

    /// The control API is off unless written down, and a written-down
    /// address has to be a socket address — a surface that can end sessions
    /// should not start by accident, nor bind to something unparseable.
    #[test]
    fn control_api_is_opt_in_and_validated() {
        let without = parse(&hub_toml(""));
        assert!(without.control.is_none());
        without.validate().unwrap();

        let with = parse(&hub_toml(
            r#"
[control]
address = "127.0.0.1:8399"
"#,
        ));
        assert_eq!(
            with.control.as_ref().and_then(|c| c.address.as_deref()),
            Some("127.0.0.1:8399")
        );
        with.validate().unwrap();

        let malformed = parse(&hub_toml(
            r#"
[control]
address = "not-an-address"
"#,
        ));
        let err = malformed.validate().unwrap_err().to_string();
        assert!(err.contains("[control]"), "error was: {}", err);

        // The section works in client mode too.
        let client = parse(&client_toml(
            r#"
[control]
address = "127.0.0.1:8399"
[[transports]]
name = "web"
local_address = "127.0.0.1:8080"
forward_to = "origin.internal:80"
"#,
        ));
        client.validate().unwrap();
    }

    /// Hub grants: a dial target or a peer reach, with the forms that mean
    /// something else rejected by name.
    #[test]
    fn hub_grants_validate_target_grammar() {
        let ok = parse(&hub_toml(
            r#"
[[grants]]
client = "laptop.example"
targets = ["origin.internal:80", "@peer/peer.example"]
"#,
        ));
        ok.validate().unwrap();

        let cases = [
            ("peer.example/web", "grant the peer instead"),
            ("@cert/peer.example", "@peer/"),
            ("@wat/peer.example", "invalid target"),
        ];
        for (target, expected) in cases {
            let config = parse(&hub_toml(&format!(
                r#"
[[grants]]
client = "laptop.example"
targets = ["{}"]
"#,
                target
            )));
            let err = config.validate().unwrap_err().to_string();
            assert!(
                err.contains(expected),
                "expected {:?}, got: {}",
                expected,
                err
            );
        }
    }

    #[test]
    fn client_mode_requires_hub_cert_and_transports() {
        // No [peer]: rebuilding the base without it.
        let no_peer: AppConfig = toml::from_str(
            r#"
[app]
mode = "client"

[identity]
certificate = "laptop.cert"

[ca]
public = "ca.pub"
"#,
        )
        .unwrap();
        let err = no_peer.validate().unwrap_err().to_string();
        assert!(err.contains("hub_cert"), "error was: {}", err);

        // [peer] present, no transports.
        let no_transports: AppConfig = toml::from_str(&client_toml("")).unwrap();
        let err = no_transports.validate().unwrap_err().to_string();
        assert!(err.contains("[[transports]]"), "error was: {}", err);
    }

    /// `certificate` has no default: a config that omits it fails at parse
    /// time, naming the field, rather than at handshake time on the hub.
    #[test]
    fn missing_certificate_is_a_parse_error() {
        let err = toml::from_str::<AppConfig>(
            r#"
[app]
mode = "client"

[identity]
name = "laptop.example"

[ca]
public = "ca.pub"
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("certificate"), "error was: {}", err);
    }

    #[test]
    fn load_from_file_reports_the_path() {
        let dir = TempDir::new("config");
        let path = dir.file("hub.toml");
        std::fs::write(&path, hub_toml("")).unwrap();
        let config = AppConfig::load_from_file(&path).unwrap();
        assert_eq!(config.app.mode, AppMode::Hub);

        let missing = dir.file("absent.toml");
        let err = AppConfig::load_from_file(&missing).unwrap_err().to_string();
        assert!(err.contains(&missing), "error was: {}", err);
    }
}

// endregion: --- Tests
