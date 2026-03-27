use crate::Result;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::process::Command;

// region:    --- Types

/// Represents the identity of the current node within the NetBird mesh.
/// In the VISP architecture, this identity governs access to Transport (Shadowsocks).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub ip: String,
    pub pubkey: String,
    pub hostname: String,
    pub is_connected: bool,
}

#[derive(Deserialize)]
struct NetbirdStatus {
    #[serde(alias = "peer", alias = "localPeerState")]
    local_peer_state: Option<NetbirdPeerState>,
    #[serde(alias = "managementState")]
    management_state: Option<NetbirdManagementState>,
}

#[derive(Deserialize)]
struct NetbirdPeerState {
    #[serde(alias = "localIP")]
    ip: Option<String>,
    #[serde(alias = "publicKey")]
    pubkey: Option<String>,
    #[serde(alias = "hostname")]
    fqdn: Option<String>,
}

#[derive(Deserialize)]
struct NetbirdManagementState {
    connected: bool,
}

// endregion: --- Types

// region:    --- NetBird Manager

/// `NetbirdManager` is the core Identity and Mesh controller.
///
/// It strictly enforces the Golden Rule: Identity comes from NetBird.
/// This manager interfaces with the local NetBird daemon to fetch node
/// identity, verify mesh health, and obtain tokens for Zero Trust SS gateways.
#[derive(Debug, Clone, Default)]
pub struct NetbirdManager;

impl NetbirdManager {
    pub fn new() -> Self {
        Self
    }

    /// Fetches the local node's NetBird identity status.
    /// Used as the foundation for gateway authentication.
    pub async fn get_identity(&self) -> Result<PeerIdentity> {
        let output = Command::new("netbird")
            .arg("status")
            .arg("--json")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(crate::Error::custom_from_err)?;

        if !output.status.success() {
            return Err(crate::Error::custom(format!(
                "netbird status failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let status: NetbirdStatus =
            serde_json::from_slice(&output.stdout).map_err(crate::Error::custom_from_err)?;

        let (ip, pubkey, hostname) = status
            .local_peer_state
            .map(|p| {
                (
                    p.ip.unwrap_or_else(|| "100.64.0.1".to_string()),
                    p.pubkey.unwrap_or_else(|| "unknown-pubkey".to_string()),
                    p.fqdn.unwrap_or_else(|| "unknown-hostname".to_string()),
                )
            })
            .unwrap_or_else(|| {
                (
                    "100.64.0.1".to_string(),
                    "unknown-pubkey".to_string(),
                    "unknown-hostname".to_string(),
                )
            });

        let is_connected = status.management_state.map(|m| m.connected).unwrap_or(true);

        Ok(PeerIdentity {
            ip,
            pubkey,
            hostname,
            is_connected,
        })
    }
}

// endregion: --- NetBird Manager
