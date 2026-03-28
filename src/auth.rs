use crate::Result;
use serde::Deserialize;

// region:    --- Types

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AuthToken {
    pub key: String,
    pub server_port: u16,
}

// endregion: --- Types

// region:    --- Auth Manager

/// `AuthManager` handles the lifecycle and validation of
/// identity tokens based on the NetBird mesh identity.
#[derive(Debug, Clone, Default)]
pub struct AuthManager;

impl AuthManager {
    pub fn new() -> Self {
        Self
    }
}

/// Fetches dynamic credentials from the Hub's Control Plane API.
/// This acts as the identity verification step where the Hub reads our NetBird IP
/// and provisions an atomic Shadowsocks password if authorized.
pub async fn _fetch_hub_credentials(hub_api_url: &str) -> Result<AuthToken> {
    let response = reqwest::get(hub_api_url)
        .await
        .map_err(|e| crate::Error::custom(format!("Failed to connect to Hub API: {}", e)))?;

    let response = response
        .error_for_status()
        .map_err(|e| crate::Error::custom(format!("Hub API returned an error: {}", e)))?;

    let token = response
        .json::<AuthToken>()
        .await
        .map_err(|e| crate::Error::custom(format!("Failed to parse Hub API response: {}", e)))?;

    Ok(token)
}

// endregion: --- Auth Manager
