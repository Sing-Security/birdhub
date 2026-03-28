use crate::Result;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// region:    --- Types

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ExitMode {
    #[default]
    Auto,
    Netbird,
    Mobile,
    Reroute,
    Geo,
    Latency,
    LoadBalance,
    Failover,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExitConfig {
    pub mode: ExitMode,
    pub primary: Option<String>,
    pub secondary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConfig {
    pub name: String,
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub is_primary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetbirdConfig {
    #[serde(default = "default_netbird_interface")]
    pub interface: String,
    #[serde(default = "default_management_url")]
    pub management_url: String,
    #[serde(default)]
    pub admin_api_token: Option<String>,
    #[serde(default)]
    pub setup_key: Option<String>,
    #[serde(default)]
    pub network_identifier: String,
}

fn default_netbird_interface() -> String {
    "wt0".to_string()
}

fn default_management_url() -> String {
    "https://api.netbird.io".to_string()
}

impl Default for NetbirdConfig {
    fn default() -> Self {
        Self {
            interface: default_netbird_interface(),
            management_url: default_management_url(),
            admin_api_token: None,
            setup_key: None,
            network_identifier: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_internal_zone")]
    pub internal_zone: String,
    #[serde(default = "default_nameserver_ip")]
    pub nameserver_ip: String,
}

fn default_internal_zone() -> String {
    "netbird.cloud".to_string()
}

fn default_nameserver_ip() -> String {
    "100.64.0.1".to_string()
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            internal_zone: default_internal_zone(),
            nameserver_ip: default_nameserver_ip(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchdogConfig {
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,
}

fn default_check_interval() -> u64 {
    30
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: default_check_interval(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub name: String,
    pub server_address: String,
    pub server_port: u16,
    pub local_port: u16,
    pub mark: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct I2pConfig {
    #[serde(default = "default_i2p_enabled")]
    pub enabled: bool,
    #[serde(default = "default_i2p_router_ip")]
    pub router_ip: String,
    #[serde(default = "default_i2p_http_proxy_port")]
    pub http_proxy_port: u16,
    #[serde(default = "default_i2p_socks_proxy_port")]
    pub socks_proxy_port: u16,
    #[serde(default = "default_i2p_dns_port")]
    pub dns_port: u16,
}

fn default_i2p_enabled() -> bool {
    false
}
fn default_i2p_router_ip() -> String {
    "127.0.0.1".to_string()
}
fn default_i2p_http_proxy_port() -> u16 {
    4444
}
fn default_i2p_socks_proxy_port() -> u16 {
    4446
}
fn default_i2p_dns_port() -> u16 {
    4447
}

impl Default for I2pConfig {
    fn default() -> Self {
        Self {
            enabled: default_i2p_enabled(),
            router_ip: default_i2p_router_ip(),
            http_proxy_port: default_i2p_http_proxy_port(),
            socks_proxy_port: default_i2p_socks_proxy_port(),
            dns_port: default_i2p_dns_port(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubServerConfig {
    #[serde(default = "default_hub_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_hub_server_port")]
    pub server_port: u16,
    #[serde(default = "default_rotation_interval")]
    pub rotation_interval_secs: u64,
}

fn default_hub_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_hub_server_port() -> u16 {
    8388
}

fn default_rotation_interval() -> u64 {
    3600 // Default to 1 hour
}

impl Default for HubServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_hub_bind_address(),
            server_port: default_hub_server_port(),
            rotation_interval_secs: default_rotation_interval(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub app: AppConfigSection,
    #[serde(default)]
    pub exit: ExitConfig,
    #[serde(default)]
    pub hubs: Vec<HubConfig>,
    #[serde(default)]
    pub transports: Vec<TransportConfig>,
    #[serde(default)]
    pub netbird: NetbirdConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub watchdog: WatchdogConfig,
    #[serde(default)]
    pub i2p: I2pConfig,
    #[serde(default)]
    pub hub_server: HubServerConfig,
}

impl AppConfig {
    /// Loads configuration from a TOML file.
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::Error::custom(format!("Failed to read config file '{}': {}", path, e))
        })?;
        let config: AppConfig = toml::from_str(&content).map_err(|e| {
            crate::Error::custom(format!("Failed to parse config file '{}': {}", path, e))
        })?;
        Ok(config)
    }
}

// endregion: --- Types

// region:    --- Config Manager

/// `ConfigManager` provides lock-free, zero-copy access to the current configuration.
/// Using `ArcSwap` ensures that readers (routing, health checks, etc.) are never blocked
/// by configuration reloads, adhering to atomic and zero-copy principles.
pub struct ConfigManager {
    #[allow(dead_code)]
    current: ArcSwap<AppConfig>,
}

impl ConfigManager {
    pub fn new(initial: AppConfig) -> Self {
        Self {
            current: ArcSwap::from_pointee(initial),
        }
    }

    /// Returns an `Arc<AppConfig>`, providing a cheap, lock-free snapshot of the configuration.
    #[allow(dead_code)]
    pub fn load(&self) -> Arc<AppConfig> {
        self.current.load().clone()
    }
}

// endregion: --- Config Manager
