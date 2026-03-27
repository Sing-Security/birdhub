use crate::Result;
use crate::auth::fetch_hub_credentials;
use log::info;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct ShadowsocksConfig {
    pub server_address: String,
    pub server_port: u16,
    pub password: Option<String>,
    pub method: String,
    pub local_port: u16,
    pub mark: Option<u32>, // Optional fwmark for policy routing
}

pub struct ShadowsocksManager;

impl ShadowsocksManager {
    pub fn new() -> Self {
        Self
    }

    pub async fn start_tunnel(&self, config: &ShadowsocksConfig) -> Result<()> {
        let password = if let Some(pwd) = &config.password {
            pwd.clone()
        } else {
            // Fetch dynamic credentials from the Hub
            let hub_api_url = format!("http://{}:8080/auth", config.server_address);
            let credentials = fetch_hub_credentials(&hub_api_url).await?;
            credentials.password
        };

        info!("Starting ss-local for hub {}", config.server_address);

        // Spawn ss-local and pass the password securely via environment variables
        let mut cmd = Command::new("ss-local");
        cmd.arg("-s")
            .arg(&config.server_address)
            .arg("-p")
            .arg(config.server_port.to_string())
            .arg("-l")
            .arg(config.local_port.to_string())
            .arg("-m")
            .arg(&config.method)
            .env("SS_PASSWORD", password)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if let Some(_mark) = config.mark {
            // Placeholder: Implementation specific to fwmark if needed
        }

        cmd.spawn()
            .map_err(|e| crate::Error::custom(format!("Failed to spawn ss-local: {}", e)))?;

        info!("ss-local started successfully.");

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn restart_tunnel(&self, _local_port: u16) -> Result<()> {
        Ok(())
    }
}
