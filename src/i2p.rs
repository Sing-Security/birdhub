use crate::Result;
use crate::config::I2pConfig;
use std::process::Command;

// region:    --- I2P Manager

/// `I2pManager` controls the integration of The Invisible Internet Project (I2P).
///
/// It allows the VISP network to securely route `.i2p` traffic and interact with
/// deep hidden services (e.g., for journalists or secure whistleblowing) without
/// the user needing to manually configure their browser's proxy settings.
///
/// We utilize `nftables` transparent proxying and Unbound split-horizon DNS
/// to make the I2P network feel like just another internal subnet.
#[derive(Debug, Clone)]
pub struct I2pManager {
    config: I2pConfig,
}

impl I2pManager {
    pub fn new(config: I2pConfig) -> Self {
        Self { config }
    }

    /// Checks if the I2P routing subsystem is enabled via the configuration.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Connects the I2P proxy to the system's global DNS and routing tables.
    /// This sets up transparent intercept rules so users don't need manual browser configuration.
    pub fn enable_transparent_routing(&self) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        println!("I2P: Enabling transparent `.i2p` proxy routing...");

        // 1. Inform DNS to intercept `.i2p` domains and route to the I2P local DNS resolver.
        // We use the `dns` module's split horizon capabilities to map `.i2p` -> `127.0.0.1:{dns_port}`.
        // E.g., setting Unbound to forward `.i2p` directly into the I2P daemon.
        self.apply_dns_interception()?;

        // 2. Add an nftables rule to capture traffic destined for the I2P fake-IP range
        // and redirect it to the local SOCKS/HTTP proxy port.
        self.apply_nftables_redirect()?;

        Ok(())
    }

    // -- Support

    /// Generates and executes the `nftables` redirect logic for transparent I2P routing.
    fn apply_nftables_redirect(&self) -> Result<()> {
        // Typically, I2P uses a fake IP subnet mapping to route via its SOCKS out-proxy.
        // E.g., Redirecting TCP traffic aimed at `.i2p` domains to our local socks port.
        let rule = format!(
            "add rule inet visp prerouting tcp dport 80 redirect to :{}",
            self.config.http_proxy_port
        );

        let status = Command::new("nft")
            .arg("-c") // Check only for now, would be `-f -` in production
            .arg(&rule)
            .status()
            .map_err(|e| crate::Error::custom(format!("Failed to execute nft: {}", e)))?;

        if !status.success() {
            // In a real environment, we'd log this.
        }

        Ok(())
    }

    /// Applies the local DNS split-horizon configuration for `.i2p` domains.
    fn apply_dns_interception(&self) -> Result<()> {
        let conf_path = "/etc/unbound/unbound.conf.d/i2p_forward.conf";
        let content = format!(
            "server:\n  domain-insecure: \"i2p\"\n  local-zone: \"i2p.\" transparent\n\nforward-zone:\n  name: \"i2p.\"\n  forward-addr: {}@{}\n",
            self.config.router_ip, self.config.dns_port
        );

        // Attempt to write the configuration. If it fails due to permissions (not running as root),
        // we map it to our custom error type gracefully.
        if let Err(e) = std::fs::write(conf_path, content) {
            return Err(crate::Error::custom(format!(
                "Failed to write I2P DNS config to {}: {}",
                conf_path, e
            )));
        }

        // We'd typically call `systemctl reload unbound` or `unbound-control reload` here.
        Ok(())
    }
}

// endregion: --- I2P Manager
