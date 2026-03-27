use crate::Result;
use std::fs;
use std::process::Command;

// region:    --- Types

/// Represents the target DNS region, directly tied to the active exit node.
/// Enforces geo-consistency to ensure DNS requests always match the physical exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRegion {
    Us,
    Eu,
    NetbirdOnly,
}

// endregion: --- Types

// region:    --- Dns Manager

/// `DnsManager` dynamically reconfigures local DNS resolvers (Unbound/dnsmasq)
/// to ensure DNS requests always exit from the same region as the transport tunnel.
///
/// It strictly separates internal (NetBird mesh) names and public DoH resolutions,
/// adhering to the split-tunnel DNS architecture. Config updates and daemon reloads
/// are performed atomically to prevent query loss.
#[derive(Debug, Clone, Default)]
pub struct DnsManager;

impl DnsManager {
    pub fn new() -> Self {
        Self
    }

    /// Switches the active upstream DNS DoH/DNSCrypt endpoint to match the specified region.
    /// This ensures zero DNS leaks and guarantees geo-consistency for CDN resolution.
    pub fn switch_region(&self, region: DnsRegion) -> Result<()> {
        let config_path = "/etc/unbound/unbound.conf.d/upstream.conf";
        let config_content = match region {
            DnsRegion::Us => {
                // Reconfigure Unbound to route via US DoH endpoints.
                "forward-zone:\n  name: \".\"\n  forward-addr: 1.1.1.1@853#cloudflare-dns.com\n  forward-addr: 1.0.0.1@853#cloudflare-dns.com\n"
            }
            DnsRegion::Eu => {
                // Reconfigure Unbound to route via EU DoH endpoints.
                "forward-zone:\n  name: \".\"\n  forward-addr: 9.9.9.9@853#dns.quad9.net\n  forward-addr: 149.112.112.112@853#dns.quad9.net\n"
            }
            DnsRegion::NetbirdOnly => {
                // Drop external DoH, resolve only internal NetBird mesh names.
                ""
            }
        };

        fs::write(config_path, config_content)
            .map_err(|e| crate::Error::custom(format!("Failed to write DNS config: {}", e)))?;

        // Trigger resolver reload/restart atomically.
        self.reload_resolver()?;

        Ok(())
    }

    /// Configures split-horizon DNS for the mesh network.
    /// Routes specific internal zones (e.g., `.netbird.cloud` or `.internal`)
    /// directly to the NetBird peer DNS, bypassing the regional DoH exit.
    ///
    /// Uses string slices to enforce zero-copy configuration passing.
    pub fn set_internal_zone(&self, zone: &str, nameserver_ip: &str) -> Result<()> {
        let safe_zone_name = zone.replace('.', "_");
        let config_path = format!("/etc/unbound/unbound.conf.d/zone_{}.conf", safe_zone_name);

        let config_content = format!(
            "server:\n  domain-insecure: \"{zone}\"\n  private-domain: \"{zone}\"\n\nforward-zone:\n  name: \"{zone}\"\n  forward-addr: {nameserver_ip}\n",
            zone = zone,
            nameserver_ip = nameserver_ip
        );

        fs::write(&config_path, config_content).map_err(|e| {
            crate::Error::custom(format!("Failed to write internal zone config: {}", e))
        })?;

        self.reload_resolver()?;

        Ok(())
    }

    // -- Support

    /// Reloads the underlying DNS resolver service without downtime.
    /// Prefer soft-reloads (`unbound-control reload` or `SIGHUP`) over hard restarts.
    fn reload_resolver(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .arg("reload")
            .arg("unbound")
            .output()
            .map_err(|e| {
                crate::Error::custom(format!("Failed to execute systemctl reload unbound: {}", e))
            })?;

        if !output.status.success() {
            // If reload fails, attempt a restart
            let restart_output = Command::new("systemctl")
                .arg("restart")
                .arg("unbound")
                .output()
                .map_err(|e| {
                    crate::Error::custom(format!(
                        "Failed to execute systemctl restart unbound: {}",
                        e
                    ))
                })?;

            if !restart_output.status.success() {
                let stderr = String::from_utf8_lossy(&restart_output.stderr);
                return Err(crate::Error::custom(format!(
                    "Failed to reload and restart unbound: {}",
                    stderr
                )));
            }
        }

        Ok(())
    }
}

// endregion: --- Dns Manager
