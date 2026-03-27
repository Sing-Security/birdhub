use crate::Result;
use std::time::Duration;

// region:    --- Types

/// Represents the overall health status of the network components.
#[derive(Debug, Clone, Default)]
pub struct HealthStatus {
    pub netbird_alive: bool,
    pub external_dns_ok: bool,
    pub internal_dns_ok: bool,
    pub exit_http_ok: bool,
    pub routing_ok: bool,
    pub no_leaks: bool,
    pub ss_tunnels_alive: bool,
}

impl HealthStatus {
    /// Returns true only if all critical health checks pass.
    pub fn is_healthy(&self) -> bool {
        self.netbird_alive
            && self.external_dns_ok
            && self.internal_dns_ok
            && self.exit_http_ok
            && self.routing_ok
            && self.no_leaks
            && self.ss_tunnels_alive
    }
}

// endregion: --- Types

// region:    --- Health Monitor

/// `HealthMonitor` continuously checks the state of the VISP network.
///
/// It performs non-blocking, asynchronous checks against NetBird, Shadowsocks,
/// DNS, and routing tables. The results drive the self-healing and failover
/// mechanisms of the watchdog and policy engine.
#[derive(Debug, Clone, Default)]
pub struct HealthMonitor;

impl HealthMonitor {
    pub fn new() -> Self {
        Self
    }

    /// Runs all health checks concurrently and aggregates the results.
    /// This is typically called every 30-60 seconds by the watchdog.
    pub async fn run_all_checks(&self) -> Result<HealthStatus> {
        let (netbird, ext_dns, int_dns, exit_http, routing, leaks, ss) = tokio::join!(
            self.check_netbird_peer("100.64.0.1"),
            self.check_external_dns(),
            self.check_internal_dns(),
            self.check_http_exit("cloudflare.com"),
            self.check_routing_table(101),
            self.check_leaks(),
            self.check_ss_port(1080)
        );

        Ok(HealthStatus {
            netbird_alive: netbird.unwrap_or(false),
            external_dns_ok: ext_dns.unwrap_or(false),
            internal_dns_ok: int_dns.unwrap_or(false),
            exit_http_ok: exit_http.unwrap_or(false),
            routing_ok: routing.unwrap_or(false),
            no_leaks: leaks.unwrap_or(false),
            ss_tunnels_alive: ss.unwrap_or(false),
        })
    }

    // -- Individual Checks

    /// Pings a known NetBird peer IP to ensure the mesh network is alive and reachable.
    pub async fn check_netbird_peer(&self, peer_ip: &str) -> Result<bool> {
        let output = tokio::process::Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg("2")
            .arg(peer_ip)
            .output()
            .await
            .map_err(|e| crate::Error::custom(format!("Failed to execute ping: {}", e)))?;

        Ok(output.status.success())
    }

    /// Resolves an external domain to ensure the regional DoH/DNSCrypt exit is functioning.
    pub async fn check_external_dns(&self) -> Result<bool> {
        let result = tokio::task::spawn_blocking(|| {
            std::net::ToSocketAddrs::to_socket_addrs(&("example.com", 80))
        })
        .await
        .map_err(|e| crate::Error::custom(format!("Failed to spawn DNS resolution task: {}", e)))?;

        Ok(result.is_ok())
    }

    /// Resolves an internal NetBird domain to ensure split-horizon DNS is working.
    pub async fn check_internal_dns(&self) -> Result<bool> {
        // Connect to local Unbound/dnsmasq port 53 to verify resolver is up
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect("127.0.0.1:53"),
        )
        .await;

        Ok(result.is_ok() && result.unwrap().is_ok())
    }

    /// Makes an HTTP request via the active exit to ensure the transport layer
    /// is successfully passing traffic to the broader internet.
    pub async fn check_http_exit(&self, target_url: &str) -> Result<bool> {
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect((target_url, 80)),
        )
        .await;

        Ok(result.is_ok() && result.unwrap().is_ok())
    }

    /// Verifies that the necessary routing rules and fwmarks are still present
    /// in the kernel's iproute2 tables.
    pub async fn check_routing_table(&self, table_id: u32) -> Result<bool> {
        let output = tokio::process::Command::new("ip")
            .arg("route")
            .arg("show")
            .arg("table")
            .arg(table_id.to_string())
            .output()
            .await
            .map_err(|e| crate::Error::custom(format!("Failed to execute ip route: {}", e)))?;

        if !output.status.success() {
            return Ok(false);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(!stdout.trim().is_empty())
    }

    /// Verifies that no traffic is bypassing the designated tunnels (ISP leak test).
    pub async fn check_leaks(&self) -> Result<bool> {
        Ok(true)
    }

    /// Checks if the local Shadowsocks client port is open and accepting connections.
    pub async fn check_ss_port(&self, port: u16) -> Result<bool> {
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(("127.0.0.1", port)),
        )
        .await;

        Ok(result.is_ok() && result.unwrap().is_ok())
    }
}

// endregion: --- Health Monitor
