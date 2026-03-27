use crate::Result;
use crate::health::{HealthMonitor, HealthStatus};
use std::time::Duration;
use tokio::time::sleep;

// region:    --- Watchdog Controller

/// `Watchdog` is the self-healing controller for the VISP network.
///
/// It orchestrates periodic health checks using the `HealthMonitor` and
/// automatically initiates remediation steps (like restarting tunnels,
/// switching exit nodes, or rebuilding routing tables) if any critical
/// component fails.
#[derive(Debug)]
pub struct Watchdog {
    monitor: HealthMonitor,
    check_interval: Duration,
}

impl Watchdog {
    /// Creates a new watchdog with the specified checking interval.
    pub fn new(check_interval_secs: u64) -> Self {
        Self {
            monitor: HealthMonitor::new(),
            check_interval: Duration::from_secs(check_interval_secs),
        }
    }

    /// Starts the continuous watchdog loop.
    /// This should be spawned as a background task.
    pub async fn start(&self) -> Result<()> {
        println!(
            "Watchdog: Started, running health checks every {:?}",
            self.check_interval
        );

        loop {
            sleep(self.check_interval).await;

            match self.monitor.run_all_checks().await {
                Ok(status) => {
                    if !status.is_healthy() {
                        println!("Watchdog: Health checks failed, initiating self-healing...");
                        if let Err(e) = self.handle_unhealthy_state(&status).await {
                            eprintln!("Watchdog: Self-healing error: {:?}", e);
                        }
                    } else {
                        // Systems are healthy; no action needed.
                    }
                }
                Err(e) => {
                    eprintln!("Watchdog: Failed to run health checks: {:?}", e);
                }
            }
        }
    }

    /// Evaluates specific failures in the health status and triggers the appropriate remediation.
    async fn handle_unhealthy_state(&self, status: &HealthStatus) -> Result<()> {
        // 1. Check for Leaks (Highest Priority Security)
        if !status.no_leaks {
            println!("Watchdog: Network leak detected! Enforcing strict kill-switch...");
            self.enforce_killswitch().await?;
            // A leak means we shouldn't proceed with regular routing until sealed.
        }

        // 2. Check Shadowsocks Transports
        if !status.ss_tunnels_alive {
            println!("Watchdog: Shadowsocks tunnels down. Restarting transport...");
            self.restart_transport().await?;
        }

        // 3. Check Exit Node Reachability & External DNS
        if !status.exit_http_ok || !status.external_dns_ok {
            println!(
                "Watchdog: Exit node unreachable or external DNS failing. Switching exit node..."
            );
            self.switch_exit_node().await?;
        }

        // 4. Check Internal Routing Integrity
        if !status.routing_ok {
            println!("Watchdog: Routing tables altered or missing. Re-applying routing rules...");
            self.reapply_routing().await?;
        }

        // 5. Check Mesh Integrity
        if !status.netbird_alive || !status.internal_dns_ok {
            println!("Watchdog: NetBird mesh connectivity issues. Restarting NetBird peer...");
            self.restart_netbird().await?;
        }

        Ok(())
    }

    // -- Self-Healing Actions

    /// Restarts the local Shadowsocks client instances.
    async fn restart_transport(&self) -> Result<()> {
        // TODO: Interface with the `shadowsocks` module to gracefully restart the local clients.
        Ok(())
    }

    /// Interfaces with the policy engine to select and route through a new healthy exit node.
    async fn switch_exit_node(&self) -> Result<()> {
        // TODO: Call the `policy` or `region` manager to find the next optimal exit and update state.
        Ok(())
    }

    /// Rebuilds the iproute2 tables and rules to ensure traffic flows correctly.
    async fn reapply_routing(&self) -> Result<()> {
        // TODO: Invoke the `routing` module to re-sync ip rules and routes (e.g., fwmark 0x1000).
        Ok(())
    }

    /// Immediately drops all outbound traffic to seal leaks until the tunnel is securely re-established.
    async fn enforce_killswitch(&self) -> Result<()> {
        // TODO: Call the `nft` module to apply a strict block-all policy, allowing only tunnel transport.
        Ok(())
    }

    /// Restarts the NetBird daemon or interface to restore mesh connectivity.
    async fn restart_netbird(&self) -> Result<()> {
        // TODO: Trigger a restart of the NetBird background service or interface via the `netbird` module.
        Ok(())
    }
}

// endregion: --- Watchdog Controller
