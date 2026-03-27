use crate::Result;
use crate::config::{ExitConfig, ExitMode};

// region:    --- Types

/// Represents the outcome of a policy evaluation.
/// Dictates which transport and region should handle outbound traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitDecision {
    /// Route traffic exclusively through the NetBird mesh.
    NetbirdOnly,
    /// Route traffic through a specific regional Shadowsocks exit.
    /// Uses a static string slice to avoid allocation for known region identifiers.
    ShadowsocksRegion(&'static str),
    /// Split traffic (e.g., Load Balancing) across multiple regions.
    LoadBalance(Vec<&'static str>),
    /// Block all traffic (Kill-switch / no valid exit).
    DropAll,
}

/// Represents the current health and latency state of available network paths.
/// Passed into the policy engine to inform dynamic decisions.
#[derive(Debug, Clone, Default)]
pub struct NetworkContext {
    pub netbird_alive: bool,
    pub us_exit_latency_ms: Option<u32>,
    pub eu_exit_latency_ms: Option<u32>,
}

// endregion: --- Types

// region:    --- Policy Engine

/// `PolicyEngine` acts as the brain of the routing architecture.
///
/// It consumes the current configuration (`ExitConfig`) and live network metrics
/// (`NetworkContext`) to make zero-allocation decisions about where packets
/// should exit the network.
#[derive(Debug, Clone, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates the current configuration and network health to determine the optimal exit.
    ///
    /// This method represents the core decision loop. It dynamically shifts routing
    /// strategies based on the selected mode (e.g., failing over if the primary is down,
    /// or selecting the lowest latency path).
    pub fn evaluate(&self, config: &ExitConfig, context: &NetworkContext) -> Result<ExitDecision> {
        match config.mode {
            ExitMode::Auto => {
                // Auto: Try NetBird direct first, fallback to lowest latency SS exit.
                if context.netbird_alive {
                    Ok(ExitDecision::NetbirdOnly)
                } else {
                    self.evaluate_latency_mode(context)
                }
            }
            ExitMode::Netbird => {
                if context.netbird_alive {
                    Ok(ExitDecision::NetbirdOnly)
                } else {
                    Ok(ExitDecision::DropAll) // Strict mesh-only policy
                }
            }
            ExitMode::Latency => self.evaluate_latency_mode(context),
            ExitMode::Failover => {
                // Determine primary vs backup based on config strings
                let primary = config.primary.as_deref().unwrap_or("us");
                let backup = config.secondary.as_deref().unwrap_or("eu");

                if self.is_region_healthy(primary, context) {
                    // We must map the string to our static region identifiers (in a real app, use an Enum).
                    Ok(ExitDecision::ShadowsocksRegion(self.map_region(primary)))
                } else if self.is_region_healthy(backup, context) {
                    Ok(ExitDecision::ShadowsocksRegion(self.map_region(backup)))
                } else {
                    Ok(ExitDecision::DropAll)
                }
            }
            ExitMode::LoadBalance => {
                // Route traffic across both US and EU if both are healthy
                let mut active_regions = Vec::with_capacity(2);
                if context.us_exit_latency_ms.is_some() {
                    active_regions.push("us");
                }
                if context.eu_exit_latency_ms.is_some() {
                    active_regions.push("eu");
                }

                if active_regions.is_empty() {
                    Ok(ExitDecision::DropAll)
                } else {
                    Ok(ExitDecision::LoadBalance(active_regions))
                }
            }
            ExitMode::Manual => {
                let primary = config.primary.as_deref().unwrap_or("us");
                Ok(ExitDecision::ShadowsocksRegion(self.map_region(primary)))
            }
            _ => {
                // Fallback for Geo, Mobile, Reroute until specifically implemented
                Ok(ExitDecision::ShadowsocksRegion("us"))
            }
        }
    }

    // -- Support

    /// Evaluates the lowest latency exit.
    fn evaluate_latency_mode(&self, context: &NetworkContext) -> Result<ExitDecision> {
        match (context.us_exit_latency_ms, context.eu_exit_latency_ms) {
            (Some(us), Some(eu)) => {
                if us <= eu {
                    Ok(ExitDecision::ShadowsocksRegion("us"))
                } else {
                    Ok(ExitDecision::ShadowsocksRegion("eu"))
                }
            }
            (Some(_), None) => Ok(ExitDecision::ShadowsocksRegion("us")),
            (None, Some(_)) => Ok(ExitDecision::ShadowsocksRegion("eu")),
            (None, None) => Ok(ExitDecision::DropAll),
        }
    }

    /// Checks if a named region has valid latency metrics (i.e., is healthy).
    fn is_region_healthy(&self, region: &str, context: &NetworkContext) -> bool {
        match region {
            "us" => context.us_exit_latency_ms.is_some(),
            "eu" => context.eu_exit_latency_ms.is_some(),
            _ => false,
        }
    }

    /// Maps a dynamic string to a static string slice identifier.
    fn map_region(&self, region: &str) -> &'static str {
        match region {
            "eu" => "eu",
            _ => "us", // Default to US to avoid allocating strings
        }
    }
}

// endregion: --- Policy Engine
