use crate::Result;
use std::process::Command;

// region:    --- Constants

pub const TABLE_US_EXIT: u32 = 101;
pub const TABLE_EU_EXIT: u32 = 102;
pub const TABLE_NETBIRD: u32 = 103;

// endregion: --- Constants

// region:    --- Route Manager

/// `RouteManager` handles multi-exit and policy routing via Linux `iproute2`.
///
/// It strictly separates routes into different tables (`nb`, `us_exit`, `eu_exit`)
/// and relies on `fwmark` rules (managed in conjunction with `nft.rs`) to
/// dictate path selection atomically and safely.
#[derive(Debug, Clone, Default)]
pub struct RouteManager;

impl RouteManager {
    pub fn new() -> Self {
        Self
    }

    /// Flushes all custom routing tables to ensure a clean, zero-state baseline
    /// before applying new routes.
    pub fn reset_tables(&self) -> Result<()> {
        self.flush_table(TABLE_US_EXIT)?;
        self.flush_table(TABLE_EU_EXIT)?;
        self.flush_table(TABLE_NETBIRD)?;
        Ok(())
    }

    // -- Support

    /// Helper to flush a specific routing table entirely.
    fn flush_table(&self, table_id: u32) -> Result<()> {
        let status = Command::new("ip")
            .args(["route", "flush", "table", &table_id.to_string()])
            .status()
            .map_err(|e| {
                crate::Error::custom(format!("Failed to execute ip route flush: {}", e))
            })?;

        if !status.success() {
            return Err(crate::Error::custom(format!(
                "ip route flush failed with status: {}",
                status
            )));
        }
        Ok(())
    }
}

// endregion: --- Route Manager
