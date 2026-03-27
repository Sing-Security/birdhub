use crate::Result;
use std::io::Write;
use std::process::{Command, Stdio};

// region:    --- Constants

#[allow(dead_code)]
pub const MARK_US_EXIT: u32 = 1;
#[allow(dead_code)]
pub const MARK_EU_EXIT: u32 = 2;
#[allow(dead_code)]
pub const MARK_NETBIRD: u32 = 3;

// endregion: --- Constants

// region:    --- Nft Manager

/// `NftManager` handles the atomic deployment of nftables rules.
///
/// It acts as the enforcement layer, ensuring no leaks occur outside the defined
/// Shadowsocks/NetBird tunnels and applying correct `fwmark` values for the `iproute2` tables.
#[derive(Debug, Clone, Default)]
pub struct NftManager;

impl NftManager {
    pub fn new() -> Self {
        Self
    }

    /// Atomically applies the base ruleset.
    /// By piping the full ruleset to `nft -f -`, we ensure zero partial-state failures.
    pub fn apply_base_rules(&self) -> Result<()> {
        let ruleset = self.generate_ruleset();

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| crate::Error::custom(format!("Failed to spawn nft: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(ruleset.as_bytes()).map_err(|e| {
                crate::Error::custom(format!("Failed to write to nft stdin: {}", e))
            })?;
        }

        let status = child
            .wait()
            .map_err(|e| crate::Error::custom(format!("Failed to wait for nft: {}", e)))?;

        if !status.success() {
            return Err(crate::Error::custom(format!(
                "nft -f - failed with status: {}",
                status
            )));
        }

        Ok(())
    }

    /// Engages the strict kill-switch.
    /// Blocks all outbound traffic that doesn't use the secure interfaces or bypass marks.
    pub fn enable_kill_switch(&self) -> Result<()> {
        let output = Command::new("nft")
            .args([
                "add",
                "rule",
                "inet",
                "visp",
                "filter_out",
                "meta",
                "mark",
                "0",
                "drop",
            ])
            .output()
            .map_err(|e| crate::Error::custom(format!("Failed to execute nft command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::Error::custom(format!(
                "nft kill switch rule failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Blocks standard port 53 UDP/TCP traffic to prevent ISP DNS leaks.
    pub fn block_cleartext_dns(&self) -> Result<()> {
        let rules = [
            [
                "add",
                "rule",
                "inet",
                "visp",
                "filter_out",
                "udp",
                "dport",
                "53",
                "drop",
            ],
            [
                "add",
                "rule",
                "inet",
                "visp",
                "filter_out",
                "tcp",
                "dport",
                "53",
                "drop",
            ],
        ];

        for args in rules {
            let output = Command::new("nft").args(args).output().map_err(|e| {
                crate::Error::custom(format!("Failed to execute nft command: {}", e))
            })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(crate::Error::custom(format!(
                    "nft dns block rule failed: {}",
                    stderr
                )));
            }
        }

        Ok(())
    }

    // -- Support

    /// Generates the raw nftables configuration string.
    /// Uses static string slices to avoid unnecessary allocations.
    #[allow(dead_code)]
    fn generate_ruleset(&self) -> &'static str {
        concat!(
            "flush ruleset\n",
            "table inet visp {\n",
            "    chain prerouting {\n",
            "        type filter hook prerouting priority mangle; policy accept;\n",
            "    }\n",
            "    chain output {\n",
            "        type route hook output priority mangle; policy accept;\n",
            "        # Policy routing marks applied here based on destination / process\n",
            "    }\n",
            "    chain filter_out {\n",
            "        type filter hook output priority filter; policy accept;\n",
            "        # Kill switch & leak protection drop rules applied here\n",
            "    }\n",
            "}\n"
        )
    }
}

// endregion: --- Nft Manager
