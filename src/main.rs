// region:    --- Modules

mod auth;
mod config;
mod crypto;
mod dns;
mod error;
mod gateway;
mod handshake;
mod health;
mod hub;
mod i2p;
mod leaks;
mod netbird;
mod nft;
mod policy;
mod region;
mod routing;
mod session;
mod transport;
mod watchdog;

pub use error::{Error, Result};

// endregion: --- Modules

use std::sync::Arc;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    println!("VISP Network Agent Starting...");

    // -- 1. Load Configuration
    let initial_config = config::AppConfig::load_from_file("config.toml").unwrap_or_else(|e| {
        println!(
            "Warning: Could not load config.toml ({}), using default configuration.",
            e
        );
        config::AppConfig {
            exit: config::ExitConfig {
                mode: config::ExitMode::Auto,
                primary: Some("us".to_string()),
                secondary: Some("eu".to_string()),
            },
            hubs: vec![],
            ..Default::default()
        }
    });

    println!(
        "Loaded configuration with {} hubs and {} transports configured.",
        initial_config.hubs.len(),
        initial_config.transports.len()
    );
    let _config_manager = Arc::new(config::ConfigManager::new(initial_config.clone()));

    // -- 2. Check App Mode (Hub vs Client)
    if initial_config.app.mode == config::AppMode::Hub {
        println!("Starting in Hub mode...");
        let bind_addr = &initial_config.hub_server.bind_address;
        let server_port = initial_config.hub_server.server_port;
        let rotation_interval = initial_config.hub_server.rotation_interval_secs;
        println!(
            "Binding Control API to {} and VISP Data Plane to port {} (Rotation: {}s)",
            bind_addr, server_port, rotation_interval
        );

        let hub_server = hub::Hub::new(bind_addr, server_port, rotation_interval).await?;
        hub_server.start().await?;
        return Ok(());
    }

    println!("Starting in Client mode...");

    // -- 3. Initialize NetBird Identity & Auth
    let netbird_manager = Arc::new(netbird::NetbirdManager::new());
    let identity = netbird_manager.get_identity().await?;
    println!("NetBird Identity: {} ({})", identity.hostname, identity.ip);

    let auth_manager = Arc::new(auth::AuthManager::new());
    let _gateway_manager = Arc::new(gateway::GatewayManager::new(auth_manager.clone()));

    // -- 4. Initialize Routing & nftables
    let nft_manager = Arc::new(nft::NftManager::new());
    let route_manager = Arc::new(routing::RouteManager::new());

    println!("Applying base firewall rules and routing tables...");
    nft_manager.apply_base_rules()?;
    nft_manager.enable_kill_switch()?;
    nft_manager.block_cleartext_dns()?;
    route_manager.reset_tables()?;

    // -- 5. Initialize DNS
    let dns_manager = Arc::new(dns::DnsManager::new());
    dns_manager.set_internal_zone(
        &initial_config.dns.internal_zone,
        &initial_config.dns.nameserver_ip,
    )?;

    // -- 6. Initialize I2P Transparent Proxying
    let i2p_manager = Arc::new(i2p::I2pManager::new(initial_config.i2p.clone()));
    if i2p_manager.is_enabled() {
        if let Err(e) = i2p_manager.enable_transparent_routing() {
            println!("Warning: Failed to enable I2P routing: {}", e);
        }
    }

    // -- 7. Start Transports
    if initial_config.transports.is_empty() {
        println!("No transports configured in config.toml. Skipping transport start.");
    } else {
        for t in &initial_config.transports {
            let transport_config = transport::TransportConfig {
                server_address: t.server_address.clone(),
                server_port: t.server_port,
                local_port: t.local_port,
                mark: t.mark,
            };

            let transport_manager = Arc::new(transport::TransportManager::new(transport_config));
            let transport_name = t.name.clone();
            tokio::spawn(async move {
                if let Err(e) = transport_manager.start_tunnel().await {
                    eprintln!("Transport '{}' failed: {}", transport_name, e);
                }
            });
        }
        println!("Transports started.");
    }

    // -- 8. Start Health Checks & Watchdog
    let watchdog = watchdog::Watchdog::new(initial_config.watchdog.check_interval_secs);
    let watchdog_task = tokio::spawn(async move {
        if let Err(e) = watchdog.start().await {
            eprintln!("Watchdog failed: {:?}", e);
        }
    });

    // -- 9. Apply Exit Policies (Initial)
    let policy_engine = policy::PolicyEngine::new();
    let network_context = policy::NetworkContext {
        netbird_alive: true,
        us_exit_latency_ms: Some(45),
        eu_exit_latency_ms: Some(120),
    };

    let decision = policy_engine.evaluate(&initial_config.exit, &network_context)?;
    println!("Initial Policy Decision: {:?}", decision);

    match decision {
        policy::ExitDecision::ShadowsocksRegion(region) => {
            println!("Routing traffic via {} region...", region);
            let region_enum = if region == "eu" {
                dns::DnsRegion::Eu
            } else {
                dns::DnsRegion::Us
            };
            dns_manager.switch_region(region_enum)?;
            // Apply routing rules accordingly...
        }
        policy::ExitDecision::NetbirdOnly => {
            println!("Routing traffic via NetBird only...");
            dns_manager.switch_region(dns::DnsRegion::NetbirdOnly)?;
        }
        policy::ExitDecision::DropAll => {
            println!("Dropping all traffic (Kill-switch active)...");
            nft_manager.enable_kill_switch()?;
        }
        policy::ExitDecision::LoadBalance(regions) => {
            println!("Load balancing across regions: {:?}", regions);
        }
    }

    println!("VISP Network Agent is running. Press Ctrl+C to exit.");

    // -- Wait for Shutdown Signal
    signal::ctrl_c().await.expect("Failed to listen for ctrl_c");
    println!("\nShutting down VISP Network Agent...");

    // Cleanup
    watchdog_task.abort();

    Ok(())
}
