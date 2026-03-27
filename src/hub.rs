// region: --- Modules & Imports
use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    routing::get,
};
use rand::{RngExt, distr::Alphanumeric};
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio::process::Child;
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};

use crate::{Error, Result};
// endregion: --- Modules & Imports

// region: --- Types
#[derive(Clone)]
pub struct HubState {
    pub password: Arc<RwLock<String>>,
    pub server_port: u16,
    pub method: String,
    // Mocking the netbird manager representation
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub password: String,
    pub server_port: u16,
    pub method: String,
}
// endregion: --- Types

// region: --- Hub Server
pub struct Hub {
    bind_addr: String,
    ss_port: u16,
}

impl Hub {
    pub fn new(bind_addr: impl Into<String>, ss_port: u16) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            ss_port,
        }
    }

    pub async fn start(self) -> Result<()> {
        let method = "aes-256-gcm".to_string();

        let initial_password = generate_password();
        let password_state = Arc::new(RwLock::new(initial_password.clone()));

        let shared_state = HubState {
            password: password_state.clone(),
            server_port: self.ss_port,
            method: method.clone(),
        };

        // Spawn initial ss-server
        let mut ss_child = spawn_ss_server(self.ss_port, &method, &initial_password)?;

        // Spawn key rotation loop
        let password_ref = password_state.clone();
        let ss_port_ref = self.ss_port;
        let method_ref = method.clone();

        tokio::spawn(async move {
            loop {
                // Rotate every hour
                sleep(Duration::from_secs(3600)).await;

                let new_password = generate_password();
                println!("Hub: Rotating Shadowsocks Password...");

                // Update shared state for new authentications
                {
                    let mut pwd_lock = password_ref.write().await;
                    *pwd_lock = new_password.clone();
                }

                // Kill old server and start a new one with the new password
                if let Err(e) = ss_child.kill().await {
                    eprintln!("Hub: Failed to kill old ss-server: {}", e);
                }

                match spawn_ss_server(ss_port_ref, &method_ref, &new_password) {
                    Ok(new_child) => {
                        ss_child = new_child;
                        println!("Hub: Password rotation complete. New server spawned.");
                    }
                    Err(e) => {
                        eprintln!("Hub: Failed to spawn new ss-server during rotation: {}", e)
                    }
                }
            }
        });

        // Start Axum API
        let app = Router::new()
            .route("/auth", get(auth_handler))
            .with_state(shared_state);

        let listener = TcpListener::bind(&self.bind_addr)
            .await
            .map_err(|e| Error::custom(format!("Failed to bind to {}: {}", self.bind_addr, e)))?;

        println!("Hub Control Plane listening on {}", self.bind_addr);

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| Error::custom(format!("Axum server error: {}", e)))?;

        Ok(())
    }
}

// -- Support functions
fn generate_password() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn spawn_ss_server(port: u16, method: &str, password: &str) -> Result<Child> {
    Command::new("ss-server")
        .arg("-s")
        .arg("0.0.0.0")
        .arg("-p")
        .arg(port.to_string())
        .arg("-m")
        .arg(method)
        .env("SS_PASSWORD", password)
        .spawn()
        .map_err(|e| Error::custom(format!("Failed to spawn ss-server: {}", e)))
}
// endregion: --- Hub Server

// region: --- Handlers
async fn auth_handler(
    State(state): State<HubState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> std::result::Result<Json<AuthResponse>, axum::http::StatusCode> {
    let ip = addr.ip();

    // Verify the caller's IP is a valid NetBird peer
    if !is_valid_netbird_peer(ip) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }

    let password = state.password.read().await.clone();

    Ok(Json(AuthResponse {
        password,
        server_port: state.server_port,
        method: state.method.clone(),
    }))
}

/// Mock representation of `netbird::NetbirdManager` verification
fn is_valid_netbird_peer(ip: std::net::IpAddr) -> bool {
    // In a real implementation, you would query the NetBird manager here.
    // For demonstration, we'll assume IPs in the 100.64.0.0/10 range are valid peers.
    if let std::net::IpAddr::V4(ipv4) = ip {
        let octets = ipv4.octets();
        if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
            return true;
        }
    }
    false
}
// endregion: --- Handlers
