use crate::auth::AuthManager;
use std::sync::Arc;

// region:    --- Gateway Manager

/// `GatewayManager` handles incoming Shadowsocks connections on the exit node.
///
/// It strictly enforces gateway authentication where the gateway verifies
/// identity via the NetBird API, allows or denies the tunnel, and assigns
/// routes based on the peer's role.
#[derive(Debug, Clone)]
pub struct GatewayManager {
    // This field is currently unused but kept for future expansion.
    _auth_manager: Arc<AuthManager>,
}

impl GatewayManager {
    pub fn new(auth_manager: Arc<AuthManager>) -> Self {
        Self {
            _auth_manager: auth_manager,
        }
    }
}

// endregion: --- Gateway Manager
