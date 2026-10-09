//! `birdhub-console <config.toml>` — the fleet console: the hub or the node
//! the config describes, embedded, with the same shell splicer and noxgraph
//! render through.
//!
//! One process, Splicer's exact division: the core runs on its own tokio
//! runtime on its own thread (eframe wants the native event loop on the
//! thread it started on), the control API is a task on that runtime, and the
//! egui frontend runs on the main thread. The console's buttons and the API
//! call the same functions, so the two surfaces cannot drift.

use birdhub::config::{AppConfig, AppMode};
use birdhub::control::{self, ApiState};
use birdhub::events::EventLog;
use birdhub::{hub, transport};
use birdhub_console::app::ConsoleApp;
use birdhub_console::backend::Backend;
use std::sync::Arc;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());
    let config = load_config(&path);
    let mode = config.app.mode;

    // The core is built on the runtime thread and handed back through this
    // channel; the UI waits for it, so a build failure (bad config, bad
    // certificate) is reported before a window exists.
    let (tx, rx) = std::sync::mpsc::channel();
    let runtime = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
    std::thread::spawn(move || {
        runtime.block_on(async move {
            let outcome = match mode {
                AppMode::Hub => run_hub(&path, config)
                    .await
                    .map(|(shared, api)| Backend::Hub { shared, api }),
                AppMode::Client => run_node(config)
                    .await
                    .map(|(link, ctx, api)| Backend::Node { link, ctx, api }),
            };
            // The send failing just means the UI gave up first — the core
            // task can stop, its work is moot.
            let _ = tx.send(outcome);
            std::future::pending::<()>().await
        });
    });

    let backend = match rx.recv() {
        Ok(Ok(backend)) => backend,
        Ok(Err(message)) => {
            eprintln!("birdhub-console: {message}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("birdhub-console: the core task stopped before starting");
            std::process::exit(1);
        }
    };

    let options = eframe::NativeOptions::default();
    let title = if matches!(backend, Backend::Hub { .. }) {
        "BIRDHUB — hub"
    } else {
        "BIRDHUB — node"
    };
    eframe::run_native(
        title,
        options,
        Box::new(move |cc| {
            birdhub_console::theme::apply(cc);
            Ok(Box::new(ConsoleApp::new(backend)))
        }),
    )
    .expect("failed to start the console window");
}

/// The config path's config, or a clean exit naming the problem — a window
/// that cannot open is better than a window over a dead core.
fn load_config(path: &str) -> AppConfig {
    let config = match AppConfig::load_from_file(path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("birdhub-console: {}", e.message());
            std::process::exit(1);
        }
    };
    if let Err(e) = config.validate() {
        eprintln!("birdhub-console: {}", e.message());
        std::process::exit(1);
    }
    config
}

/// Build the hub and start its control API; the hub's accept loop runs in
/// this task, on the runtime thread.
async fn run_hub(
    path: &str,
    config: AppConfig,
) -> std::result::Result<(Arc<birdhub::hub::HubShared>, Option<std::net::SocketAddr>), String> {
    let hub = hub::Hub::build(config, path, EventLog::quiet()).map_err(|e| e.message())?;
    let shared = hub.shared();
    let api = control::spawn(
        ApiState::Hub {
            shared: shared.clone(),
        },
        hub.control_config(),
    )
    .await
    .map_err(|e| e.message())?;
    // The accept loop never returns; it is the core this window renders.
    tokio::spawn(async move {
        if let Err(e) = hub.run().await {
            eprintln!("birdhub-console: hub exited: {}", e.message());
        }
    });
    Ok((shared, api))
}

/// Build the node, start its control API, and spawn its supervisor and
/// listeners; the node then runs on the runtime thread.
async fn run_node(
    config: AppConfig,
) -> std::result::Result<
    (
        Arc<birdhub::node::NodeLink>,
        Arc<birdhub::node::NodeContext>,
        Option<std::net::SocketAddr>,
    ),
    String,
> {
    let control = config.control.clone();
    let link = Arc::new(transport::build(config, EventLog::quiet()).map_err(|e| e.message())?);
    let ctx = link.context();
    let api = control::spawn(
        ApiState::Node {
            ctx: ctx.clone(),
            link: link.clone(),
        },
        control,
    )
    .await
    .map_err(|e| e.message())?;
    // The node's tasks are spawned onto this runtime; the UI reads their
    // state through the link.
    transport::spawn_all(&link);
    Ok((link, ctx, api))
}
