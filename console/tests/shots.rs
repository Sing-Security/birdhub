//! Headless screenshots of the real views — noxgraph's harness (`egui_kittest`
//! builds the actual `ConsoleApp` through `eframe` on the same wgpu backend
//! the window uses), pointed at deterministic fixture data instead of a live
//! fleet. What a test renders is what a user sees, and a screenshot can be
//! looked at without sitting in front of it.
//!
//! The fixtures are `ConsoleData` built by hand — no network, no keys. Where
//! no GPU adapter will actually open (a headless CI box, or a hybrid-GPU
//! desktop whose dGPU driver dies at vkCreateDevice — seen on this desk) the
//! shots print why and skip; the action test below needs no GPU and always
//! runs.

use birdhub_console::app::ConsoleApp;
use birdhub_console::backend::Backend;
use birdhub_console::data::{ConsoleData, EventRow, GrantRow, SessionRow};
use egui_kittest::Harness;
use egui_wgpu::{wgpu, WgpuSetup};
use std::sync::{Arc, Mutex};

/// A fixture backend plus its action recorder.
fn fixture() -> (Backend, Arc<Mutex<Vec<birdhub_console::backend::Action>>>) {
    let recorder = Arc::new(Mutex::new(Vec::new()));
    (Backend::Fixture(recorder.clone()), recorder)
}

/// Where the pictures go — beside the workspace, like noxgraph's `shots/`.
const SHOTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../shots");

/// A hub's worth of fixture data: three sessions, a roster, and a log with
/// one of each event kind.
fn hub_fixture() -> ConsoleData {
    let mut data = ConsoleData::empty();
    data.mode = "hub".to_string();
    data.subject = "hub.example".to_string();
    data.key_id = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_string();
    data.cert_id = "ebe273e44231d9d434c3673f148c9366dd2027da8fd28123677c653f7c031b25".to_string();
    data.not_before = 1_791_567_010;
    data.not_after = 1_823_103_010;
    data.config_path = Some("/etc/birdhub/hub-config.toml".to_string());
    data.config_text = Some(FIXTURE_CONFIG.to_string());
    data.sessions = vec![
        session(11, "laptop.example", "7cd2ff07", 1_791_571_000, 2),
        session(12, "desktop.example", "b162a899", 1_791_571_500, 0),
        session(13, "build-box.example", "9f3c01aa", 1_791_572_000, 1),
    ];
    data.roster = vec![
        GrantRow {
            client: "laptop.example".to_string(),
            targets: vec!["origin:80".to_string()],
        },
        GrantRow {
            client: "desktop.example".to_string(),
            targets: vec!["@peer/laptop.example".to_string()],
        },
        GrantRow {
            client: "build-box.example".to_string(),
            targets: Vec::new(),
        },
    ];
    data.events_cursor = 5;
    let lines: [(&str, bool, &str); 5] = [
        ("Hub: data plane on 0.0.0.0:8388", false, "listeners"),
        (
            "Hub: session 11 with 'laptop.example' (key_id=7cd2ff07…)",
            false,
            "sessions",
        ),
        (
            "Hub: pairing 'desktop.example' with 'laptop.example'",
            false,
            "pairing",
        ),
        (
            "Hub: refusing 'stranger.example' (key_id=…) — no grant names it",
            true,
            "refusals",
        ),
        ("Hub: grants applied (3 rows)", false, "other"),
    ];
    for (i, (text, warn, kind)) in lines.iter().enumerate() {
        data.events.push_back(EventRow {
            seq: (i + 1) as u64,
            at_unix: 1_791_572_000,
            warn: *warn,
            kind,
            text: text.to_string(),
        });
    }
    data
}

fn session(id: u64, subject: &str, key_id: &str, since: u64, streams: u64) -> SessionRow {
    SessionRow {
        session_id: id,
        subject: subject.to_string(),
        key_id: key_id.to_string(),
        cert_id: format!("cert-{key_id}"),
        not_before: 1_791_567_010,
        not_after: 1_823_103_010,
        since_unix: since,
        streams_open: streams,
    }
}

const FIXTURE_CONFIG: &str = r#"[app]
mode = "hub"

[identity]
key_file = "/etc/birdhub/keys/hub.key"
name = "hub.example"
certificate = "/etc/birdhub/keys/hub.cert"

[ca]
public = "/etc/birdhub/keys/ca.pub"

[[grants]]
client = "laptop.example"
targets = ["origin:80"]
"#;

/// kittest's preference order (CPU, then discrete, then the rest), but each
/// candidate is *opened* before it is trusted. kittest's own selector takes
/// the first adapter by enumeration; on a machine where a driver enumerates
/// fine and then fails vkCreateDevice with DEVICE_LOST (the NVIDIA ICD on
/// this desk, with the dGPU asleep), that adapter wins the sort and panics
/// every shot. Probing costs one device open per candidate, here: nothing.
fn open_first_working<'a>(
    adapters: impl IntoIterator<Item = &'a wgpu::Adapter>,
) -> Result<wgpu::Adapter, String> {
    let mut candidates: Vec<_> = adapters.into_iter().collect();
    candidates.sort_by_key(|a| match a.get_info().device_type {
        wgpu::DeviceType::Cpu => 0,
        wgpu::DeviceType::DiscreteGpu => 1,
        _ => 2,
    });
    for adapter in candidates {
        if pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor::default())).is_ok() {
            return Ok(adapter.clone());
        }
    }
    Err("every adapter failed to open a device".to_owned())
}

/// The harness setup: kittest's headless defaults, with the selector above.
fn render_setup() -> WgpuSetup {
    let mut setup = egui_wgpu::WgpuSetupCreateNew::without_display_handle();
    setup
        .instance_descriptor
        .backends
        .remove(wgpu::Backends::BROWSER_WEBGPU);
    setup.native_adapter_selector = Some(Arc::new(|adapters, _surface| {
        open_first_working(adapters.iter())
    }));
    WgpuSetup::CreateNew(setup)
}

/// Whether any adapter will open, checked before building a harness so the
/// shots can skip with a reason instead of panicking inside kittest.
fn some_adapter_opens() -> bool {
    let setup = WgpuSetup::CreateNew(egui_wgpu::WgpuSetupCreateNew::without_display_handle());
    let instance = pollster::block_on(setup.new_instance());
    let adapters = pollster::block_on(instance.enumerate_adapters(wgpu::Backends::all()));
    open_first_working(adapters.iter()).is_ok()
}

fn shot(app: ConsoleApp, name: &str) {
    if !some_adapter_opens() {
        println!("skipping screenshot '{name}': no wgpu adapter would open a device");
        return;
    }
    let mut harness = Harness::builder()
        .with_size(egui::vec2(1280.0, 800.0))
        .wgpu_setup(render_setup())
        .build_eframe(move |cc| {
            birdhub_console::theme::apply(cc);
            app
        });
    harness.run();
    harness.run();
    let image = harness.render().expect("wgpu renders");
    std::fs::create_dir_all(SHOTS).expect("a place to put the pictures");
    image
        .save(format!("{SHOTS}/{name}.png"))
        .expect("write the picture");
}

/// The fleet page: the session table, and the inspector open on the first
/// session — the hub's home screen.
#[test]
fn shot_the_fleet_with_an_open_inspector() {
    let (backend, _recorder) = fixture();
    let mut app = ConsoleApp::new(backend);
    app.set_fixture(hub_fixture());
    app.select_fixture_session(11);
    shot(app, "console-fleet");
}

/// The roster editor, seeded from the fixture's applied table.
#[test]
fn shot_the_roster_editor() {
    let (backend, _recorder) = fixture();
    let mut app = ConsoleApp::new(backend);
    app.set_fixture(hub_fixture());
    app.open_fixture_section(birdhub_console::app::Section::Roster);
    shot(app, "console-roster");
}

/// The events page with one of each kind — the chips and the colours.
#[test]
fn shot_the_events_page() {
    let (backend, _recorder) = fixture();
    let mut app = ConsoleApp::new(backend);
    app.set_fixture(hub_fixture());
    app.open_fixture_section(birdhub_console::app::Section::Events);
    shot(app, "console-events");
}

/// The action layer, driven the way a click drives it: a roster edit parses
/// its targets, and a kick queues exactly the session named. The fixture
/// backend records what it was asked to do, so the assertion is on the
/// action, not on the core's response (which the core's own tests cover).
#[test]
fn the_action_layer_parses_and_routes() {
    let (backend, recorder) = fixture();
    let mut app = ConsoleApp::new(backend);
    app.set_fixture(hub_fixture());
    app.open_fixture_section(birdhub_console::app::Section::Roster);

    // The editor is seeded from the fixture roster; editing a row's targets
    // and saving builds a SaveRoster action with split, trimmed targets.
    app.edit_fixture_draft(0, "origin:80, origin:443");
    app.act_fixture_save();
    app.run_fixture_actions();
    // Cloned, not held: the app's next action also locks the recorder, and
    // a guard held across `run_fixture_actions` would deadlock it.
    let actions = recorder.lock().expect("recorder lock").clone();
    match &actions[0] {
        birdhub_console::backend::Action::SaveRoster(rows) => {
            assert_eq!(rows[0].targets, vec!["origin:80", "origin:443"]);
        }
        other => panic!("expected SaveRoster, got {other:?}"),
    }

    // A kick from the fleet page names the selected session.
    app.select_fixture_session(12);
    app.kick_fixture_selected();
    app.run_fixture_actions();
    let actions = recorder.lock().expect("recorder lock").clone();
    match &actions[1] {
        birdhub_console::backend::Action::Kick(12) => {}
        other => panic!("expected Kick(12), got {other:?}"),
    }
}
