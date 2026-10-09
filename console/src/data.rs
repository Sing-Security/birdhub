//! The console's view data: what the pages render. Built by
//! `Backend::refresh` from the core's snapshots, or by hand in the fixture
//! tests — the views never touch the core directly, which is what lets a
//! screenshot test draw a fleet that does not exist.

use birdhub::events::Event;
use std::collections::VecDeque;
use std::net::SocketAddr;

/// Events kept for the Events page — the same count the core's ring holds;
/// the page shows the newest `PAGE` of them.
pub const EVENT_RING: usize = 5000;
const PAGE: usize = 500;

/// One session on the fleet page.
#[derive(Clone)]
pub struct SessionRow {
    pub session_id: u64,
    pub subject: String,
    pub key_id: String,
    pub cert_id: String,
    pub not_before: u64,
    pub not_after: u64,
    pub since_unix: u64,
    pub streams_open: u64,
}

impl SessionRow {
    pub fn of(info: &birdhub::hub::SessionInfo) -> Self {
        Self {
            session_id: info.session_id,
            subject: info.subject.clone(),
            key_id: info.key_id.clone(),
            cert_id: info.certificate.cert_id.clone(),
            not_before: info.certificate.not_before,
            not_after: info.certificate.not_after,
            since_unix: info.since_unix,
            streams_open: info.streams_open.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

/// One roster row, as the editor and the table show it.
#[derive(Clone, Debug, PartialEq)]
pub struct GrantRow {
    pub client: String,
    pub targets: Vec<String>,
}

/// One node transport.
pub struct TransportRow {
    pub name: String,
    pub local_address: String,
    pub forward_to: String,
    pub accepted: u64,
    pub last_error: Option<String>,
}

impl TransportRow {
    pub fn of(runtime: &birdhub::node::TransportRuntime) -> Self {
        Self {
            name: runtime.config().name.clone(),
            local_address: runtime.config().local_address.clone(),
            forward_to: runtime.config().forward_to.clone(),
            accepted: runtime.accepted(),
            last_error: runtime.last_error(),
        }
    }
}

/// One service this node serves to peers.
pub struct ServiceRow {
    pub name: String,
    pub target: String,
    pub clients: Vec<String>,
}

/// The node's cached peer sessions, or "locked" while a handshake holds the
/// map.
pub struct PeersRow {
    pub locked: bool,
    pub peers: Vec<PeerRow>,
}

pub struct PeerRow {
    pub subject: String,
    pub session_id: u64,
    pub since_unix: u64,
    pub live: bool,
}

/// The node's hub link, one line.
pub struct LinkRow {
    pub state: String,
    pub session_id: Option<u64>,
    pub retry_in_secs: Option<u64>,
    pub last_error: Option<String>,
}

/// One event line, the Events page's row.
pub struct EventRow {
    pub seq: u64,
    pub at_unix: u64,
    pub warn: bool,
    pub kind: &'static str,
    pub text: String,
}

impl EventRow {
    pub fn of(event: &Event) -> Self {
        Self {
            seq: event.seq,
            at_unix: event.at_unix,
            warn: event.level == birdhub::events::Level::Warn,
            kind: match event.kind {
                birdhub::events::Kind::Session => "sessions",
                birdhub::events::Kind::Pairing => "pairing",
                birdhub::events::Kind::Refusal => "refusals",
                birdhub::events::Kind::Listener => "listeners",
                birdhub::events::Kind::Other => "other",
            },
            text: event.text.clone(),
        }
    }
}

/// Everything the pages read. One struct per mode would split the shell in
/// two; the `Option`s are the page's dispatch — a page renders only its own
/// half, and a page for the other mode is not reachable from that mode's
/// nav.
pub struct ConsoleData {
    pub mode: String,
    pub subject: String,
    pub key_id: String,
    pub cert_id: String,
    pub not_before: u64,
    pub not_after: u64,
    /// Hub: the config file the roster edits rewrite.
    pub config_path: Option<String>,
    /// Hub: the config file's text, as the Config page shows it.
    pub config_text: Option<String>,
    /// Hub: live sessions, oldest first.
    pub sessions: Vec<SessionRow>,
    /// Hub: the roster as applied.
    pub roster: Vec<GrantRow>,
    /// Node: where the hub is.
    pub hub_address: Option<String>,
    /// Node: the hub's certificate subject.
    pub hub_subject: Option<String>,
    /// Node: the hub link.
    pub link: LinkRow,
    /// Node: local listeners.
    pub transports: Vec<TransportRow>,
    /// Node: what this node serves.
    pub services: Vec<ServiceRow>,
    /// Node: cached peer sessions.
    pub peers: PeersRow,
    /// Both: newest events at the back.
    pub events: VecDeque<EventRow>,
    /// The event cursor the next refresh reads after.
    pub events_cursor: u64,
    /// The control API's bound address, if one is up.
    pub api: Option<SocketAddr>,
    /// The last action error, for the status bar.
    pub last_error: Option<String>,
}

impl ConsoleData {
    pub fn empty() -> Self {
        Self {
            mode: "none".to_string(),
            subject: String::new(),
            key_id: String::new(),
            cert_id: String::new(),
            not_before: 0,
            not_after: 0,
            config_path: None,
            config_text: None,
            sessions: Vec::new(),
            roster: Vec::new(),
            hub_address: None,
            hub_subject: None,
            link: LinkRow {
                state: "connecting".to_string(),
                session_id: None,
                retry_in_secs: None,
                last_error: None,
            },
            transports: Vec::new(),
            services: Vec::new(),
            peers: PeersRow {
                locked: false,
                peers: Vec::new(),
            },
            events: VecDeque::new(),
            events_cursor: 0,
            api: None,
            last_error: None,
        }
    }

    /// The newest events, most recent first — the order the page shows.
    pub fn recent_events(&self, limit: usize) -> Vec<&EventRow> {
        let skip = self.events.len().saturating_sub(limit);
        self.events.iter().skip(skip).rev().collect()
    }

    pub fn recent_events_capped(&self) -> Vec<&EventRow> {
        self.recent_events(PAGE)
    }
}

/// UTC date and time from a unix timestamp — `2026-10-09 18:36:40`. The
/// validity windows and the fleet's "since" are fleet-wide facts, so they
/// print in the one timezone every node agrees on. (Civil-from-days is
/// Hinnant's; std has no date formatting and the console carries no
/// chrono.)
pub fn date_time(unix: u64) -> String {
    let z = (unix / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 {
        yoe + era * 400 + 1
    } else {
        yoe + era * 400
    };
    let secs = unix % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::date_time;

    #[test]
    fn date_time_agrees_with_known_moments() {
        // The epoch itself, a leap day, the leap-non-day it skips, and the
        // fixture timestamps the screenshots render.
        assert_eq!(date_time(0), "1970-01-01 00:00:00");
        assert_eq!(date_time(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(date_time(951_868_800), "2000-03-01 00:00:00");
        assert_eq!(date_time(1_791_572_000), "2026-10-09 18:53:20");
        assert_eq!(date_time(1_823_103_010), "2027-10-09 17:30:10");
    }
}
