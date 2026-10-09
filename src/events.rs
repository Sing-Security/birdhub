// ============================================================================
// EVENTS MODULE: the operator-visible log, as data
// ============================================================================
//
// Every line the core prints — hub or node — is also an `Event` in a ring
// buffer. The headless binary still prints them; the console renders the same
// records in its Events page, and `GET /events?after=<seq>` serves them to
// anything else that asks. One producer path, three readers.
//
// Two decisions worth the words:
//
// * **The line is the record.** `text` is exactly what used to be printed,
//   byte for byte, including the `Hub:`/`Node:` prefix and the em dashes. A
//   log that changes shape when it becomes data is a log whose history stops
//   being greppable, and the e2e driver's captured transcripts are the
//   regression gate for this refactor precisely because they must not change.
//
// * **The headless print happens at the call site, synchronously.** The
//   alternative — a printer task draining a channel — reorders lines that
//   several tasks produce concurrently, so the captured log would differ from
//   the pre-refactor one even with identical text. Printing where the event
//   is produced keeps the interleaving the log always had. The `watch`
//   notification below is *not* the print path; it is for subscribers who
//   want to be woken instead of polling, and it carries only the newest
//   sequence number — the ring is the source of truth, so a missed
//   notification costs a poll, never an event. A broadcast queue of events
//   would be the wrong shape for exactly that reason: a lagging reader would
//   drop records, and a log that drops records silently is worse than no log.
//
// The ring holds the most recent `CAPACITY` events and forgets older ones;
// the count kept is the one Splicer keeps, so the console's memory profile is
// the one already proven at 5000 lines of traffic.

use crate::time::now_secs;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::watch;

/// Events kept before the oldest is dropped. Sized for a fleet's day of
/// sessions rather than a debug session's minutes.
pub const CAPACITY: usize = 5000;

// region:    --- Types

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Warn,
}

/// What a line is about, for the Events page's filter chips and for
/// `GET /events?filter=`. A small closed set, because a filter nobody can
/// name is a filter nobody uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Sessions with the hub, on either end, and the local connections they
    /// carry.
    Session,
    /// Peer sessions and hub pairings — the carrier path.
    Pairing,
    /// Anything refused: handshakes, ungranted targets, denied services.
    Refusal,
    /// Listener bind/accept/stop.
    Listener,
    /// Startup facts: identity, certificates, grants, config-derived lines.
    Other,
}

impl Kind {
    /// The chip label the console shows. Plural because it reads as a group.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Session => "sessions",
            Kind::Pairing => "pairing",
            Kind::Refusal => "refusals",
            Kind::Listener => "listeners",
            Kind::Other => "other",
        }
    }
}

/// One line, as data.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub seq: u64,
    pub at_unix: u64,
    pub level: Level,
    pub kind: Kind,
    /// The line as printed, without the trailing newline.
    pub text: String,
}

/// Whether `push` also writes to this process's stdout/stderr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    /// The headless binary: print, so the process's log is unchanged.
    Console,
    /// Embedded (the console) or under test: collect, never print.
    Silent,
}

struct Ring {
    events: VecDeque<Event>,
    next_seq: u64,
}

// endregion: --- Types

// region:    --- Log

pub struct EventLog {
    output: Output,
    ring: Mutex<Ring>,
    /// Newest sequence number. Subscribers wake on change; see the module
    /// comment for why this is a signal and not the events themselves.
    notify: watch::Sender<u64>,
}

impl EventLog {
    fn new(output: Output) -> Self {
        Self {
            output,
            ring: Mutex::new(Ring {
                events: VecDeque::with_capacity(64),
                // Sequence numbers start at 1 so that 0 is unambiguous: it is
                // the cursor meaning "I have seen nothing", which is what a
                // fresh reader (and `?after=0`) must get everything for.
                next_seq: 1,
            }),
            notify: watch::channel(0).0,
        }
    }

    /// A log that prints: the headless binary's.
    pub fn console() -> Arc<Self> {
        Arc::new(Self::new(Output::Console))
    }

    /// A log that only collects: the console's, and the library's default
    /// for a caller that has its own rendering.
    pub fn quiet() -> Arc<Self> {
        Arc::new(Self::new(Output::Silent))
    }

    /// A shared silent log, for tests and for references that outlive a
    /// local binding. Never prints, so a test that produces events still
    /// reads as a test rather than as a running fleet.
    pub fn silent() -> &'static EventLog {
        static SILENT: OnceLock<EventLog> = OnceLock::new();
        SILENT.get_or_init(|| Self::new(Output::Silent))
    }

    pub fn info(&self, kind: Kind, text: impl Into<String>) {
        self.push(Level::Info, kind, text.into());
    }

    pub fn warn(&self, kind: Kind, text: impl Into<String>) {
        self.push(Level::Warn, kind, text.into());
    }

    pub fn push(&self, level: Level, kind: Kind, text: String) {
        let seq = {
            // The lock is released before anything is printed: output is the
            // slow part, and holding the ring across it would serialise every
            // producer behind a blocked stdout.
            let mut ring = self.ring.lock().expect("event log lock");
            let seq = ring.next_seq;
            ring.next_seq += 1;
            if ring.events.len() == CAPACITY {
                ring.events.pop_front();
            }
            ring.events.push_back(Event {
                seq,
                at_unix: now_secs(),
                level,
                kind,
                text: text.clone(),
            });
            seq
        };
        self.notify.send_replace(seq);
        if self.output == Output::Console {
            match level {
                Level::Info => println!("{}", text),
                Level::Warn => eprintln!("{}", text),
            }
        }
    }

    /// Every event held, oldest first.
    pub fn events(&self) -> Vec<Event> {
        self.ring
            .lock()
            .expect("event log lock")
            .events
            .iter()
            .cloned()
            .collect()
    }

    /// Events with `seq > after_seq`, oldest first — the cursor reads a
    /// subscriber keeps so a poll never misses or repeats one.
    pub fn since(&self, after_seq: u64) -> Vec<Event> {
        self.ring
            .lock()
            .expect("event log lock")
            .events
            .iter()
            .filter(|event| event.seq > after_seq)
            .cloned()
            .collect()
    }

    /// The newest `limit` events, oldest first.
    pub fn recent(&self, limit: usize) -> Vec<Event> {
        let ring = self.ring.lock().expect("event log lock");
        let skip = ring.events.len().saturating_sub(limit);
        ring.events.iter().skip(skip).cloned().collect()
    }

    /// The control API's read: everything after `after_seq` whose text
    /// contains `needle` (case-insensitive), at most `limit` of the newest.
    pub fn matching(
        &self,
        after_seq: u64,
        needle: Option<&str>,
        limit: Option<usize>,
    ) -> Vec<Event> {
        let needle = needle.map(str::to_lowercase);
        let ring = self.ring.lock().expect("event log lock");
        let mut matched: Vec<Event> = ring
            .events
            .iter()
            .filter(|event| event.seq > after_seq)
            .filter(|event| match &needle {
                Some(needle) => event.text.to_lowercase().contains(needle.as_str()),
                None => true,
            })
            .cloned()
            .collect();
        if let Some(limit) = limit {
            let skip = matched.len().saturating_sub(limit);
            matched.drain(..skip);
        }
        matched
    }

    pub fn last_seq(&self) -> u64 {
        self.notify.borrow().to_owned()
    }

    pub fn len(&self) -> usize {
        self.ring.lock().expect("event log lock").events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Wake on the next push. The value is the newest sequence number, not
    /// the event: read `since` for the events themselves.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.notify.subscribe()
    }
}

// endregion: --- Log

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_numbers_are_dense_and_cursor_reads_are_exact() {
        let log = EventLog::quiet();
        log.info(Kind::Session, "Node: session 1 with hub 'h.example'");
        log.warn(Kind::Refusal, "Hub: refusing 'x.example'");
        log.info(Kind::Pairing, "Hub: pairing 'a' with 'b'");

        let all = log.events();
        assert_eq!(all.len(), 3);
        assert_eq!(
            all.iter().map(|event| event.seq).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(all[1].level, Level::Warn);
        assert_eq!(all[1].kind, Kind::Refusal);

        // The cursor means exactly "everything after this one": a reader
        // that stores the last seq it saw never repeats or skips.
        let rest = log.since(1);
        assert_eq!(rest.len(), 2);
        assert_eq!(rest[0].seq, 2);
        assert!(log.since(3).is_empty());
        assert_eq!(log.last_seq(), 3);
    }

    #[test]
    fn the_ring_forgets_the_oldest_first() {
        let log = EventLog::quiet();
        for i in 0..CAPACITY + 10 {
            log.info(Kind::Other, format!("line {}", i));
        }
        assert_eq!(log.len(), CAPACITY);
        let held = log.events();
        assert_eq!(held.first().expect("oldest held").text, "line 10");
        assert_eq!(
            held.last().expect("newest held").seq as usize,
            CAPACITY + 10
        );
    }

    #[test]
    fn matching_filters_and_keeps_newest() {
        let log = EventLog::quiet();
        log.info(Kind::Session, "Hub: session 7 with 'a.example'");
        log.warn(Kind::Refusal, "Hub: refusing 'b.example' (key_id=x)");
        log.info(Kind::Session, "Hub: session 8 with 'c.example'");

        let refused = log.matching(0, Some("refusing"), None);
        assert_eq!(refused.len(), 1);
        assert!(refused[0].text.contains("b.example"));

        let newest = log.matching(0, None, Some(2));
        assert_eq!(newest.len(), 2);
        assert!(newest[0].text.contains("refusing"));
    }

    #[test]
    fn a_subscriber_wakes_on_the_next_event() {
        let log = EventLog::quiet();
        let mut rx = log.subscribe();
        assert!(!rx.has_changed().expect("sender alive"));
        log.info(Kind::Other, "something happened");
        assert!(rx.has_changed().expect("sender alive"));
        // The notification carries the newest sequence number, not the text:
        // a subscriber reads `since` for the events themselves.
        assert_eq!(*rx.borrow_and_update(), 1);
        assert_eq!(log.last_seq(), 1);
    }
}

// endregion: --- Tests
