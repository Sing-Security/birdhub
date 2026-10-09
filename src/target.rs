// ============================================================================
// TARGET MODULE: what an `Open`'s target string means
// ============================================================================
//
// A target is a name, and the first byte of grammar decides who acts on it:
//
//   - `host:port`        the hub dials it — the original relay shape.
//   - `subject/service`  the local node reaches a service on a *peer* by
//                        certificate subject, through the hub's pairing.
//                        Parsed on the dialing node; the hub never sees these.
//   - `@peer/<subject>`  a node asks the hub for a carrier to that peer: a
//                        raw byte pipe to the peer, on which the two peers run
//                        their own Temper session. This is the unit the hub
//                        authorizes — one `@peer/<subject>` grant entry is
//                        what lets a node reach a peer at all.
//   - `@cert/<subject>`  a node asks the hub for that peer's certificate. The
//                        hub saw it at the peer's handshake and can hand it
//                        back; the requester verifies it against the CA like
//                        any other certificate. No file has to be copied, and
//                        no separate identity server has to exist — the hub is
//                        one because it is already the meeting point.
//
// `@` is reserved: no host, service or certificate subject may contain it, so
// an `@`-prefixed target can never collide with a name that means something
// else. `subject/service` splits at the first `/`, and service names cannot
// contain `/`, so the split is unambiguous in both directions.

/// The target the hub opens on a peer's session when pairing a carrier. Not a
/// parseable user target — bare `@peer` has no subject — so it can only come
/// from the hub, which is the only party that opens streams toward a peer.
pub const CARRIER_TARGET: &str = "@peer";

/// One parsed target. `Dial` carries the raw string — the grant table and the
/// dialer both want exactly what the operator wrote, and giving it a parser
/// would be a second place for the two to disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Dial { target: String },
    Peer { subject: String, service: String },
    Carrier { subject: String },
    Directory { subject: String },
}

/// Parse a target, or say why it is not one.
///
/// Rejecting is not incidental: the refused-target tests lean on "cannot be
/// parsed" and "not granted" being different answers, because a target that
/// silently fell through to the dial path would be dialed.
pub fn parse(target: &str) -> Result<Target, String> {
    if let Some(subject) = target.strip_prefix("@peer/") {
        return if is_subject(subject) {
            Ok(Target::Carrier {
                subject: subject.to_string(),
            })
        } else {
            Err(format!("'{}' is not a valid peer subject", subject))
        };
    }
    if let Some(subject) = target.strip_prefix("@cert/") {
        return if is_subject(subject) {
            Ok(Target::Directory {
                subject: subject.to_string(),
            })
        } else {
            Err(format!("'{}' is not a valid peer subject", subject))
        };
    }
    if let Some('@') = target.chars().next() {
        return Err(format!(
            "'{}' begins with '@', which is reserved for hub targets",
            target
        ));
    }

    if let Some((subject, service)) = target.split_once('/') {
        if !is_subject(subject) {
            return Err(format!("'{}' is not a valid peer subject", subject));
        }
        if !is_service_name(service) {
            return Err(format!("'{}' is not a valid service name", service));
        }
        return Ok(Target::Peer {
            subject: subject.to_string(),
            service: service.to_string(),
        });
    }

    Ok(Target::Dial {
        target: target.to_string(),
    })
}

/// A certificate subject: non-empty, and none of the characters that carry
/// grammar somewhere else (`/` splits, `@` marks hub targets, `:` separates a
/// host from a port, whitespace never survives a config file intact).
pub fn is_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= 253
        && !subject
            .chars()
            .any(|c| c == '/' || c == '@' || c == ':' || c.is_whitespace())
}

/// A service name: lowercase letters, digits and dashes — the same shape as a
/// DNS label, so it can become an inner mux target, a log field, and a config
/// key without quoting rules.
pub fn is_service_name(service: &str) -> bool {
    !service.is_empty()
        && service.len() <= 63
        && service
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The grant entry that permits reaching `subject` — one entry covers both the
/// certificate lookup and the carrier, because "may I reach this peer" is one
/// question asked in two steps.
pub fn peer_grant(subject: &str) -> String {
    format!("@peer/{}", subject)
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_port_is_a_dial_target() {
        assert_eq!(
            parse("origin.internal:80").unwrap(),
            Target::Dial {
                target: "origin.internal:80".to_string()
            }
        );
    }

    #[test]
    fn subject_and_service_is_a_peer_target() {
        assert_eq!(
            parse("peer.example/web").unwrap(),
            Target::Peer {
                subject: "peer.example".to_string(),
                service: "web".to_string()
            }
        );
    }

    #[test]
    fn at_targets_are_the_hub_requests() {
        assert_eq!(
            parse("@peer/peer.example").unwrap(),
            Target::Carrier {
                subject: "peer.example".to_string()
            }
        );
        assert_eq!(
            parse("@cert/peer.example").unwrap(),
            Target::Directory {
                subject: "peer.example".to_string()
            }
        );
    }

    /// Every malformed shape, and that each is an error rather than a dial —
    /// a target that falls through to the dial path is a target that can be
    /// dialed.
    #[test]
    fn malformed_targets_are_rejected_not_dialed() {
        let cases = [
            "@peer/",
            "@peer/has/slash",
            "@cert/",
            "@cert/bad:subject",
            "@unknown/peer.example",
            "peer.example/",
            "peer.example/UPPER",
            "peer.example/space name",
            "peer.example/slash/in/service",
            "/service",
        ];
        for case in cases {
            assert!(parse(case).is_err(), "{:?} parsed as a target", case);
        }
    }

    /// A dial target is opaque — the grant table compares the string the
    /// operator wrote, so anything without a `/` or a leading `@` stays one.
    #[test]
    fn dial_targets_stay_opaque() {
        assert!(matches!(
            parse("origin.internal").unwrap(),
            Target::Dial { .. }
        ));
        assert!(matches!(
            parse("127.0.0.1:8099").unwrap(),
            Target::Dial { .. }
        ));
    }

    #[test]
    fn names_are_validated_by_their_rules() {
        assert!(is_subject("peer.example"));
        assert!(!is_subject(""));
        assert!(!is_subject("a/b"));
        assert!(!is_subject("a@b"));
        assert!(is_service_name("web"));
        assert!(is_service_name("db-1"));
        assert!(!is_service_name(""));
        assert!(!is_service_name("Web"));
        assert!(!is_service_name("a_b"));
        assert_eq!(peer_grant("peer.example"), "@peer/peer.example");
    }
}

// endregion: --- Tests
