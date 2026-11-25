//! Each event in plain words (LIM-23): what `limbo report --plain` shows in its timeline instead of the event's name and
//! its `key=value` details, and what Settings' Limbo page saves as the evidence report. One sentence per kind in
//! docs/EVENTS.md. The details come from the log as they are; where a detail came from a guest (a path, a name it asked
//! for, the first bytes it sent) it is said to be the guest's, and the report bounds and escapes the whole sentence.

use crate::events::Event;

/// The sentence for `e`, or None for a kind this list does not know (the report then shows its name and details).
pub fn sentence(e: &Event) -> Option<String> {
    let d = |k: &str| e.detail.as_ref().and_then(|m| m.get(k)).map(String::as_str).unwrap_or("");
    let or = |k: &str, none: &str| if d(k).is_empty() { none.to_string() } else { d(k).to_string() };
    let guest = if e.guest.is_empty() { "the guest".to_string() } else { format!("guest {}", e.guest) };
    let s = match e.kind.as_str() {
        // a guest's life
        "image.verified" => format!(
            "The base image of {guest} matched its checksum{}.",
            match d("check") {
                "full" => " (hashed in full)",
                "record" => " (vouched for by an earlier full hash, the file unchanged since)",
                _ => "",
            }
        ),
        "image.rejected" if d("during") == "weekly check" => {
            format!("The weekly check found a proven base image changed: {}.", or("reason", "no reason given"))
        }
        "image.rejected" => {
            format!("{} was not started: its base image failed the check ({}).", cap(&guest), or("reason", "no reason given"))
        }
        "gate.blocked" => format!("{} was not started: {}.", cap(&guest), or("reason", "a gate refused it")),
        "guest.define" => {
            format!("{} was set up ({}, network {}).", cap(&guest), or("os", "its system"), or("network", "as its manifest says"))
        }
        "policy.apply" => format!("The firewall rules of {guest} were loaded."),
        "guest.start" => format!("{} started.", cap(&guest)),
        "app.launch" => format!("The app {} of {guest} was opened on the desktop.", or("app", "(unnamed)")),
        "guest.stop" => format!("{} was stopped.", cap(&guest)),
        "policy.remove" => format!("The firewall rules of {guest} were removed."),
        // quarantine
        "quarantine.open" => format!(
            "{} was put under quarantine ({}) by {}: {}.",
            cap(&guest),
            level(d("level")),
            or("source", "someone"),
            or("reason", "no reason given")
        ),
        "quarantine.raise" => format!("The quarantine of {guest} was tightened ({}).", level(d("level"))),
        "quarantine.advisory" => {
            format!("An opinion on the quarantine of {guest} was attached by {}; it changed nothing.", or("source", "someone"))
        }
        "quarantine.verdict" => match d("verdict") {
            "safe" => format!("{} was judged safe by {} and let out of quarantine.", cap(&guest), or("by", "a person")),
            "dangerous" => format!("{} was judged dangerous by {} and stays cut off.", cap(&guest), or("by", "a person")),
            "closed" => format!("The quarantine record of {guest} was closed by {}.", or("by", "a person")),
            v => format!("A verdict ({v}) was given on {guest} by {}.", or("by", "a person")),
        },
        "policy.restrict" => format!("{} was cut off: its firewall now refuses everything.", cap(&guest)),
        "policy.release" => format!("{} got its own firewall rules back.", cap(&guest)),
        "link.down" => format!("The network cable of {guest} was pulled ({}).", or("interface", "its link")),
        "link.up" => format!("The network cable of {guest} was plugged back in ({}).", or("interface", "its link")),
        // validation runs
        "run.start" => format!("A test run ({}) started with the profile {}.", e.guest, or("profile", "(none)")),
        "run.end" => format!(
            "The test run {} ended: {}{}{}{}.",
            e.guest,
            or("status", "no status"),
            if d("exit_code").is_empty() { String::new() } else { format!(", exit code {}", d("exit_code")) },
            if d("teardown") == "failed" { "; its guest was not fully cleaned away" } else { "" },
            if d("suggested").is_empty() {
                String::new()
            } else {
                format!("; names in its output suggest the ATT&CK techniques {} (not verified)", d("suggested").replace(',', ", "))
            }
        ),
        "run.error" if d("during") == "startup reap" => {
            format!("A test run left over from before ({}) was cleaned away when Limbo started.", e.guest)
        }
        "run.error" => format!("A test run ({}) was refused or failed: {}.", e.guest, or("code", "no code")),
        // the network a guest uses
        "net.flow" => format!("{} first reached {} ({}, {}).", cap(&guest), dest(e), or("proto", "?"), or("scope", "somewhere")),
        "net.blocked" => format!("{} was refused {} ({}, {}).", cap(&guest), dest(e), or("proto", "?"), or("scope", "somewhere")),
        "net.anomaly" => format!(
            "{}'s refused connections look like probing ({}): {} times, towards {}.",
            cap(&guest),
            or("reason", "unusual"),
            or("count", "several"),
            dest(e)
        ),
        "net.capped" => {
            format!("{} reached {} different destinations; further ones are not written down.", cap(&guest), or("limit", "the limit of"))
        }
        // a sample run's sinkhole
        "sinkhole.start" => format!("The sinkhole of {guest} started: every name it asks for leads back to Limbo, nothing leaves."),
        "sinkhole.dns" => {
            format!("{} asked for the name {} ({}); the guest's own words.", cap(&guest), or("name", "(none)"), or("type", "?"))
        }
        "sinkhole.connect" => format!(
            "{} tried to connect ({} port {}){}; it reached only the sinkhole.",
            cap(&guest),
            or("proto", "?"),
            or("dport", "?"),
            match (d("sni"), d("host")) {
                ("", "") => String::new(),
                ("", h) => format!(" asking for {h}"),
                (s, _) => format!(" asking for {s}"),
            }
        ),
        "sinkhole.capped" => {
            format!("{} made more than {} sinkhole contacts; the rest were only counted.", cap(&guest), or("limit", "the limit of"))
        }
        "sinkhole.stop" => format!(
            "The sinkhole of {guest} stopped: {} name lookups, {} TCP and {} UDP contacts.",
            or("dns", "0"),
            or("tcp", "0"),
            or("udp", "0")
        ),
        // instances, settings, licenses (Settings' Limbo page)
        "instance.request" => format!("Someone asked to {} {guest}.", or("action", "change")),
        "instance.change" if d("changed") == "free_space" => format!("The disk of {guest} was emptied back to its base image."),
        "instance.change" => format!("The settings of {guest} were changed ({}).", or("changed", "something")),
        "instance.add" => {
            format!("{} was registered{}.", cap(&guest), if d("owner").is_empty() { String::new() } else { format!(" for {}", d("owner")) })
        }
        "instance.remove" => format!("{} was removed{}.", cap(&guest), if d("delete_disk") == "true" { ", with its disk" } else { "" }),
        "settings.change" => {
            format!("The password switch for Limbo changes was turned {}.", if d("ask_password") == "true" { "on" } else { "off" })
        }
        "license.add" => format!("A Windows license ({}) was stored.", or("id", "?")),
        "license.remove" => format!("A Windows license ({}) was removed.", or("id", "?")),
        "license.reveal" => format!("A Windows license ({}) was shown in full.", or("id", "?")),
        "license.assign" => format!("A Windows license ({}) was given to {guest}.", or("id", "?")),
        "license.unassign" => format!("A Windows license ({}) was taken from {guest}.", or("id", "?")),
        // files from a guest
        "exchange.file" => format!(
            "A file left {guest}'s outbox, scanned clean ({} bytes); its name, the guest's words: {}.",
            or("size", "?"),
            or("path", "(none)")
        ),
        "exchange.held" => format!(
            "A file in {guest}'s outbox was held: ClamAV knows it as {}; its name, the guest's words: {}.",
            or("signature", "malware"),
            or("path", "(none)")
        ),
        "exchange.fail" => {
            format!("A file in {guest}'s outbox could not be scanned, so it stayed there ({}).", or("reason", "no reason given"))
        }
        // Windows programs on the desktop
        "wine.setup" => format!(
            "A Windows prefix was {} ({}).",
            if d("step") == "windows" { "set to another Windows version" } else { "made" },
            or("run", "?")
        ),
        "wine.start" => format!(
            "A Windows program started in its sandbox (network {}, graphics card {}){}.",
            or("network", "?"),
            or("gpu", "?"),
            if d("trace") == "on" { ", traced" } else { "" }
        ),
        "wine.stop" => format!("A Windows program ended: {} after {} s.", or("status", "?"), or("seconds", "?")),
        "wine.refused" => format!("A Windows program was not run: {}.", or("reason", "no reason given")),
        // devices passed through
        "passthrough.approve" => format!("A device was approved for passthrough ({}) until {}.", or("devices", "?"), or("expires", "?")),
        "passthrough.revoke" => format!("An approval for passthrough was taken back ({}).", or("devices", "?")),
        "hardware.stuck" => format!("A device did not come back to the host after {guest}: {}. A reboot frees it.", or("reason", "?")),
        _ => return None,
    };
    Some(s)
}

/// "guest lab" -> "Guest lab", "the guest" -> "The guest".
fn cap(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

fn level(l: &str) -> &str {
    match l {
        "restrict" => "its network cut to nothing",
        "isolate" => "cut off and its link pulled",
        "" => "no level given",
        other => other,
    }
}

/// "1.2.3.4 port 443", or an ICMP type, or the address alone.
fn dest(e: &Event) -> String {
    let d = |k: &str| e.detail.as_ref().and_then(|m| m.get(k)).map(String::as_str).unwrap_or("");
    let a = if d("dst").is_empty() { "somewhere" } else { d("dst") };
    if !d("dport").is_empty() {
        format!("{a} port {}", d("dport"))
    } else if !d("icmp_type").is_empty() {
        format!("{a} (ICMP type {})", d("icmp_type"))
    } else {
        a.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ev(kind: &str, guest: &str, kv: &[(&str, &str)]) -> Event {
        Event {
            time: Default::default(),
            kind: kind.into(),
            guest: guest.into(),
            detail: Some(kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>()),
        }
    }

    /// LIM-23's check: every kind docs/EVENTS.md lists (and the passthrough ones ARCHITECTURE.md names) has its sentence,
    /// also with no details at all.
    #[test]
    fn every_documented_kind_has_a_sentence() {
        let doc = include_str!("../../../docs/EVENTS.md");
        let mut kinds: Vec<String> = doc
            .lines()
            .filter(|l| l.starts_with("| `"))
            .flat_map(|l| l.split('|').nth(1).unwrap_or("").split('/').map(|k| k.trim().trim_matches('`').to_string()).collect::<Vec<_>>())
            .collect();
        kinds.extend(["passthrough.approve", "passthrough.revoke", "hardware.stuck"].map(String::from));
        assert!(kinds.len() >= 49, "{kinds:?}");
        for k in &kinds {
            let s = sentence(&ev(k, "lab", &[])).unwrap_or_else(|| panic!("no sentence for {k}"));
            assert!(s.ends_with('.') && !s.contains("{"), "{k}: {s}");
            assert!(sentence(&Event { detail: None, ..ev(k, "", &[]) }).is_some(), "{k} with no details");
        }
        assert!(sentence(&ev("made.up", "lab", &[])).is_none());
    }

    #[test]
    fn some_sentences() {
        assert_eq!(
            sentence(&ev("quarantine.open", "lab", &[("level", "isolate"), ("source", "heimdall"), ("reason", "host probe")])).unwrap(),
            "Guest lab was put under quarantine (cut off and its link pulled) by heimdall: host probe."
        );
        assert_eq!(
            sentence(&ev("net.blocked", "lab", &[("dst", "192.0.2.1"), ("dport", "22"), ("proto", "tcp"), ("scope", "lan")])).unwrap(),
            "Guest lab was refused 192.0.2.1 port 22 (tcp, lan)."
        );
        assert_eq!(
            sentence(&ev("run.end", "r1234abcd", &[("status", "finished"), ("exit_code", "0"), ("teardown", "failed")])).unwrap(),
            "The test run r1234abcd ended: finished, exit code 0; its guest was not fully cleaned away."
        );
        assert_eq!(
            sentence(&ev("run.end", "r1234abcd", &[("status", "done"), ("exit_code", "0"), ("suggested", "T1055,T1055.008")])).unwrap(),
            "The test run r1234abcd ended: done, exit code 0; names in its output suggest the ATT&CK techniques T1055, \
             T1055.008 (not verified)."
        );
        assert_eq!(
            sentence(&ev("image.rejected", "", &[("during", "weekly check"), ("reason", "base.qcow2 changed")])).unwrap(),
            "The weekly check found a proven base image changed: base.qcow2 changed."
        );
        assert_eq!(
            sentence(&ev("settings.change", "", &[("ask_password", "true")])).unwrap(),
            "The password switch for Limbo changes was turned on."
        );
    }
}
