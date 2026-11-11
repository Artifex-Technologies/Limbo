//! The audit log and the quarantine records as a Markdown report (Go: internal/report). Everything that came from a
//! guest, or from a model reading guest data, is escaped here: control characters removed, Markdown and table syntax
//! neutralised, advisories inside a fence their text cannot close.

use crate::events::{self, Event};
use crate::gotext;
use crate::gotime::Time;
use crate::quarantine::{self, Record};
use std::collections::BTreeMap;
use std::fmt::Write;

/// Everything a report is built from.
pub struct Input {
    pub events: Vec<Event>,
    /// Unreadable log lines, reported so a damaged log is not silent.
    pub skipped: usize,
    pub records: Vec<Record>,
    /// Only this guest, when set.
    pub guest: String,
    /// Only what happened on or after this, when not zero.
    pub since: Time,
    pub now: Time,
}

/// The report as Markdown.
pub fn render(inp: &Input) -> String {
    let evs = filter_events(inp);
    let recs = filter_records(inp);
    let mut b = String::new();
    macro_rules! w {
        ($($a:tt)*) => {{
            let _ = write!(b, $($a)*);
            b.push('\n');
        }};
    }
    w!("# Limbo activity report");
    w!("");
    w!("Generated {}.", inp.now.utc().rfc3339());
    let scope = if inp.guest.is_empty() { "all guests".to_string() } else { format!("guest `{}`", md(&inp.guest)) };
    let period = if inp.since.is_zero() { "the whole log".to_string() } else { format!("since {}", inp.since.utc().rfc3339()) };
    w!("Scope: {scope}, {period}.");
    if inp.skipped > 0 {
        w!("");
        w!(
            "> **{} line(s) in the event log could not be read and are not reflected here.** The log may be damaged or written by something else.",
            inp.skipped
        );
    }

    let c = count(&evs, &recs);
    w!("");
    w!("## Summary");
    w!("");
    w!("| | |");
    w!("| --- | --- |");
    w!("| Guests started | {} |", c.starts);
    w!("| Validation runs | {} ({} completed, {} failed, {} timed out) |", c.runs, c.run_done, c.run_failed, c.run_timeout);
    w!("| Quarantines | {} ({} open, {} safe, {} dangerous, {} closed) |", recs.len(), c.open, c.safe, c.dangerous, c.closed);
    w!("| Starts blocked (license gate or quarantine) | {} |", c.gate);
    w!("| Image checksum rejections | {} |", c.image_rejected);
    if c.open > 0 {
        w!("");
        w!("> **{} quarantine(s) are still open and awaiting a human verdict.**", c.open);
    }

    w!("");
    w!("## Quarantines");
    if recs.is_empty() {
        w!("");
        w!("None in this period.");
    }
    for r in &recs {
        w!("");
        w!("### {} \u{2014} guest `{}` \u{2014} {}", md(&r.id), md(&r.guest), gotext::to_upper(&r.status));
        w!("");
        w!("- Opened: {} by `{}`", r.opened.utc().rfc3339(), md(&r.source));
        w!("- Hold level: {}", md(&r.level));
        w!("- Reason: {}", md(&r.reason));
        if let Some(ev) = &r.evidence {
            for (k, v) in ev {
                w!("- Evidence `{}`: {}", md(k), md(v));
            }
        }
        match &r.verdict {
            Some(v) => w!("- **Verdict: {}** by {} at {}. Note: {}", md(&v.value), md(&v.by), v.time.utc().rfc3339(), md(&v.note)),
            None => w!("- **No verdict yet.** A human must decide."),
        }
        for a in r.advisory.iter().flatten() {
            w!("");
            w!(
                "Advisory from `{}` at {}. **Untrusted**: produced from guest-derived data by an automated reader, shown for information only. It did not change this record.",
                md(&a.source),
                a.time.utc().rfc3339()
            );
            w!("");
            w!("{}", fence(&a.text));
        }
    }

    w!("");
    w!("## Validation runs");
    let runs = run_rows(&evs);
    if runs.is_empty() {
        w!("");
        w!("None in this period.");
    } else {
        w!("");
        w!("| Run | Started | Result | Command (first 80 bytes) |");
        w!("| --- | --- | --- | --- |");
        for r in &runs {
            w!("| {} | {} | {} | `{}` |", md(&r.id), r.started, md(&r.result), md(&clip(r.command.as_bytes(), 80)));
        }
    }

    w!("");
    w!("## Integrity and policy events");
    let mut notable = 0;
    for e in &evs {
        if matches!(
            e.kind.as_str(),
            events::IMAGE_REJECTED
                | events::GATE_BLOCKED
                | events::POLICY_RESTRICT
                | events::POLICY_RELEASE
                | events::LINK_DOWN
                | events::LINK_UP
        ) {
            if notable == 0 {
                w!("");
                w!("| Time | Guest | Event | Detail |");
                w!("| --- | --- | --- | --- |");
            }
            notable += 1;
            w!("| {} | {} | {} | {} |", e.time.utc().rfc3339(), md(&e.guest), md(&e.kind), md(&detail(e)));
        }
    }
    if notable == 0 {
        w!("");
        w!("None in this period.");
    }

    w!("");
    w!("## Timeline");
    if evs.is_empty() {
        w!("");
        w!("No events in this period.");
    } else {
        w!("");
        w!("| Time | Guest | Event | Detail |");
        w!("| --- | --- | --- | --- |");
        for e in &evs {
            w!("| {} | {} | {} | {} |", e.time.utc().rfc3339(), md(&e.guest), md(&e.kind), md(&clip(&detail(e), 160)));
        }
    }
    b
}

#[derive(Default)]
struct Tally {
    starts: usize,
    runs: usize,
    run_done: usize,
    run_failed: usize,
    run_timeout: usize,
    gate: usize,
    image_rejected: usize,
    open: usize,
    safe: usize,
    dangerous: usize,
    closed: usize,
}

fn count(evs: &[&Event], recs: &[&Record]) -> Tally {
    let mut t = Tally::default();
    for e in evs {
        match e.kind.as_str() {
            events::GUEST_START => t.starts += 1,
            events::RUN_START => t.runs += 1,
            events::RUN_END => match e.get("status").unwrap_or("") {
                "done" => t.run_done += 1,
                "timeout" => t.run_timeout += 1,
                _ => t.run_failed += 1,
            },
            events::GATE_BLOCKED => t.gate += 1,
            events::IMAGE_REJECTED => t.image_rejected += 1,
            _ => {}
        }
    }
    for r in recs {
        match r.status.as_str() {
            quarantine::STATUS_OPEN => t.open += 1,
            quarantine::STATUS_SAFE => t.safe += 1,
            quarantine::STATUS_DANGEROUS => t.dangerous += 1,
            quarantine::STATUS_CLOSED => t.closed += 1,
            _ => {}
        }
    }
    t
}

struct RunRow {
    id: String,
    started: String,
    result: String,
    command: String,
}

fn run_rows(evs: &[&Event]) -> Vec<RunRow> {
    let mut idx: BTreeMap<&str, usize> = BTreeMap::new();
    let mut rows: Vec<RunRow> = vec![];
    for e in evs {
        match e.kind.as_str() {
            events::RUN_START => {
                idx.insert(&e.guest, rows.len());
                rows.push(RunRow {
                    id: e.guest.clone(),
                    started: e.time.utc().rfc3339(),
                    result: "unfinished".into(),
                    command: e.get("command").unwrap_or("").into(),
                });
            }
            events::RUN_END => {
                if let Some(&i) = idx.get(e.guest.as_str()) {
                    rows[i].result = e.get("status").unwrap_or("").into();
                    if let Some(code) = e.get("exit_code") {
                        rows[i].result += &format!(" (exit {code})");
                    }
                }
            }
            _ => {}
        }
    }
    rows
}

fn filter_events(inp: &Input) -> Vec<&Event> {
    let mut out: Vec<&Event> = inp
        .events
        .iter()
        .filter(|e| (inp.guest.is_empty() || e.guest == inp.guest) && (inp.since.is_zero() || !e.time.before(&inp.since)))
        .collect();
    out.sort_by_key(|e| e.time); // stable, as Go's SliceStable
    out
}

fn filter_records(inp: &Input) -> Vec<&Record> {
    let mut out: Vec<&Record> = inp
        .records
        .iter()
        .filter(|r| (inp.guest.is_empty() || r.guest == inp.guest) && (inp.since.is_zero() || !r.opened.before(&inp.since)))
        .collect();
    out.sort_by_key(|r| r.opened);
    out
}

/// "k=v k=v", keys sorted.
fn detail(e: &Event) -> Vec<u8> {
    let parts: Vec<String> = e.detail.iter().flatten().map(|(k, v)| format!("{k}={v}")).collect();
    parts.join(" ").into_bytes()
}

/// At most n bytes, then "…" (a character cut in two stays cut, as in Go).
fn clip(s: &[u8], n: usize) -> Vec<u8> {
    if s.len() <= n {
        return s.to_vec();
    }
    let mut out = s[..n].to_vec();
    out.extend_from_slice("\u{2026}".as_bytes());
    out
}

trait Text {
    fn text(&self) -> String;
}
impl Text for str {
    fn text(&self) -> String {
        self.to_string()
    }
}
impl Text for String {
    fn text(&self) -> String {
        self.clone()
    }
}
impl Text for Vec<u8> {
    fn text(&self) -> String {
        gotext::lossy(self)
    }
}

fn invisible(c: char) -> bool {
    matches!(c as u32, 0x200b..=0x200f | 0x202a..=0x202e | 0x2066..=0x2069)
}

/// Untrusted text made safe for a Markdown line or table cell.
fn md<T: Text + ?Sized>(t: &T) -> String {
    let mut b = String::new();
    for r in t.text().chars() {
        match r {
            '\n' | '\r' | '\t' => b.push(' '),
            c if gotext::is_control(c) || invisible(c) => {}
            c if "\\`*_[]<>#!|~".contains(c) => {
                b.push('\\');
                b.push(c);
            }
            c => b.push(c),
        }
    }
    b
}

/// Text in a code block whose fence is longer than any run of backticks inside it.
fn fence(s: &str) -> String {
    let mut clean = String::new();
    let (mut longest, mut run) = (0, 0);
    for r in s.chars() {
        if gotext::is_control(r) && r != '\n' || invisible(r) {
            continue;
        }
        clean.push(r);
        if r == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let f = "`".repeat(3.max(longest + 1));
    format!("{f}text\n{}\n{f}", clean.trim_end_matches('\n'))
}
