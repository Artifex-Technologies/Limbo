//! `limbo image list | verify` (cmd/limbo/image_cmd.go), line for line: the base images proven by a full hash, and the
//! weekly check that hashes each again. Same output, errors, events and files as Go; rust/parity/cli-differential.py
//! compares the two binaries (the trusted record, root's, under `unshare -r`).

use super::commands::{Fail, Io};
use super::flags::{parse_interspersed, FlagSet};
use super::local::{check_root_state_dir, default_state_dir};
use crate::events::Emitter;
use crate::image::{self, FileState, Proofs, VerifyErr};
use crate::{sys, tz};

const USAGE: &str =
    "usage: limbo image list | verify   (list: the base images proven by a full hash, and whether a start skips the hash now; \
verify: hash each of them in full again and refuse any that changed; root)";

pub fn run(args: &[String], io: &mut Io) -> Result<(), Fail> {
    let mut fs = FlagSet::new("image");
    fs.string("state-dir", &default_state_dir(io), "Limbo's state folder: the record of proven images and the event log");
    fs.bool("i-know", false, "as root, allow a state folder other than the daemon's");
    let mut stderr = vec![];
    let r = parse_interspersed(&mut fs, args.to_vec(), &mut stderr);
    let _ = io.err.write_all(&stderr);
    let pos = r.map_err(Fail::Msg)?;
    if pos.len() != 1 {
        return Err(Fail::Msg(USAGE.into()));
    }
    let state = fs.str("state-dir");
    check_root_state_dir(io, &state, fs.is_true("i-know"))?;
    let p = Proofs::new(&sys::join(&[&state, image::PROOFS_FILE]), 0);
    match pos[0].as_str() {
        "list" => list(&p, io),
        "verify" => {
            if io.euid != 0 {
                return Err(Fail::Msg("image verify: must run as root (the record of proven images is root's)".into()));
            }
            let log = open_log(&sys::join(&[&state, "events.jsonl"]))?;
            verify(&p, &log, io)
        }
        _ => Err(Fail::Msg(USAGE.into())),
    }
}

/// events.Open with Go's error texts.
pub fn open_log(path: &str) -> Result<crate::events::Logger, Fail> {
    sys::go_mkdir_all(&sys::dir(path), 0o700)?;
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| Fail::Msg(sys::go_path_error("open", path, &e)))?;
    }
    crate::events::Logger::open(path).map_err(|e| Fail::Msg(sys::go_path_error("open", path, &e)))
}

fn list(p: &Proofs, io: &mut Io) -> Result<(), Fail> {
    let (recs, st, why) = p.list();
    match st {
        FileState::Missing => {
            let _ = writeln!(io.out, "No base image has been proven yet: the first start of each hashes it in full and records it.");
            return Ok(());
        }
        FileState::Ignored => {
            return Err(Fail::Msg(format!(
                "the record of proven images is not used ({}); every start hashes in full until the next proof rewrites it (as root)",
                why.unwrap_or_else(|| "<nil>".into())
            )))
        }
        FileState::Ok => {}
    }
    if recs.is_empty() {
        let _ = writeln!(io.out, "No base image is recorded.");
    }
    for r in &recs {
        let rec = &r.record;
        let _ = write!(
            io.out,
            "{}\n  sha256 {}, {}, hashed in full {}\n",
            rec.path,
            rec.sha256,
            super::text::size(rec.sig.size),
            tz::local_ymd_hm(&rec.hashed_at)
        );
        if r.quick {
            let _ = writeln!(io.out, "  a start skips the hash (nothing about the file has changed)");
        } else {
            let _ = writeln!(io.out, "  a start hashes it in full: {}", r.why);
        }
    }
    Ok(())
}

/// Duration.Round(100 ms): halves away from zero.
fn round_100ms(d: i64) -> i64 {
    const M: i64 = 100_000_000;
    let r = d % M;
    if r + r < M {
        d - r
    } else {
        d.saturating_add(M - r)
    }
}

fn verify(p: &Proofs, log: &crate::events::Logger, io: &mut Io) -> Result<(), Fail> {
    let (mut changed, mut failed) = (0, 0);
    let mut log_err: Option<String> = None;
    let out = &mut *io.out;
    let r = p.verify_all(&mut |o| match o.result {
        image::RESULT_OK => {
            let _ = writeln!(out, "ok       {} (hashed in {})", o.path, crate::gotext::duration(round_100ms(o.took_ns)));
        }
        image::RESULT_DROPPED => {
            let _ = writeln!(out, "dropped  {}: {}; the next start hashes it in full", o.path, o.detail);
        }
        image::RESULT_GONE => {
            let _ = writeln!(out, "gone     {}: {}; its record is dropped", o.path, o.detail);
        }
        image::RESULT_ERROR => {
            failed += 1;
            let _ = writeln!(out, "ERROR    {}: {}", o.path, o.detail);
        }
        _ => {
            changed += 1;
            let mut trace = "changed";
            let _ = writeln!(out, "CHANGED  {}: {}. Refused: every start hashes it against its manifest.", o.path, o.detail);
            if o.stat_same {
                trace = "unchanged";
                let _ = writeln!(
                    out,
                    "         Its inode, size and times are what they were: the change left no trace in its metadata \
                     (damage on the disk, or a write below the filesystem)."
                );
            }
            if !o.newly_refused {
                return;
            }
            let reason = format!("weekly check: {} no longer hashes to the sha256 it was proven to have", o.path);
            let d = crate::detail([
                ("reason", reason.as_str()),
                ("during", "weekly check"),
                ("path", o.path.as_str()),
                ("sha256", o.recorded.as_str()),
                ("found", o.found.as_str()),
                ("stat", trace),
            ]);
            if let Err(e) = log.emit(crate::events::IMAGE_REJECTED, "", d) {
                log_err.get_or_insert(sys::go_err(&e));
            }
        }
    });
    let outs = match r {
        Err(VerifyErr::Ignored(why)) => {
            return Err(Fail::Msg(format!(
                "image verify: image proofs: the record file was ignored: {why}; nothing to re-check (the next start hashes in full and rewrites it)"
            )))
        }
        Err(VerifyErr::Other(e)) => return Err(Fail::Msg(format!("image verify: {e}"))),
        Ok(o) => o,
    };
    if outs.is_empty() {
        let _ = writeln!(io.out, "No base image has been proven yet: nothing to re-check.");
    }
    if let Some(e) = log_err {
        return Err(Fail::Msg(format!("image verify: the audit log: {e}")));
    }
    if changed > 0 || failed > 0 {
        return Err(Fail::Msg(format!("image verify: {changed} of {} images changed, {failed} could not be read", outs.len())));
    }
    Ok(())
}
