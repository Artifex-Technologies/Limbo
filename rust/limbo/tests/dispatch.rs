//! main.rs's dispatch as the package installs it (/usr/bin/limbo is limbo-rs): a command limbo-rs does not run itself
//! reaches the Go limbo with its arguments unchanged, bytes that are not UTF-8 included (std::env::args() would panic on
//! them); LIMBO_RS_NO_GO (the differential runs only) stops it instead. The Go limbo here is a fake that prints its
//! arguments, one per line; nothing real is run.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

fn fake_go() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("limbo-d-{}-{}", std::process::id(), limbo::sys::rand_hex(6)));
    std::fs::create_dir_all(&dir).unwrap();
    let go = dir.join("limbo-go");
    std::fs::write(&go, "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n").unwrap();
    std::fs::set_permissions(&go, std::fs::Permissions::from_mode(0o755)).unwrap();
    go
}

fn limbo(go: &std::path::Path, args: &[&[u8]], no_go: bool) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_limbo-rs"));
    c.args(args.iter().map(|a| OsStr::from_bytes(a))).env("LIMBO_GO_BINARY", go).env_remove("LIMBO_RS_NO_GO");
    if no_go {
        c.env("LIMBO_RS_NO_GO", "1");
    }
    c.output().unwrap()
}

fn lines(args: &[&[u8]]) -> Vec<u8> {
    args.iter().flat_map(|a| a.iter().copied().chain(*b"\n")).collect()
}

#[test]
fn unported_and_non_utf8_commands_reach_go_unchanged() {
    let go = fake_go();
    let cases: [&[&[u8]]; 5] = [
        &[b"net", b"watch", b"--json"],
        &[b"capture", b"--guest", b"g\xff\xfe"],
        // a ported command whose arguments are not UTF-8 runs in Go, as it did before the port
        &[b"version", b"\xff"],
        &[b"quarantine", b"list", b"\xc3"],
        // and so does the daemon: never a panic in limbo.service
        &[b"serve", b"--state-dir", b"/var/lib/limbo/\xff"],
    ];
    for args in cases {
        let out = limbo(&go, args, false);
        assert_eq!(
            (out.status.code(), String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)),
            (Some(0), String::from_utf8_lossy(&lines(args)), "".into()),
            "{args:?}"
        );
        assert_eq!(out.stdout, lines(args), "{args:?}");
    }
    std::fs::remove_dir_all(go.parent().unwrap()).unwrap();
}

#[test]
fn no_go_stops_instead_of_running_go() {
    let go = fake_go();
    for args in [&[b"net".as_slice(), b"watch"][..], &[b"capture", b"\xff"]] {
        let out = limbo(&go, args, true);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.starts_with("limbo-rs: ") && err.contains("is not ported (LIMBO_RS_NO_GO is set)"), "{err}");
    }
    let out = limbo(&go, &[b"rs-version"], false);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.starts_with(format!("limbo-rs {} (", limbo::api::VERSION).as_bytes()), "Limbo's VERSION");
    std::fs::remove_dir_all(go.parent().unwrap()).unwrap();
}
