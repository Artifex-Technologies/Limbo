//! main.rs's dispatch as the package installs it (/usr/bin/limbo is limbo-rs, and there is no Go limbo to hand a
//! command to since 2026-11-15): a command line that is not UTF-8, the daemon's included, is refused with exit status 2
//! and never panics (std::env::args() would); so is a variable the commands read that is not UTF-8. `limbo wine` refuses
//! only the variables it reads or hands to the sandbox; any other is left out, as it never reached the sandbox.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Output};

fn limbo(args: &[&[u8]], env: &[(&str, &[u8])]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_limbo-rs"));
    c.args(args.iter().map(|a| OsStr::from_bytes(a)));
    for (k, v) in env {
        c.env(k, OsStr::from_bytes(v));
    }
    c.output().unwrap()
}

#[test]
fn non_utf8_command_lines_are_refused_not_a_panic() {
    let cases: [&[&[u8]]; 6] = [
        &[b"capture", b"--guest", b"g\xff\xfe"],
        &[b"version", b"\xff"],
        &[b"quarantine", b"list", b"\xc3"],
        &[b"\xff"],
        &[b"wine", b"--", b"/tmp/a\xe9.exe"],
        // the daemon too: never a panic in limbo.service
        &[b"serve", b"--state-dir", b"/var/lib/limbo/\xff"],
    ];
    for args in cases {
        let out = limbo(args, &[]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {err}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(err.starts_with("limbo: argument ") && err.contains("is not UTF-8"), "{args:?}: {err}");
    }
}

#[test]
fn non_utf8_variables_that_are_read_are_refused() {
    for v in ["LIMBO_STATE_DIR", "SUDO_USER", "HOME"] {
        let out = limbo(&[b"version"], &[(v, b"x\xff")]);
        assert_eq!(out.status.code(), Some(2), "{v}");
        assert_eq!(String::from_utf8_lossy(&out.stderr), format!("limbo: ${v} is not UTF-8; limbo reads it\n"));
    }
    // limbo wine reads the whole environment: a variable it uses is refused, any other left out
    let out = limbo(&[b"wine", b"--bogus"], &[("DISPLAY", b":0\xff")]);
    assert_eq!(String::from_utf8_lossy(&out.stderr), "limbo: wine: $DISPLAY is not UTF-8; limbo reads it\n");
    let out = limbo(&[b"wine", b"--bogus"], &[("SOME_OTHER_THING", b"\xff")]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("flag provided but not defined: -bogus"), "{err}");
}

#[test]
fn ported_commands_and_rs_version_run_here() {
    let out = limbo(&[b"rs-version"], &[]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.starts_with(format!("limbo-rs {} (every command in Rust)", limbo::api::VERSION).as_bytes()));
    for (args, want) in [
        (&[b"net".as_slice()][..], "limbo: usage: limbo net watch [--seconds N]"),
        (&[b"capture"], "limbo: capture: manifest path required"),
    ] {
        let out = limbo(args, &[]);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).starts_with(want), "{args:?}");
    }
}

/// LIM-25: started as wine (or another of Wine's names) through a link, limbo is Limbo's wine on PATH: the same as
/// `limbo wine --shim -- [NAME] ARGS`. A WINEPREFIX outside Limbo's prefixes is refused, so nothing runs here.
#[test]
fn as_wine_through_a_link_it_is_the_shim() {
    let dir = std::env::temp_dir().join(format!("limbo-shim-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("home")).unwrap();
    let bin = env!("CARGO_BIN_EXE_limbo-rs");
    let run = |cmd: &std::path::Path, args: &[&str]| {
        let out = Command::new(cmd)
            .args(args)
            .env_clear()
            .env("HOME", dir.join("home"))
            .env("PATH", "/usr/bin")
            .env("WINEPREFIX", "/tmp/somewhere-else")
            .output()
            .unwrap();
        (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    for (name, args, direct) in [
        ("wine", vec!["setup.exe", "/S"], vec!["wine", "--shim", "--", "setup.exe", "/S"]),
        ("wine64", vec!["x.exe"], vec!["wine", "--shim", "--", "x.exe"]),
        ("winecfg", vec![], vec!["wine", "--shim", "--", "winecfg"]),
        ("regedit", vec!["/s", "a.reg"], vec!["wine", "--shim", "--", "regedit", "/s", "a.reg"]),
    ] {
        let link = dir.join(name);
        std::os::unix::fs::symlink(bin, &link).unwrap();
        let (via_link, via_limbo) = (run(&link, &args), run(std::path::Path::new(bin), &direct));
        assert_eq!(via_link, via_limbo, "{name} {args:?}");
        assert_ne!(via_link.0, Some(0), "{name}: refused, nothing ran: {via_link:?}");
        assert!(via_link.2.contains("WINEPREFIX"), "{name}: {via_link:?}");
    }
    // under another name it is limbo as usual
    let other = dir.join("limbo-other");
    std::os::unix::fs::symlink(bin, &other).unwrap();
    assert_eq!(run(&other, &["version", "--bogus"]), run(std::path::Path::new(bin), &["version", "--bogus"]));
    let _ = std::fs::remove_dir_all(&dir);
}
