//! limbo-rs, installed as /usr/bin/limbo: `limbo serve` and every command of the CLI, in Rust. The Go limbo it was
//! ported from left the repository on 2026-11-15; rust/parity compares the two against the Go build of a pinned commit
//! (docs/RUST_PORT.md "The Go side").

/// The variables the commands read through `Io::env`. One that is not UTF-8 is refused: the Go limbo took any bytes,
/// and reading it as "" or with U+FFFD would act on something other than what was given.
const VARS: [&str; 9] = ["SUDO_USER", "USER", "PKEXEC_UID", "SUDO_UID", "SUDO_GID", "HOME", "LIMBO_STATE_DIR", "TMPDIR", "WAYLAND_DISPLAY"];

/// Every command but `serve` and `rs-version` (src/cli/commands.rs, src/cli/local.rs), with its exit status.
fn cli_command(cmd: Option<&str>, rest: &[String]) -> i32 {
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let stdin_is_char_device = rustix::fs::fstat(std::io::stdin())
        .is_ok_and(|st| rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::CharacterDevice);
    let (mut stdin, stdout, mut stderr) = (std::io::stdin().lock(), std::io::stdout(), std::io::stderr().lock());
    let mut out = stdout.lock();
    let mut io = limbo::cli::commands::Io {
        env: &env,
        euid: rustix::process::geteuid().as_raw(),
        stdin: &mut stdin,
        stdin_is_char_device,
        out: &mut out,
        err: &mut stderr,
    };
    let r = match cmd.and_then(|c| limbo::cli::commands::run(c, rest, &mut io)) {
        Some(r) => r,
        // local::run answers every command but serve, which main runs before it
        None => limbo::cli::local::run(cmd, rest, &mut io)
            .unwrap_or_else(|| Err(limbo::cli::commands::Fail::Msg(format!("unknown command {:?}", cmd.unwrap_or_default())))),
    };
    use std::io::Write;
    let _ = out.flush();
    match r {
        Ok(()) => 0,
        Err(limbo::cli::commands::Fail::Silent) => 1,
        Err(limbo::cli::commands::Fail::Exit(code)) => code,
        Err(limbo::cli::commands::Fail::Msg(m)) => {
            let _ = writeln!(stderr, "limbo: {m}");
            1
        }
    }
}

fn main() {
    // std::env::args() would panic on an argument that is not UTF-8; as /usr/bin/limbo that panic would be every
    // command's, the daemon's included. Such a command line is refused instead (the Go limbo took any bytes).
    let os_args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let Some(args) = os_args.iter().map(|a| a.to_str().map(String::from)).collect::<Option<Vec<String>>>() else {
        let n = os_args.iter().position(|a| a.to_str().is_none()).unwrap_or(0);
        eprintln!("limbo: argument {n} is not UTF-8 ({:?}); limbo reads its command line as UTF-8", os_args[n]);
        std::process::exit(2);
    };
    // started under one of Wine's names: Limbo's wine on PATH (LIM-25)
    let args = limbo::cli::wine::shim_args(args);
    let first = args.get(1).map(String::as_str);
    match first {
        Some("serve") => {
            if let Err(e) = limbo::serve::run(&args[2..]) {
                eprintln!("limbo: {e}");
                std::process::exit(1);
            }
            return;
        }
        // run by limbo serve for a guest in network mode sinkhole, as the account limbo-sinkhole (docs/SINKHOLE.md)
        Some("sinkhole-responder") => std::process::exit(limbo::sinkhole::responder::run(&args[2..])),
        Some("rs-version") => {
            println!("limbo-rs {} (every command in Rust)", limbo::api::VERSION);
            return;
        }
        _ => {}
    }
    if let Some(v) = VARS.iter().find(|v| std::env::var_os(v).is_some_and(|x| x.to_str().is_none())) {
        eprintln!("limbo: ${v} is not UTF-8; limbo reads it");
        std::process::exit(2);
    }
    std::process::exit(cli_command(first, args.get(2..).unwrap_or_default()));
}
