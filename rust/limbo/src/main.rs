//! limbo-rs: `limbo serve`, the socket-client commands (quarantine, settings, instance, license, exchange) and the
//! manifest and file commands (version, validate, plan, address, report) in Rust.
//! Every other command is handed, unchanged, to the Go limbo binary (docs/RUST_PORT.md).

use std::os::unix::process::CommandExt;

/// Where the Go binary is: $LIMBO_GO_BINARY, then `limbo-go` beside this binary (the integration scripts), then
/// /usr/lib/limbo/limbo-go (where a package puts it once limbo-rs becomes /usr/bin/limbo), then /usr/bin/limbo while
/// that is still the Go one.
fn go_binary() -> Option<String> {
    let me = std::env::current_exe().ok().and_then(|p| std::fs::canonicalize(p).ok());
    let mut cands = vec![];
    if let Ok(p) = std::env::var("LIMBO_GO_BINARY") {
        if !p.is_empty() {
            cands.push(p);
        }
    }
    if let Some(dir) = me.as_ref().and_then(|p| p.parent()) {
        cands.push(dir.join("limbo-go").to_string_lossy().into_owned());
    }
    cands.push("/usr/lib/limbo/limbo-go".into());
    cands.push("/usr/bin/limbo".into());
    cands.into_iter().find(|c| {
        let canon = std::fs::canonicalize(c).ok();
        canon.is_some() && canon != me
    })
}

/// The commands ported so far (src/cli/commands.rs, src/cli/local.rs), when their arguments and the environment they read are
/// UTF-8 (otherwise the Go limbo runs them, as it did before: it takes any bytes).
fn cli_command(args: &[std::ffi::OsString]) -> Option<i32> {
    const VARS: [&str; 7] = ["SUDO_USER", "USER", "PKEXEC_UID", "SUDO_UID", "SUDO_GID", "HOME", "LIMBO_STATE_DIR"];
    let cmd = match args.get(1) {
        Some(c) => Some(c.to_str()?),
        None => None,
    };
    if cmd == Some("rs-version") {
        return None;
    }
    let rest: Vec<String> = args.get(2..).unwrap_or_default().iter().map(|a| a.to_str().map(String::from)).collect::<Option<_>>()?;
    if VARS.iter().any(|v| std::env::var_os(v).is_some_and(|x| x.to_str().is_none())) {
        return None;
    }
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
    let r = match cmd.and_then(|c| limbo::cli::commands::run(c, &rest, &mut io)) {
        Some(r) => r,
        None => limbo::cli::local::run(cmd, &rest, &mut io)?,
    };
    use std::io::Write;
    let _ = out.flush();
    Some(match r {
        Ok(()) => 0,
        Err(limbo::cli::commands::Fail::Silent) => 1,
        Err(limbo::cli::commands::Fail::Msg(m)) => {
            let _ = writeln!(stderr, "limbo: {m}");
            1
        }
    })
}

fn main() {
    let os_args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if let Some(code) = cli_command(&os_args) {
        std::process::exit(code);
    }
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("serve") {
        if let Err(e) = limbo::serve::run(&args[2..]) {
            eprintln!("limbo: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("rs-version") {
        println!(
            "limbo-rs {} (serve, quarantine, settings, instance, license, exchange, version, validate, plan, address and report in Rust; every other command runs the Go limbo)",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }
    match go_binary() {
        Some(go) => {
            let err = std::process::Command::new(&go).arg0("limbo").args(&args[1..]).exec();
            eprintln!("limbo: cannot run the Go limbo ({go}): {err}");
            std::process::exit(1);
        }
        None => {
            eprintln!("limbo: this command runs the Go limbo, and none was found (set LIMBO_GO_BINARY)");
            std::process::exit(2);
        }
    }
}
