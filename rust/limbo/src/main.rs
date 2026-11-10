//! limbo-rs: `limbo serve` in Rust. Every other command is handed, unchanged, to the Go limbo binary (docs/RUST_PORT.md).

use std::os::unix::process::CommandExt;

/// Where the Go binary is: $LIMBO_GO_BINARY, then /usr/lib/limbo/limbo-go (where a package puts it once limbo-rs
/// becomes /usr/bin/limbo), then /usr/bin/limbo while that is still the Go one.
fn go_binary() -> Option<String> {
    let me = std::env::current_exe().ok().and_then(|p| std::fs::canonicalize(p).ok());
    let mut cands = vec![];
    if let Ok(p) = std::env::var("LIMBO_GO_BINARY") {
        if !p.is_empty() {
            cands.push(p);
        }
    }
    cands.push("/usr/lib/limbo/limbo-go".into());
    cands.push("/usr/bin/limbo".into());
    cands.into_iter().find(|c| {
        let canon = std::fs::canonicalize(c).ok();
        canon.is_some() && canon != me
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("serve") {
        if let Err(e) = limbo::serve::run(&args[2..]) {
            eprintln!("limbo: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("rs-version") {
        println!("limbo-rs {} (serve in Rust; every other command runs the Go limbo)", env!("CARGO_PKG_VERSION"));
        return;
    }
    match go_binary() {
        Some(go) => {
            let err = std::process::Command::new(&go).arg0("limbo").args(&args[1..]).exec();
            eprintln!("limbo: cannot run the Go limbo ({go}): {err}");
            std::process::exit(1);
        }
        None => {
            eprintln!("limbo: only 'serve' is built into limbo-rs, and no Go limbo was found (set LIMBO_GO_BINARY)");
            std::process::exit(2);
        }
    }
}
