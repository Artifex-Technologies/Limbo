//! The Go CLI's socket-client commands (quarantine, settings, instance, license, exchange), ported (docs/RUST_PORT.md
//! step 6): the pieces their output is made of (`flags`, `tabw`, `text`, pinned by `testdata/parity/cli.json`), the
//! HTTP client over the unix socket (`url`, `client`, pinned by `testdata/parity/cliclient.json`), and the commands
//! themselves (`commands`, compared with the Go binary by rust/parity/cli-differential.py).

pub mod act;
pub mod analyze;
pub mod client;
pub mod commands;
pub mod flags;
pub mod goexec;
pub mod image;
pub mod local;
pub mod passthrough;
pub mod seed;
pub mod setup;
pub mod tabw;
pub mod text;
pub mod url;
pub mod wine;
