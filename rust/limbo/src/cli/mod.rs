//! The Go CLI's socket-client commands (quarantine, settings, instance, license, exchange), being ported
//! (docs/RUST_PORT.md step 6). So far the pieces their output is made of, each pinned against Go by
//! `testdata/parity/cli.json`; main.rs does not dispatch to them yet, so every command still runs the Go limbo.

pub mod flags;
pub mod tabw;
pub mod text;
