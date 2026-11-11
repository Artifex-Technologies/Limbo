//! Limbo's always-on daemon (`limbo serve`) in Rust. The Go packages it replaces are named in each module; the Go code
//! stays the reference, and its behaviour is pinned by the fixtures in testdata/parity (docs/RUST_PORT.md).
#![allow(clippy::type_complexity, clippy::too_many_arguments, clippy::collapsible_match)]

pub mod gojson;
pub mod gotext;
pub mod gotime;
pub mod osuser;
pub mod sys;

pub mod events;
pub mod manifest;
pub mod quarantine;
pub mod report;
pub mod settings;

pub mod disk;
pub mod hostfw;
pub mod policy;
pub mod provision;
pub mod virt;

pub mod engine;
pub mod exchange;
pub mod hostpolicy;
pub mod image;
pub mod instances;
pub mod launch;
pub mod license;
pub mod runs;

pub mod flows;

pub mod api;
pub mod cli;
pub mod http;
pub mod serve;

pub mod fuzzing;

/// A refusal with a stable code, a plain message, a one-line remedy and (when it has one) the HTTP status it maps to:
/// Go's runs.Error, instances.Error, exchange.Error, api.apiError and api.badRequest in one shape.
#[derive(Clone, Debug, PartialEq)]
pub struct Refusal {
    pub status: Option<u16>,
    pub code: String,
    pub message: String,
    pub remedy: String,
    /// The fixed sentence a skipped profile shows (runs only).
    pub short: String,
}

impl Refusal {
    pub fn new(status: Option<u16>, code: &str, remedy: &str, message: String) -> Refusal {
        Refusal { status, code: code.into(), message, remedy: remedy.into(), short: String::new() }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}. Remedy: {}", self.code, self.message, self.remedy)
    }
}

/// The audit log's detail: strings only, written with sorted keys (Go's map order in JSON).
pub type Detail = std::collections::BTreeMap<String, String>;

/// Builds a [`Detail`] from pairs.
pub fn detail<const N: usize>(pairs: [(&str, &str); N]) -> Detail {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}
