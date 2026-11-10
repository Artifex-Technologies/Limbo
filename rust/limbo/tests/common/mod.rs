//! Reading the Go fixtures (testdata/parity/*.json).

use serde_json::Value;

pub fn fixture(name: &str) -> Vec<Value> {
    let path = format!("{}/../../testdata/parity/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let b = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let v: Value = serde_json::from_slice(&b).unwrap_or_else(|e| panic!("{path}: {e}"));
    v["cases"].as_array().cloned().unwrap_or_default()
}

pub fn s(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

/// Compares and collects differences, so one run reports all of them.
#[derive(Default)]
pub struct Diffs {
    pub n: usize,
    pub bad: Vec<String>,
}

impl Diffs {
    pub fn eq(&mut self, what: &str, got: &str, want: &str) {
        self.n += 1;
        if got != want {
            // the first difference with some context, so a long document stays readable
            let at = got.bytes().zip(want.bytes()).position(|(a, b)| a != b).unwrap_or(got.len().min(want.len()));
            let win = |s: &str| {
                let mut a = at.saturating_sub(60);
                while !s.is_char_boundary(a) {
                    a -= 1;
                }
                let mut b = (at + 60).min(s.len());
                while !s.is_char_boundary(b) {
                    b -= 1;
                }
                s[a..b].to_string()
            };
            let what: String = what.chars().take(160).collect();
            self.bad.push(format!("{what}\n  at byte {at}\n  got:  {:?}\n  want: {:?}", win(got), win(want)));
        }
    }
    pub fn done(self, name: &str) {
        if !self.bad.is_empty() {
            let shown: Vec<&String> = self.bad.iter().take(25).collect();
            panic!("{name}: {} of {} comparisons differ from Go:\n{}", self.bad.len(), self.n, shown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n"));
        }
        eprintln!("{name}: {} comparisons, all equal to Go", self.n);
    }
}
