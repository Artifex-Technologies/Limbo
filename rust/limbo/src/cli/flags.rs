//! Go's `flag` package as the Go CLI uses it (`flag.NewFlagSet(name, flag.ContinueOnError)` and `parseInterspersed`):
//! the same syntax (`-x`, `--x`, `-x=v`, `-x v`, `--` ending the flags), the same messages, and on a mistake the same
//! "Usage of NAME:" listing on stderr. String, bool and int flags are all the commands need.

use crate::gotext::quote;

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Str,
    Bool,
    Int,
    /// a repeatable string flag (a flag.Value whose Set appends; its usage names its argument "value")
    List,
}

struct Flag {
    name: &'static str,
    kind: Kind,
    usage: &'static str,
    default: String,
    value: String,
    values: Vec<String>,
}

pub struct FlagSet {
    name: &'static str,
    flags: Vec<Flag>,
    /// the first line of the usage when the Go flag set has its own Usage function (then PrintDefaults)
    header: Option<&'static str>,
}

/// What a parse failed with: Go's error text. The usage has already gone to `stderr`.
pub const HELP: &str = "flag: help requested";

impl FlagSet {
    pub fn new(name: &'static str) -> FlagSet {
        FlagSet { name, flags: vec![], header: None }
    }

    /// A Usage function of the set's own: `header` on its own line, then the flags.
    pub fn usage_header(&mut self, header: &'static str) {
        self.header = Some(header);
    }

    pub fn string(&mut self, name: &'static str, default: &str, usage: &'static str) {
        self.flags.push(Flag { name, kind: Kind::Str, usage, default: default.into(), value: default.into(), values: vec![] });
    }

    pub fn bool(&mut self, name: &'static str, default: bool, usage: &'static str) {
        let d = if default { "true" } else { "false" };
        self.flags.push(Flag { name, kind: Kind::Bool, usage, default: d.into(), value: d.into(), values: vec![] });
    }

    pub fn int(&mut self, name: &'static str, default: i64, usage: &'static str) {
        let d = default.to_string();
        self.flags.push(Flag { name, kind: Kind::Int, usage, default: d.clone(), value: d, values: vec![] });
    }

    pub fn list(&mut self, name: &'static str, usage: &'static str) {
        self.flags.push(Flag { name, kind: Kind::List, usage, default: String::new(), value: String::new(), values: vec![] });
    }

    /// Every value a repeatable flag was given, in order.
    pub fn strs(&self, name: &str) -> Vec<String> {
        self.get(name).values.clone()
    }

    fn get(&self, name: &str) -> &Flag {
        self.flags.iter().find(|f| f.name == name).expect("flag defined")
    }

    pub fn str(&self, name: &str) -> String {
        self.get(name).value.clone()
    }

    pub fn is_true(&self, name: &str) -> bool {
        self.get(name).value == "true"
    }

    pub fn num(&self, name: &str) -> i64 {
        self.get(name).value.parse().unwrap_or(0)
    }

    /// Go's `defaultUsage`: "Usage of NAME:" ("Usage:" for a set without a name) and `PrintDefaults`, flags sorted by name.
    pub fn usage(&self, out: &mut Vec<u8>) {
        if let Some(h) = self.header {
            out.extend_from_slice(h.as_bytes());
            out.push(b'\n');
        } else if self.name.is_empty() {
            out.extend_from_slice(b"Usage:\n");
        } else {
            out.extend_from_slice(format!("Usage of {}:\n", self.name).as_bytes());
        }
        let mut fl: Vec<&Flag> = self.flags.iter().collect();
        fl.sort_by(|a, b| a.name.cmp(b.name));
        for f in fl {
            let mut b = format!("  -{}", f.name);
            match f.kind {
                Kind::Str => b.push_str(" string"),
                Kind::Int => b.push_str(" int"),
                Kind::List => b.push_str(" value"),
                Kind::Bool => {}
            }
            // a one-letter flag without a type name stays on one line
            if b.len() <= 4 {
                b.push('\t');
            } else {
                b.push_str("\n    \t");
            }
            b.push_str(&f.usage.replace('\n', "\n    \t"));
            let zero = match f.kind {
                Kind::Str | Kind::List => "",
                Kind::Bool => "false",
                Kind::Int => "0",
            };
            if f.default != zero {
                match f.kind {
                    Kind::Str => b.push_str(&format!(" (default {})", quote(&f.default))),
                    _ => b.push_str(&format!(" (default {})", f.default)),
                }
            }
            b.push('\n');
            out.extend_from_slice(b.as_bytes());
        }
    }

    fn fail(&self, msg: String, stderr: &mut Vec<u8>) -> String {
        stderr.extend_from_slice(msg.as_bytes());
        stderr.push(b'\n');
        self.usage(stderr);
        msg
    }

    /// `fs.Parse(args)`: the arguments left after the flags (Go's `fs.Args()`).
    pub fn parse(&mut self, mut args: &[String], stderr: &mut Vec<u8>) -> Result<Vec<String>, String> {
        loop {
            let Some(s) = args.first() else { return Ok(vec![]) };
            let b = s.as_bytes();
            if b.len() < 2 || b[0] != b'-' {
                return Ok(args.to_vec());
            }
            let mut minuses = 1;
            if b[1] == b'-' {
                minuses = 2;
                if b.len() == 2 {
                    return Ok(args[1..].to_vec());
                }
            }
            let name = &s[minuses..];
            if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
                return Err(self.fail(format!("bad flag syntax: {s}"), stderr));
            }
            args = &args[1..];
            let (name, mut value) = match name.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (name, None),
            };
            let Some(i) = self.flags.iter().position(|f| f.name == name) else {
                if name == "help" || name == "h" {
                    self.usage(stderr);
                    return Err(HELP.into());
                }
                return Err(self.fail(format!("flag provided but not defined: -{name}"), stderr));
            };
            match self.flags[i].kind {
                Kind::Bool => {
                    let v = value.unwrap_or_else(|| "true".into());
                    match parse_bool(&v) {
                        Some(x) => self.flags[i].value = x.to_string(),
                        None => return Err(self.fail(format!("invalid boolean value {} for -{name}: parse error", quote(&v)), stderr)),
                    }
                }
                kind => {
                    if value.is_none() && !args.is_empty() {
                        value = Some(args[0].clone());
                        args = &args[1..];
                    }
                    let Some(v) = value else {
                        return Err(self.fail(format!("flag needs an argument: -{name}"), stderr));
                    };
                    if kind == Kind::Int {
                        match parse_int(&v) {
                            Ok(x) => self.flags[i].value = x.to_string(),
                            Err(why) => {
                                // Go's intValue.Set stores what ParseInt returned: the nearest bound on a range error
                                if why == RANGE {
                                    self.flags[i].value = if v.starts_with('-') { i64::MIN } else { i64::MAX }.to_string();
                                } else {
                                    self.flags[i].value = "0".into();
                                }
                                return Err(self.fail(format!("invalid value {} for flag -{name}: {why}", quote(&v)), stderr));
                            }
                        }
                    } else if kind == Kind::List {
                        self.flags[i].values.push(v);
                    } else {
                        self.flags[i].value = v;
                    }
                }
            }
        }
    }
}

/// The Go CLI's `parseInterspersed`: flags may follow positional arguments.
pub fn parse_interspersed(fs: &mut FlagSet, mut args: Vec<String>, stderr: &mut Vec<u8>) -> Result<Vec<String>, String> {
    let mut pos = vec![];
    loop {
        let rest = fs.parse(&args, stderr)?;
        if rest.is_empty() {
            return Ok(pos);
        }
        pos.push(rest[0].clone());
        args = rest[1..].to_vec();
    }
}

/// strconv.ParseBool
pub fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

const SYNTAX: &str = "parse error";
const RANGE: &str = "value out of range";

/// strconv.ParseInt(s, 0, 64), with the flag package's short reasons ("parse error", "value out of range").
pub fn parse_int(s0: &str) -> Result<i64, &'static str> {
    if s0.is_empty() {
        return Err(SYNTAX);
    }
    let (neg, s) = match s0.as_bytes()[0] {
        b'+' => (false, &s0[1..]),
        b'-' => (true, &s0[1..]),
        _ => (false, s0),
    };
    // ParseUint(s, 0, 64)
    if s.is_empty() {
        return Err(SYNTAX);
    }
    let b = s.as_bytes();
    let (base, digits): (u64, &[u8]) = if b[0] == b'0' {
        if b.len() >= 3 && matches!(b[1].to_ascii_lowercase(), b'b' | b'o' | b'x') {
            (
                match b[1].to_ascii_lowercase() {
                    b'b' => 2,
                    b'o' => 8,
                    _ => 16,
                },
                &b[2..],
            )
        } else {
            (8, &b[1..])
        }
    } else {
        (10, b)
    };
    let mut n: u64 = 0;
    let mut underscores = false;
    for &c in digits {
        let d = match c {
            b'_' => {
                underscores = true;
                continue;
            }
            b'0'..=b'9' => (c - b'0') as u64,
            b'a'..=b'z' => (c - b'a' + 10) as u64,
            b'A'..=b'Z' => (c - b'A' + 10) as u64,
            _ => return Err(SYNTAX),
        };
        if d >= base {
            return Err(SYNTAX);
        }
        // overflow: Go stops at once with a range error
        n = match n.checked_mul(base).and_then(|x| x.checked_add(d)) {
            Some(x) => x,
            None => return Err(RANGE),
        };
    }
    if underscores && !underscore_ok(s) {
        return Err(SYNTAX);
    }
    let cutoff = 1u64 << 63;
    if !neg && n >= cutoff {
        return Err(RANGE);
    }
    if neg && n > cutoff {
        return Err(RANGE);
    }
    Ok(if neg { (n as i64).wrapping_neg() } else { n as i64 })
}

/// strconv's underscoreOK: underscores only between digits (or after a base prefix).
fn underscore_ok(s: &str) -> bool {
    let mut b = s.as_bytes();
    if !b.is_empty() && (b[0] == b'-' || b[0] == b'+') {
        b = &b[1..];
    }
    let mut saw = b'^';
    let mut i = 0;
    let mut hex = false;
    if b.len() >= 2 && b[0] == b'0' && matches!(b[1].to_ascii_lowercase(), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = b[1].eq_ignore_ascii_case(&b'x');
    }
    while i < b.len() {
        let c = b[i];
        let l = c.to_ascii_lowercase();
        if c.is_ascii_digit() || hex && (b'a'..=b'f').contains(&l) {
            saw = b'0';
        } else if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else {
            if saw == b'_' {
                return false;
            }
            saw = b'!';
        }
        i += 1;
    }
    saw != b'_'
}
