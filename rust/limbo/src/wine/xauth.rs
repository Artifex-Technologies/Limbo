//! The X authority filter (Go: internal/wine/xauth.go): the entries a client in the sandbox needs for one display,
//! rewritten as "wild" entries with no address, so the real host name never reaches the sandbox.

const XAUTH_LOCAL: u16 = 256;
const XAUTH_WILD: u16 = 0xffff;

/// FilterXauth: local or wild entries for display n (or for any display), as wild entries; a damaged file yields what
/// parsed before the damage.
pub fn filter_xauth(mut b: &[u8], n: i64) -> Vec<u8> {
    let want = n.to_string();
    let mut out = Vec::new();
    fn field(p: &[u8]) -> Option<(&[u8], &[u8])> {
        if p.len() < 2 {
            return None;
        }
        let l = u16::from_be_bytes([p[0], p[1]]) as usize;
        if p.len() < 2 + l {
            return None;
        }
        Some((&p[2..2 + l], &p[2 + l..]))
    }
    let put = |out: &mut Vec<u8>, f: &[u8]| {
        out.extend_from_slice(&(f.len() as u16).to_be_bytes());
        out.extend_from_slice(f);
    };
    while b.len() >= 2 {
        let family = u16::from_be_bytes([b[0], b[1]]);
        let rest = &b[2..];
        let Some((_addr, rest)) = field(rest) else { break };
        let Some((num, rest)) = field(rest) else { break };
        let Some((name, rest)) = field(rest) else { break };
        let Some((data, rest)) = field(rest) else { break };
        b = rest;
        if (family == XAUTH_LOCAL || family == XAUTH_WILD) && (num.is_empty() || num == want.as_bytes()) {
            out.extend_from_slice(&XAUTH_WILD.to_be_bytes());
            put(&mut out, &[]);
            put(&mut out, num);
            put(&mut out, name);
            put(&mut out, data);
        }
    }
    out
}
