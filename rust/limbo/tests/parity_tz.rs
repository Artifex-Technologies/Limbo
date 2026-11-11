//! testdata/parity/tz.json: Go's time zone files and lookups (cmd/limbo/parity_tz_test.go): TZif files read as
//! LoadLocationFromTZData reads them, and times looked up in them (the POSIX TZ footer included), as `limbo image list`
//! shows a time in the local zone.

mod common;
use common::{fixture, s, Diffs};
use limbo::gotime::Time;
use limbo::tz;

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn tz_matches_go() {
    let mut d = Diffs::default();
    for c in fixture("tz") {
        let name = s(&c["in"]["name"]);
        let loc = tz::from_tzdata(&unhex(&s(&c["in"]["data"])));
        d.eq(&format!("{name}: loads"), &loc.is_some().to_string(), &s(&c["out"]["error"]).is_empty().to_string());
        let Some(loc) = loc else { continue };
        for z in c["out"]["zones"].as_array().unwrap() {
            let sec = z["sec"].as_i64().unwrap();
            let (zn, off, dst) = loc.lookup(sec);
            let what = format!("{name} at {sec}");
            d.eq(&format!("{what}: name"), &zn, &s(&z["name"]));
            d.eq(&format!("{what}: offset"), &off.to_string(), &z["offset"].to_string());
            d.eq(&format!("{what}: dst"), &dst.to_string(), &z["dst"].to_string());
            d.eq(&format!("{what}: local"), &Time::from_unix(sec, 0).in_offset(off as i32).ymd_hm(), &s(&z["local"]));
        }
    }
    d.done("tz");
}
