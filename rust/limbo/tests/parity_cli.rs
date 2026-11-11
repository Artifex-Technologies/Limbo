//! testdata/parity/cli.json: the pieces of the socket-client commands' output against Go (cmd/limbo/parity_test.go):
//! flag parsing with its messages and usage, text/tabwriter, json.Indent, a RawMessage's compaction and lookup, `%v`
//! of a float, RFC3339, the CLI's sizes, and `limbo report --since` (parseSince).

mod common;
use common::{fixture, s, Diffs};
use limbo::cli::{flags, tabw, text};
use limbo::gotime::Time;

#[test]
fn cli_pieces_match_go() {
    let mut d = Diffs::default();
    for c in fixture("cli") {
        let i = &c["in"];
        let o = &c["out"];
        match s(&c["fn"]).as_str() {
            "flags" => {
                let name: &'static str = Box::leak(s(&i["set"]).into_boxed_str());
                let mut fs = flags::FlagSet::new(name);
                let mut names = vec![];
                for def in i["defs"].as_array().unwrap() {
                    let n: &'static str = Box::leak(s(&def["Name"]).into_boxed_str());
                    let u: &'static str = Box::leak(s(&def["Usage"]).into_boxed_str());
                    let dv = s(&def["Default"]);
                    match s(&def["Kind"]).as_str() {
                        "s" => fs.string(n, &dv, u),
                        "b" => fs.bool(n, dv == "true", u),
                        _ => fs.int(n, dv.parse().unwrap(), u),
                    }
                    names.push((n, s(&def["Kind"])));
                }
                let args: Vec<String> = i["args"].as_array().unwrap().iter().map(s).collect();
                let what = format!("{name} {args:?}");
                let mut stderr = vec![];
                let r = flags::parse_interspersed(&mut fs, args, &mut stderr);
                let (pos, err) = match r {
                    Ok(p) => (p, String::new()),
                    Err(e) => (vec![], e),
                };
                let want_pos: Vec<String> = o["pos"].as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default();
                if err.is_empty() {
                    d.eq(&format!("pos of {what}"), &pos.join("|"), &want_pos.join("|"));
                }
                d.eq(&format!("err of {what}"), &err, &s(&o["err"]));
                d.eq(&format!("stderr of {what}"), &String::from_utf8_lossy(&stderr), &s(&o["stderr"]));
                for (n, k) in names {
                    let got = match k.as_str() {
                        "s" => fs.str(n),
                        "b" => fs.is_true(n).to_string(),
                        _ => fs.num(n).to_string(),
                    };
                    d.eq(&format!("-{n} of {what}"), &got, &s(&o["values"][n]));
                }
            }
            "tabwriter" => {
                let got = tabw::format(s(i).as_bytes());
                d.eq(&format!("tabwriter {:?}", s(i)), &String::from_utf8_lossy(&got), &s(o));
            }
            "json" => {
                let doc = s(i);
                let what = format!("json {doc:?}");
                match text::indent(doc.as_bytes(), "  ") {
                    Some(b) => d.eq(&format!("indent of {what}"), &String::from_utf8_lossy(&b), &s(&o["indent"])),
                    None => d.eq(&format!("indent error of {what}"), "true", &o["indent_err"].to_string()),
                }
                match text::compact_html(doc.as_bytes()) {
                    Some(b) => d.eq(&format!("compact of {what}"), &String::from_utf8_lossy(&b), &s(&o["compact"])),
                    None => d.eq(&format!("compact error of {what}"), "true", &o["compact_err"].to_string()),
                }
                match text::member_raw(doc.as_bytes(), "instances") {
                    Ok(m) => {
                        d.eq(&format!("member error of {what}"), "", &s(&o["member_err"]));
                        d.eq(&format!("member found of {what}"), &m.is_some().to_string(), &o["member_found"].to_string());
                        d.eq(&format!("member of {what}"), &String::from_utf8_lossy(&m.unwrap_or_default()), &s(&o["member"]));
                    }
                    Err(e) => d.eq(&format!("member error of {what}"), &e, &s(&o["member_err"])),
                }
            }
            "float_v" => {
                let x: f64 = s(i).parse().unwrap();
                d.eq(&format!("%v of {}", s(i)), &text::float_v(x), &s(o));
            }
            "size" => {
                let n = i.as_i64().unwrap();
                d.eq(&format!("size {n}"), &text::size(n), &s(o));
            }
            "rfc3339" => {
                let t = Time::parse_rfc3339(&s(i)).unwrap();
                d.eq(&format!("rfc3339 {}", s(i)), &text::rfc3339(&t), &s(o));
            }
            "since" => {
                let now = Time::parse_rfc3339("2026-11-11T12:30:15.123456789Z").unwrap();
                let (t, e) = match limbo::cli::local::parse_since(&s(i), now) {
                    Ok(t) => (t.rfc3339_nano(), String::new()),
                    Err(e) => (String::new(), e),
                };
                d.eq(&format!("since {:?}", s(i)), &t, &s(&o["time"]));
                d.eq(&format!("since error {:?}", s(i)), &e, &s(&o["err"]));
            }
            f => panic!("unknown fn {f}"),
        }
    }
    d.done("cli");
}
