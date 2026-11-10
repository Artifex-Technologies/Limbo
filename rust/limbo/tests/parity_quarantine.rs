//! testdata/parity/quarantine.json: clean() and a store's answers and files, as the Go code makes them.

mod common;
use common::{fixture, s, Diffs};
use limbo::gotime::Time;
use limbo::quarantine::{self, Store};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};

static CLOCK: AtomicI64 = AtomicI64::new(0);

fn clock() -> Time {
    // Go's test clock: 09:00 UTC, 1.5 s later at each call
    let n = CLOCK.fetch_add(1, Ordering::SeqCst) + 1;
    let base = Time::from_unix(1_794_301_200, 0); // 2026-11-10T09:00:00Z
    base.add(n * 1_500_000_000)
}

#[test]
fn quarantine_matches_go() {
    let mut d = Diffs::default();
    for c in fixture("quarantine") {
        match c["fn"].as_str().unwrap() {
            "clean" => {
                let i = &c["in"];
                d.eq(
                    &format!("clean {:?}", s(&i["s"])),
                    &quarantine::clean(&s(&i["s"]), i["max"].as_u64().unwrap() as usize),
                    &s(&c["out"]),
                );
            }
            "Store" => {
                CLOCK.store(0, Ordering::SeqCst);
                let dir = tempdir();
                let st = Store::open_with_clock(&dir, clock).unwrap();
                let mut ids: Vec<String> = vec![];
                let real = |ids: &Vec<String>, norm: &str| -> String {
                    let n: usize = norm.trim_start_matches("q-").parse().unwrap_or(0);
                    if n == 0 {
                        norm.to_string()
                    } else {
                        ids[n - 1].clone()
                    }
                };
                let norm = |ids: &Vec<String>, x: &str| -> String {
                    let mut x = x.to_string();
                    for (i, id) in ids.iter().enumerate() {
                        x = x.replace(id, &format!("q-{:012}", i + 1));
                    }
                    x
                };
                for step in c["out"]["steps"].as_array().unwrap() {
                    let op = &step["step"];
                    let guest = s(&op["guest"]);
                    let (res, created): (Result<quarantine::Record, quarantine::Error>, bool) = match s(&op["op"]).as_str() {
                        "quarantine" => {
                            let ev: Option<BTreeMap<String, String>> = serde_json::from_value(op["evidence"].clone()).ok();
                            match st.quarantine(&guest, &s(&op["reason"]), &s(&op["source"]), &s(&op["level"]), ev.as_ref()) {
                                Ok((r, created)) => {
                                    if created {
                                        ids.push(r.id.clone());
                                    }
                                    (Ok(r), created)
                                }
                                Err(e) => (Err(e), false),
                            }
                        }
                        "raise" => (st.raise(&real(&ids, &s(&op["id"])), &s(&op["level"])), false),
                        "advisory" => {
                            let id = real(&ids, &s(&op["id"]));
                            for _ in 0..op["before"].as_u64().unwrap() {
                                let _ = st.add_advisory(&id, &s(&op["source"]), &s(&op["text"]));
                            }
                            (st.add_advisory(&id, &s(&op["source"]), &s(&op["text"])), false)
                        }
                        "decide" => (st.decide(&real(&ids, &s(&op["id"])), &s(&op["verdict"]), &s(&op["by"]), &s(&op["note"])), false),
                        "close" => (st.close(&real(&ids, &s(&op["id"])), &s(&op["by"])), false),
                        o => panic!("op {o}"),
                    };
                    let (rec, err) = match res {
                        Ok(r) => (r.json(), String::new()),
                        Err(e) => (quarantine::Record::default().json(), e.to_string()),
                    };
                    let what = format!("{} {}", s(&op["op"]), serde_json::to_string(op).unwrap());
                    d.eq(&what, &norm(&ids, &rec), &s(&step["record"]));
                    d.eq(&format!("error of {what}"), &err, &s(&step["error"]));
                    d.eq("created", &created.to_string(), &step["created"].to_string());
                    let guest = if guest.is_empty() { "lab".to_string() } else { guest };
                    let _ = guest;
                }
                let list: Vec<String> = st.list().iter().map(|r| r.json()).collect();
                d.eq("list", &norm(&ids, &format!("[{}]", list.join(","))), &s(&c["out"]["list"]));
                let mut files: Vec<String> = std::fs::read_dir(&dir)
                    .unwrap()
                    .map(|e| {
                        let e = e.unwrap();
                        format!("{}\n{}", e.file_name().to_string_lossy(), std::fs::read_to_string(e.path()).unwrap())
                    })
                    .map(|f| norm(&ids, &f))
                    .collect();
                files.sort();
                let want: Vec<String> = c["out"]["files"].as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default();
                d.eq("files", &files.join("\n--\n"), &want.join("\n--\n"));
                let _ = std::fs::remove_dir_all(&dir);
            }
            o => panic!("unknown case {o}"),
        }
    }
    d.done("quarantine");
}

fn tempdir() -> String {
    let p = std::env::temp_dir().join(format!("limbo-q-{}-{}", std::process::id(), limbo::sys::rand_hex(4)));
    std::fs::create_dir_all(&p).unwrap();
    p.to_string_lossy().into_owned()
}
