//! testdata/parity/wine.json: the Wine backend's parts that do not touch the host, as the Go code answers them
//! (internal/wine/parity_test.go): names, folders, profiles, Merge against a folder tree (made here the same way;
//! "{R}" stands for its root), CheckShare, ShimPrefix, the X authority filter, the trace splitter, the sandbox for
//! hand-written hosts, the dry run, the records, the lock's message, ensureDir and the pruning of run folders.

mod common;
use common::{fixture, s, Diffs};
use limbo::wine::record::{self, Allowed, Record, RecordShare, Trace};
use limbo::wine::sandbox::{self, Host};
use limbo::wine::{self, prefix, probe, profile, run, trace, xauth, Dirs, Flags, Options, Share};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default()
}

fn smap(v: &Value) -> BTreeMap<String, String> {
    v.as_object().map(|o| o.iter().map(|(k, x)| (k.clone(), s(x))).collect()).unwrap_or_default()
}

fn err(r: Result<(), String>) -> String {
    r.err().unwrap_or_default()
}

fn host(v: &Value) -> Host {
    Host {
        uid: v["uid"].as_u64().unwrap() as u32,
        gid: v["gid"].as_u64().unwrap() as u32,
        user: s(&v["user"]),
        group: s(&v["group"]),
        home: s(&v["home"]),
        env: smap(&v["env"]),
        root_links: smap(&v["root_links"]),
        root_dirs: strs(&v["root_dirs"]),
        etc: v["etc"].as_object().map(|o| o.iter().map(|(k, x)| (k.clone(), x.as_bool().unwrap())).collect()).unwrap_or_default(),
        localtime: s(&v["localtime"]),
        ntsync: v["ntsync"].as_bool().unwrap(),
        cpuinfo: v["cpuinfo"].as_bool().unwrap(),
        fontcache: v["fontcache"].as_bool().unwrap(),
        wayland: s(&v["wayland"]),
        x11_display: v["x11_display"].as_i64().unwrap(),
        x11_socket: s(&v["x11_socket"]),
        xauth: if v["xauth_nil"].as_bool().unwrap() { None } else { Some(unhex(&s(&v["xauth"]))) },
        pulse: s(&v["pulse"]),
        pipewire: s(&v["pipewire"]),
        pulse_cookie: unhex(&s(&v["pulse_cookie"])),
        gpu_nodes: strs(&v["gpu_nodes"]),
        gpu_sys: strs(&v["gpu_sys"]),
        driver_dirs: strs(&v["driver_dirs"]),
    }
}

fn shares_json(shares: &[Share]) -> Value {
    Value::Array(shares.iter().map(|sh| json!({"path": sh.path, "source": sh.source, "writable": sh.writable})).collect())
}

fn options(v: &Value) -> Options {
    Options {
        prefix: s(&v["prefix"]),
        network: s(&v["network"]),
        gpu: v["gpu"].as_bool().unwrap(),
        audio: v["audio"].as_bool().unwrap(),
        display: v["display"].as_bool().unwrap(),
        x11: v["x11"].as_bool().unwrap(),
        shares: v["shares"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| Share { path: s(&x["path"]), source: s(&x["source"]), writable: x["writable"].as_bool().unwrap() })
            .collect(),
        env: smap(&v["env"]),
        arch: s(&v["arch"]),
        windows: s(&v["windows"]),
        trace: v["trace"].as_bool().unwrap(),
    }
}

fn options_json(o: &Options) -> Value {
    json!({"prefix": o.prefix, "network": o.network, "gpu": o.gpu, "audio": o.audio, "display": o.display, "x11": o.x11,
        "shares": shares_json(&o.shares), "env": o.env, "arch": o.arch, "windows": o.windows, "trace": o.trace})
}

fn dirs(v: &Value) -> Dirs {
    Dirs { root: s(&v["root"]), cache: s(&v["cache"]), config: s(&v["config"]), state: s(&v["state"]) }
}

fn dirs_json(d: &Dirs) -> Value {
    json!({"root": d.root, "cache": d.cache, "config": d.config, "state": d.state})
}

fn flags(v: &Value, root: &str) -> Flags {
    let re = |l: Vec<String>| l.into_iter().map(|x| x.replace("{R}", root)).collect();
    Flags {
        network: v["network"].as_bool().unwrap(),
        no_gpu: v["no_gpu"].as_bool().unwrap(),
        no_audio: v["no_audio"].as_bool().unwrap(),
        no_x11: v["no_x11"].as_bool().unwrap(),
        no_display: v["no_display"].as_bool().unwrap(),
        headless: v["headless"].as_bool().unwrap(),
        share: re(strs(&v["share"])),
        share_rw: re(strs(&v["share_rw"])),
        env: strs(&v["env"]),
        windows: s(&v["windows"]),
        arch: s(&v["arch"]),
        trace: v["trace"].as_bool().unwrap(),
    }
}

fn profile_json(p: Option<&profile::Profile>) -> Value {
    let Some(p) = p else { return Value::Null };
    json!({"network": p.network, "gpu": p.gpu, "audio": p.audio, "display": p.display, "x11": p.x11, "share": p.share,
        "share_rw": p.share_rw, "env": p.env, "windows": p.windows, "arch": p.arch, "trace": p.trace, "program": p.program,
        "args": p.args})
}

fn sandbox_json(r: &Result<sandbox::Sandbox, String>) -> Value {
    match r {
        Err(e) => json!({"error": e}),
        Ok(s) => {
            let data: Vec<Value> = s.data.iter().map(|d| json!({"dest": d.dest, "content": limbo::sys::hex(&d.content)})).collect();
            json!({"args": s.args, "env": s.env, "data": data, "display": s.display, "audio": s.audio, "gpu": s.gpu,
                "chdir": s.chdir, "error": ""})
        }
    }
}

/// The answer with the tree's root as "{R}", as Go's unroot writes it.
fn unroot(v: Value, root: &str) -> Value {
    serde_json::from_str(&serde_json::to_string(&v).unwrap().replace(root, "{R}")).unwrap()
}

fn eqv(d: &mut Diffs, what: &str, got: &Value, want: &Value) {
    d.eq(what, &serde_json::to_string(got).unwrap(), &serde_json::to_string(want).unwrap());
}

fn make_tree(entries: &Value) -> String {
    let p = std::env::temp_dir().join(format!("limbo-wine-{}-{}", std::process::id(), limbo::sys::rand_hex(4)));
    std::fs::create_dir_all(&p).unwrap();
    let root = std::fs::canonicalize(&p).unwrap().to_string_lossy().into_owned();
    for e in entries.as_array().unwrap() {
        let path = format!("{root}/{}", s(&e["path"]));
        let body = s(&e["body"]).replace("{R}", &root);
        let mode = e["mode"].as_u64().unwrap_or(0) as u32;
        match s(&e["kind"]).as_str() {
            "dir" => std::fs::create_dir_all(&path).unwrap(),
            "file" => {
                let pad = e["pad"].as_u64().unwrap_or(0) as usize;
                std::fs::write(&path, format!("{}{body}", " ".repeat(pad))).unwrap()
            }
            "link" => std::os::unix::fs::symlink(&body, &path).unwrap(),
            "fifo" => {
                let c = std::ffi::CString::new(path.clone()).unwrap();
                // SAFETY: mkfifo on a path we own
                assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            }
            k => panic!("tree kind {k}"),
        }
        if s(&e["kind"]) != "link" {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }
    root
}

#[test]
fn wine_matches_go() {
    let mut d = Diffs::default();
    let mut root = String::new();
    let mut test_host = Host::default();
    let no_log = |e: &std::io::Error| e.to_string();
    for c in fixture("wine") {
        let i = &c["in"];
        let o = &c["out"];
        let what = format!("{} {}", s(&c["fn"]), serde_json::to_string(i).unwrap().chars().take(140).collect::<String>());
        match s(&c["fn"]).as_str() {
            "tree" => root = make_tree(i),
            "names" => {
                let n = s(i);
                let got = json!({"name": err(wine::valid_name(&n)), "windows": err(wine::valid_windows(&n)),
                    "arch": err(wine::valid_arch(&n)), "env": err(sandbox::valid_env_name(&n)), "pass": sandbox::pass_env(&n),
                    "guest": wine::guest(&n)});
                eqv(&mut d, &what, &got, o);
            }
            "dirs" => {
                let env = smap(&i["env"]);
                let dd = Dirs::default_dirs(&|k| env.get(k).cloned().unwrap_or_default(), &s(&i["home"]), &s(&i["state"]));
                let got = json!({"dirs": dirs_json(&dd), "prefix": dd.prefix("game"), "cache": dd.prefix_cache("game"),
                    "profile": dd.profile("game"), "lock": dd.lock_file("game"), "record": dd.record_file("game"),
                    "creating": dd.creating_file("game"), "runs": record::runs_dir(&dd.state)});
                eqv(&mut d, &what, &got, o);
            }
            "profile" => {
                let r = profile::parse_profile(s(i).as_bytes());
                let got = json!({"profile": profile_json(r.as_ref().ok()), "error": r.err().unwrap_or_default()});
                eqv(&mut d, &what, &got, o);
            }
            "load_profile" => {
                let got = match profile::load_profile(&s(i).replace("{R}", &root)) {
                    Ok((p, sum)) => json!({"profile": profile_json(p.as_ref()), "sha256": sum, "error": ""}),
                    Err(e) => json!({"profile": null, "sha256": "", "error": e}),
                };
                eqv(&mut d, &what, &unroot(got, &root), o);
            }
            "merge" => {
                let doc = s(&i["profile"]);
                let p = (!doc.is_empty()).then(|| profile::parse_profile(doc.replace("{R}", &root).as_bytes()).unwrap());
                let f = flags(&i["flags"], &root);
                let r = wine::merge("game", p.as_ref(), &f, &s(&i["cwd"]).replace("{R}", &root), &s(&i["home"]).replace("{R}", &root));
                let got = match r {
                    Ok(o) => json!({"error": "", "options": options_json(&o)}),
                    Err(e) => json!({"error": e}),
                };
                eqv(&mut d, &what, &unroot(got, &root), o);
            }
            "check_share" => {
                let sh = &i["share"];
                let share = Share { path: s(&sh["path"]), source: s(&sh["source"]), writable: sh["writable"].as_bool().unwrap() };
                let home = s(&i["home"]);
                let got = json!({"error": err(wine::check_share(&share, &home, &dirs(&i["dirs"]))),
                    "within": wine::within(&share.path, &home), "within_rev": wine::within(&home, &share.path)});
                eqv(&mut d, &what, &got, o);
            }
            "within" => eqv(&mut d, &what, &json!(wine::within(&s(&i[0]), &s(&i[1]))), o),
            "shim_prefix" => {
                let (p, e) = match wine::shim_prefix(&s(&i["wineprefix"]), &dirs(&i["dirs"])) {
                    Ok(p) => (p, String::new()),
                    Err(e) => (String::new(), e),
                };
                eqv(&mut d, &what, &json!({"prefix": p, "error": e}), o);
            }
            "xauth" => {
                let got = limbo::sys::hex(&xauth::filter_xauth(&unhex(&s(&i["in"])), i["n"].as_i64().unwrap()));
                d.eq(&what, &got, &s(o));
            }
            "split_trace" => {
                let mut input = Vec::new();
                for p in i["parts"].as_array().unwrap() {
                    input.extend(s(&p["text"]).repeat(p["n"].as_u64().unwrap() as usize).into_bytes());
                }
                let (mut tr, mut other) = (Vec::new(), Vec::new());
                let (n, cut) = trace::split_trace(&input[..], &mut tr, &mut other, i["limit"].as_i64().unwrap());
                use sha2::Digest;
                let got = json!({"n": n, "cut": cut, "trace": limbo::sys::hex(&sha2::Sha256::digest(&tr)), "trace_len": tr.len(),
                    "other": limbo::sys::hex(&sha2::Sha256::digest(&other)), "other_len": other.len()});
                eqv(&mut d, &what, &got, o);
            }
            "trace_line" => eqv(&mut d, &what, &json!(trace::trace_line(s(i).as_bytes())), o),
            "build" => {
                let (h, opts, dd) = (host(&i["host"]), options(&i["options"]), dirs(&i["dirs"]));
                let r = sandbox::build(&opts, &h, &dd);
                let mut got = sandbox_json(&r);
                if let (Ok(mut sb), true) = (r, o.get("set_chdir").is_some()) {
                    sb.set_chdir("/mnt/data/x");
                    got["set_chdir"] = json!(sb.args);
                    got["chdir_after"] = json!(sb.chdir);
                    got["with_arch"] = json!(sb.with_env("WINEARCH", "win32"));
                    got["with_debug"] = json!(sb.with_env("WINEDEBUG", trace::TRACE_CHANNELS));
                    let a = [r#"x"; rm -rf ~; echo ""#, "$(id)", ""].map(String::from);
                    got["command"] = json!(sb.command(&run::script(&run::body_run()), &a));
                }
                eqv(&mut d, &what, &got, o);
            }
            "scripts" => {
                let got = json!({"run": run::script(&run::body_run()), "create": run::script(&run::body_create()),
                    "windows": run::script(&run::body_windows()), "trace_channels": trace::TRACE_CHANNELS, "trace_limit": trace::TRACE_LIMIT});
                eqv(&mut d, &what, &got, o);
            }
            "quote" => d.eq(&what, &run::shell_quote(&s(i)), &s(o)),
            "test_host" => test_host = host(o),
            "dry_run" => {
                let rhome = format!("{root}/home");
                let rdirs = Dirs::default_dirs(&|_| String::new(), &rhome, &format!("{rhome}/.local/state/limbo"));
                let prefix = s(&i["prefix"]);
                let cwd = s(&i["cwd"]).replace("{R}", &root);
                let mut opts = wine::merge(&prefix, None, &flags(&i["flags"], &root), &cwd, &rhome).unwrap();
                opts.prefix = prefix;
                let mut h = test_host.clone();
                h.home = rhome.clone();
                let r = run::Run {
                    options: opts,
                    host: h,
                    dirs: rdirs,
                    program: s(&i["program"]).replace("{R}", &root),
                    args: ["/x", "it's", ""].map(String::from).to_vec(),
                    cwd,
                    via: String::new(),
                    parent: vec![],
                    profile: String::new(),
                    profile_sha: String::new(),
                    log: None,
                    stop_grace: std::time::Duration::ZERO,
                    log_err: &no_log,
                };
                let mut out = Vec::new();
                let e = r.dry_run(&mut out).err().unwrap_or_default();
                let got = json!({"out": String::from_utf8(out).unwrap(), "error": e, "program_file": r.program_file()});
                eqv(&mut d, &what, &unroot(got, &root), o);
            }
            "record" => {
                let t = |v: &Value| limbo::gotime::parse_go_rfc3339(&s(v)).unwrap();
                let a = &i["allowed"];
                let rec = Record {
                    id: s(&i["id"]),
                    prefix: s(&i["prefix"]),
                    via: s(&i["via"]),
                    parent: s(&i["parent"]),
                    profile: s(&i["profile"]),
                    profile_sha256: s(&i["profile_sha256"]),
                    program: s(&i["program"]),
                    args: strs(&i["args"]),
                    program_path: s(&i["program_path"]),
                    program_sha256: s(&i["program_sha256"]),
                    program_size: i["program_size"].as_i64().unwrap(),
                    cwd: s(&i["cwd"]),
                    arch: s(&i["arch"]),
                    windows: s(&i["windows"]),
                    started: t(&i["started"]),
                    ended: i.get("ended").map(t),
                    status: s(&i["status"]),
                    exit_code: i.get("exit_code").map(|x| x.as_i64().unwrap()),
                    stopped: s(&i["stopped"]),
                    allowed: Allowed {
                        network: s(&a["network"]),
                        gpu: a["gpu"].as_bool().unwrap(),
                        display: strs(&a["display"]),
                        audio: s(&a["audio"]),
                        shares: a["shares"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|x| RecordShare {
                                path: s(&x["path"]),
                                source: s(&x["source"]),
                                writable: x["writable"].as_bool().unwrap(),
                            })
                            .collect(),
                        env: strs(&a["env"]),
                    },
                    trace: i.get("trace").map(|x| Trace {
                        file: s(&x["file"]),
                        channels: s(&x["channels"]),
                        bytes: x["bytes"].as_i64().unwrap(),
                        limit: x["limit"].as_i64().unwrap(),
                        truncated: x["truncated"].as_bool().unwrap(),
                    }),
                };
                d.eq(&what, &rec.to_json(), &s(o));
            }
            "prefix_record" => {
                let r = prefix::PrefixRecord {
                    arch: s(&i["arch"]),
                    windows: s(&i["windows"]),
                    updated: limbo::gotime::parse_go_rfc3339(&s(&i["updated"])).unwrap(),
                };
                d.eq(&what, &r.to_json(), &s(o));
            }
            "read_prefix_record" => {
                let p = format!("{root}/runs/rec.json");
                std::fs::write(&p, s(i)).unwrap();
                let r = prefix::read_prefix_record(&p);
                let ok = r.is_some();
                let r = r.unwrap_or_default();
                let got = json!({"ok": ok, "arch": r.arch, "windows": r.windows, "updated": r.updated.rfc3339_nano()});
                eqv(&mut d, &what, &got, o);
            }
            "prefix_arch" => {
                let dir = format!("{root}/runs/reg");
                std::fs::create_dir_all(&dir).unwrap();
                let body = format!("{}{}", "y".repeat(i["pad"].as_u64().unwrap() as usize), s(&i["body"]));
                std::fs::write(format!("{dir}/system.reg"), body).unwrap();
                d.eq(&what, &prefix::prefix_arch(&dir), &s(o));
            }
            "clean" => {
                let b = unhex(&s(i));
                let mut got = serde_json::Map::new();
                for n in [200, 64, 1, 0, 300, 512] {
                    got.insert(n.to_string(), json!(record::clean(&b, n)));
                }
                eqv(&mut d, &what, &Value::Object(got), o);
            }
            "path_list" => {
                let l: Vec<Vec<u8>> = strs(i).iter().map(|h| unhex(h)).collect();
                let refs: Vec<&[u8]> = l.iter().map(|x| x.as_slice()).collect();
                d.eq(&what, &record::path_list(&refs), &s(o));
            }
            "x11_display" => {
                let r = probe::x11_display(&s(i));
                eqv(&mut d, &what, &json!({"n": r.unwrap_or(0), "ok": r.is_some()}), o);
            }
            "nvidia_node" => eqv(&mut d, &what, &json!(probe::nvidia_node(&s(i))), o),
            "library_paths" => {
                let v = limbo::gojson::parse(s(i).as_bytes()).unwrap();
                let mut l = probe::library_paths(&v);
                l.sort();
                let got = if l.is_empty() { Value::Null } else { json!(l) };
                eqv(&mut d, &what, &got, o);
            }
            "lock_busy" => {
                let ld = Dirs { root: format!("{root}/locks"), ..Dirs::default() };
                let name = s(&i["name"]);
                let p = ld.lock_file(&name);
                std::fs::write(&p, s(&i["body"])).unwrap();
                let holder = std::fs::OpenOptions::new().read(true).write(true).open(&p).unwrap();
                rustix::fs::flock(&holder, rustix::fs::FlockOperation::LockExclusive).unwrap();
                let got = prefix::lock_prefix(&ld, &name).err().unwrap_or_default();
                drop(holder);
                eqv(&mut d, &what, &unroot(json!(got), &root), o);
            }
            "ensure_dir" => {
                let got = err(prefix::ensure_dir(&s(i).replace("{R}", &root)));
                eqv(&mut d, &what, &unroot(json!(got), &root), o);
            }
            "prune_runs" => {
                let names = strs(&i["names"]);
                let keep = i["keep"].as_u64().unwrap() as usize;
                let dir = format!("{root}/runs/{keep} {}", names.len());
                for n in &names {
                    std::fs::create_dir_all(format!("{dir}/{n}")).unwrap();
                }
                std::fs::write(format!("{dir}/20261111T080000Z-file"), "").unwrap();
                record::prune_runs(&dir, keep);
                let left: Vec<String> = limbo::sys::read_dir_sorted(&dir).unwrap().into_iter().map(|(n, _)| n).collect();
                eqv(&mut d, &what, &json!(left), o);
            }
            other => panic!("unknown case {other}"),
        }
    }
    if !root.is_empty() {
        let _ = std::fs::remove_dir_all(&root);
    }
    d.done("wine");
}
