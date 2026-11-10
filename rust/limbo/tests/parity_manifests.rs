//! testdata/parity/manifests.json: manifest parsing, the libvirt XML, the firewall rules, the seed and the UFW rules,
//! as the Go code makes them.

mod common;
use common::{fixture, s, Diffs};
use limbo::{gojson, hostfw, manifest, policy, provision, virt};

fn errtext<T>(r: &Result<T, String>) -> String {
    match r {
        Ok(_) => String::new(),
        Err(e) => e.clone(),
    }
}

#[test]
fn manifests_virt_policy_provision_match_go() {
    let mut d = Diffs::default();
    for c in fixture("manifests") {
        match c["fn"].as_str().unwrap_or("") {
            "manifest.Parse" => {
                let doc = s(&c["in"]);
                let r = manifest::parse(doc.as_bytes());
                d.eq(&format!("parse error of {doc}"), &errtext(&r), &s(&c["out"]["error"]));
                if let Ok(m) = &r {
                    d.eq(&format!("parsed {doc}"), &gojson::indent(&m.json(), "  "), &s(&c["out"]["manifest"]));
                }
            }
            "derived" => {
                let doc = s(&c["in"]["manifest"]);
                let mut m = manifest::parse(doc.as_bytes()).expect("parsed in Go");
                m.subnet = c["in"]["subnet"].as_i64().unwrap_or(0);
                let o = &c["out"];
                let dom = virt::domain_xml(&m, &format!("/var/lib/limbo/state/{}", virt::disk_name(&m)));
                d.eq(&format!("domain {doc}"), &dom.clone().unwrap_or_default(), &s(&o["domain"]));
                d.eq("domain error", &errtext(&dom), &s(&o["domain_error"]));
                d.eq(&format!("network {doc}"), &virt::network_xml(&m), &s(&o["network"]));
                let a = virt::addr(&m);
                d.eq("gateway", &virt::ip4(a.gateway), &s(&o["gateway"]));
                d.eq("guest", &virt::ip4(a.guest), &s(&o["guest"]));
                d.eq("mac", &a.mac, &s(&o["mac"]));
                let n = policy::nft(&m);
                d.eq(&format!("nft {doc}"), &n.clone().unwrap_or_default(), &s(&o["nft"]));
                d.eq("nft error", &errtext(&n), &s(&o["nft_error"]));
                let r = policy::nft_restrict(&m);
                d.eq("restrict", &r.clone().unwrap_or_default(), &s(&o["restrict"]));
                d.eq("restrict error", &errtext(&r), &s(&o["restrict_error"]));
                let l = policy::nft_release(&m);
                d.eq("release", &l.clone().unwrap_or_default(), &s(&o["release"]));
                d.eq("release error", &errtext(&l), &s(&o["release_error"]));
                let seed = provision::build(&m);
                match &seed {
                    Ok(sd) => {
                        d.eq(&format!("user-data {doc}"), &sd.user_data, &s(&o["user_data"]));
                        d.eq("meta-data", &sd.meta_data, &s(&o["meta_data"]));
                        d.eq("seed error", "", &s(&o["seed_error"]));
                    }
                    Err(e) => d.eq(&format!("seed error {doc}"), e, &s(&o["seed_error"])),
                }
                d.eq("table", &policy::table_name(&m), &s(&o["table"]));
                let names = [virt::domain_name(&m), virt::network_name(&m), virt::bridge_name(&m), virt::tap_name(&m), virt::disk_name(&m)];
                let want: Vec<String> = o["names"].as_array().unwrap().iter().map(s).collect();
                d.eq("names", &names.join(","), &want.join(","));
            }
            "virt.DomainXML" => {
                let m = manifest::parse(s(&c["in"]).as_bytes()).expect("parsed in Go");
                d.eq("windows domain", &virt::domain_xml(&m, "/s/win.overlay.qcow2").unwrap_or_default(), &s(&c["out"]));
            }
            "hostfw" => {
                let b = s(&c["in"]);
                let j = |v: Vec<Vec<String>>| serde_json::to_string(&v).unwrap();
                d.eq("ufw open", &j(hostfw::ufw_open(&b)), &serde_json::to_string(&c["out"]["open"]).unwrap());
                d.eq("ufw close", &j(hostfw::ufw_close(&b)), &serde_json::to_string(&c["out"]["close"]).unwrap());
            }
            other => panic!("unknown case {other}"),
        }
    }
    d.done("manifests");
}
