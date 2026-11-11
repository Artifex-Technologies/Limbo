//! testdata/parity/cliclient.json: the CLI's HTTP client against Go (cmd/limbo/parity_client_test.go): the request URL
//! "http://limbo"+path as http.NewRequest reads it, a Location resolved against it, and responses as http.ReadResponse
//! reads them, and a time in an answer as encoding/json reads it.

mod common;
use common::{fixture, s, Diffs};
use limbo::cli::client::{read_response, Body, Buf};
use limbo::cli::url;

fn st(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn client_pieces_match_go() {
    let mut d = Diffs::default();
    for c in fixture("cliclient") {
        let i = &c["in"];
        let o = &c["out"];
        match s(&c["fn"]).as_str() {
            "url" => {
                let p = s(i);
                let what = format!("url {p:?}");
                match url::parse(format!("http://limbo{p}").as_bytes()) {
                    Ok(u) => {
                        d.eq(&format!("err of {what}"), "", &s(&o["err"]));
                        d.eq(&format!("uri of {what}"), &st(&u.request_uri()), &s(&o["uri"]));
                        d.eq(&format!("string of {what}"), &st(&u.string()), &s(&o["string"]));
                        d.eq(&format!("host of {what}"), &st(&u.host), &s(&o["host"]));
                    }
                    Err(e) => d.eq(&format!("err of {what}"), &e.text(), &s(&o["err"])),
                }
            }
            "location" => {
                let (base, loc) = (s(&i["base"]), s(&i["loc"]));
                let what = format!("location {base:?} + {loc:?}");
                let b = url::parse(base.as_bytes()).unwrap();
                match b.join(loc.as_bytes()) {
                    Ok(u) => {
                        d.eq(&format!("err of {what}"), "", &s(&o["err"]));
                        d.eq(&format!("string of {what}"), &st(&u.string()), &s(&o["string"]));
                        d.eq(&format!("uri of {what}"), &st(&u.request_uri()), &s(&o["uri"]));
                        d.eq(&format!("host of {what}"), &st(&u.host), &s(&o["host"]));
                        d.eq(&format!("scheme of {what}"), &st(&u.scheme), &s(&o["scheme"]));
                        let user = u.user.as_ref();
                        d.eq(&format!("user of {what}"), &st(&user.map(|x| x.string()).unwrap_or_default()), &s(&o["user"]));
                        d.eq(
                            &format!("username of {what}"),
                            &st(&user.map(|x| x.username.clone()).unwrap_or_default()),
                            &s(&o["username"]),
                        );
                        let pw = user.is_some_and(|x| x.password.is_some());
                        d.eq(&format!("password set of {what}"), &pw.to_string(), &o["password_set"].to_string());
                    }
                    Err(e) => d.eq(&format!("err of {what}"), &e.text(), &s(&o["err"])),
                }
            }
            "response" => {
                let raw = s(i);
                let what = format!("response {raw:?}");
                let mut b = Buf::new(raw.as_bytes(), None);
                match read_response(&mut b) {
                    Ok((h, framing)) => {
                        d.eq(&format!("err of {what}"), "", &s(&o["err"]));
                        d.eq(&format!("status of {what}"), &h.status, &s(&o["status"]));
                        d.eq(&format!("code of {what}"), &h.code.to_string(), &o["code"].to_string());
                        d.eq(&format!("location of {what}"), &h.get_str("Location"), &s(&o["location"]));
                        d.eq(&format!("sha of {what}"), &h.get_str("X-Limbo-Sha256"), &s(&o["sha"]));
                        d.eq(&format!("scan of {what}"), &h.get_str("X-Limbo-Scan"), &s(&o["scan"]));
                        d.eq(&format!("long of {what}"), &h.get_str("X-Long"), &s(&o["long"]));
                        let (body, err) = Body::new(b, framing).read_all();
                        d.eq(&format!("body of {what}"), &st(&body), &s(&o["body"]));
                        d.eq(&format!("body error of {what}"), &err, &s(&o["body_err"]));
                    }
                    Err(e) => {
                        let text = match e {
                            limbo::cli::client::ReadErr::Other(t) => t,
                            other => format!("{other:?}"),
                        };
                        d.eq(&format!("err of {what}"), &text, &s(&o["err"]))
                    }
                }
            }
            "time" => {
                let doc = format!("\"{}\"", s(i));
                let what = format!("time {doc:?}");
                match limbo::gojson::unmarshal(doc.as_bytes(), limbo::gotime::Time::default(), "time.Time") {
                    Ok(t) => {
                        d.eq(&format!("err of {what}"), "", &s(&o["err"]));
                        d.eq(&format!("time of {what}"), &t.rfc3339_nano(), &s(&o["time"]));
                    }
                    Err(e) => d.eq(&format!("err of {what}"), &e.0, &s(&o["err"])),
                }
            }
            f => panic!("unknown fn {f}"),
        }
    }
    d.done("cliclient");
}
