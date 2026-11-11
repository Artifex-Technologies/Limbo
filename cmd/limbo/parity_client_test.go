package main

import (
	"bufio"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/parity"
)

// TestParityCLIClient: what the socket client (unixClient, doJSON, cli.do, cli.take) is made of, for the Rust client
// (rust/limbo/src/cli/client.rs): the request URL "http://limbo"+path as http.NewRequest parses it (its error, the
// request line's target, the URL as an error message writes it), a redirect's Location resolved against it, and a
// response as the transport reads it (status, headers, the body and its error).
func TestParityCLIClient(t *testing.T) {
	var cases []parity.Case
	r := rand.New(rand.NewSource(20261111))

	bits := []string{"a", "lab", "q-1", " ", "%", "%2", "%2F", "%2f", "%zz", "%25", "%3F", "%23", "%e9", "%C3%A9", "%00", "?", "#", "/",
		"..", ".", "é", "\x7f", "\n", "\t", "+", "@", ":", ";", "[", "]", "!", "*", "'", "(", ")", "~", "$", "&", "=", ",", "\"", "<", ">",
		"\\", "^", "`", "{", "|", "}", "😀", " ", "-", "_", "%%", "?#", "#?"}
	paths := []string{"/v1/status", "/v1/quarantine/", "/v1/instances/lab/start", "/v1/x?", "/v1/x?a=b?c", "/v1/x#", "/v1/x#a#b",
		"/v1/x#%zz", "/v1/x%zz#a", "/v1/a b/c", "/v1/%41", "/v1/a%2Fb", "/v1/..", "/v1/./x", "/v1/x?q=%zz", "/v1/x#%41", "/v1/x#a b"}
	for i := 0; i < 300; i++ {
		var b strings.Builder
		b.WriteString([]string{"/v1/quarantine/", "/v1/instances/", "/v1/exchange/", "/v1/licenses/"}[r.Intn(4)])
		for n := r.Intn(5); n >= 0; n-- {
			b.WriteString(bits[r.Intn(len(bits))])
		}
		if r.Intn(3) == 0 {
			b.WriteString("/start")
		}
		paths = append(paths, b.String())
	}
	var bases []*url.URL
	for _, p := range paths {
		req, err := http.NewRequest("GET", "http://limbo"+p, nil)
		out := map[string]any{"err": parity.Err(err)}
		if err == nil {
			out["uri"] = req.URL.RequestURI()
			out["string"] = req.URL.String()
			out["host"] = req.URL.Host
			if len(bases) < 40 {
				bases = append(bases, req.URL)
			}
		}
		cases = append(cases, parity.Case{Fn: "url", In: p, Out: out})
	}

	locs := []string{"/x", "x", "../y", "../../../../z", "./", ".", "..", "", "?q", "?", "#f", "#", "/a/./b/../c", "http://other/z",
		"HTTP://LIMBO/a", "//other/p", "ftp://x/", "http:///nohost", "%zz", "/a%zz", "http://[::1]:80/x", "http://[::1/x",
		"http://1.2.3.4:x/", "http://a:1:2/", "https://limbo/x", "a b", "/a%2Fb", " /x", "/x\t", "http://a b/", "http://u:p@h/x",
		"http://u@h/x", "http://u:p%zz@h/", "http://u:p q@h/", "mailto:x", "http:x", "/x?a#b", "/v1/quarantine/", "//", "///x",
		"http://limbo", "http://limbo?q", "http://[fe80::1%25eth0]/", "http://[1.2.3.4]/", "x:y/z", "/é?é#é", "/%41%2f", "*",
		"http://limbo:/x", "http://limbo:80/x", "../a/./", "a/..", "http://h%41/", "http://h%2f/", "http://<h>/", "/a//b", "#%zz", "?%zz"}
	for i, base := range bases {
		for j, loc := range locs {
			if (i+j)%3 != 0 && i > 3 {
				continue
			}
			u, err := base.Parse(loc)
			out := map[string]any{"err": parity.Err(err)}
			if err == nil {
				out["string"] = u.String()
				out["uri"] = u.RequestURI()
				out["host"] = u.Host
				out["scheme"] = u.Scheme
				out["user"] = u.User.String()
				out["username"] = u.User.Username()
				_, out["password_set"] = u.User.Password()
			}
			cases = append(cases, parity.Case{Fn: "location", In: map[string]string{"base": base.String(), "loc": loc}, Out: out})
		}
	}

	resps := []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}",
		"HTTP/1.1 200 OK\r\n\r\nclose-delimited body",
		"HTTP/1.0 200 OK\r\n\r\nold",
		"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"error\":\"absent\"}",
		"HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 404\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 404 \r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1  500  Odd  spacing \r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\nContent-Length: 2\n\nok",
		"HTTP/1.1 2000 OK\r\n\r\n",
		"HTTP/1.1 20 OK\r\n\r\n",
		"HTTP/1.1 +20 OK\r\n\r\n",
		"HTTP/1.1 -20 OK\r\n\r\n",
		"HTTP/1.1 abc OK\r\n\r\n",
		"HTTP/1.1\r\n\r\n",
		"garbage\r\n\r\n",
		"HTTP/2.0 200 OK\r\nContent-Length: 1\r\n\r\nx",
		"HTTP/1.2 200 OK\r\nContent-Length: 1\r\n\r\nx",
		"HTTP/10.1 200 OK\r\n\r\n",
		"HTTP/a.b 200 OK\r\n\r\n",
		"http/1.1 200 OK\r\n\r\n",
		"",
		"HTTP/1.1 200 OK\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length:  2 \r\n\r\nab",
		"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nab",
		"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\nab",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\nContent-Length: 1\r\n\r\n2\r\nab\r\n3;ext=1\r\ncde\r\n0\r\nTrailer: x\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabX\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nz\r\nab\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\nab\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\nab\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\r\nab\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2 \t\r\nab\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\nab\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\nX",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nab",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n",
		"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello",
		"HTTP/1.1 304 Not Modified\r\n\r\nhello",
		"HTTP/1.1 301 Moved Permanently\r\nLocation: /v1/x\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nlocation: /a\r\nx-limbo-sha256: abc\r\nX-Limbo-Scan: clean\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-Limbo-Sha256:abc\r\nX-Limbo-Sha256: def\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-Limbo-Sha256:  a b  \t\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-Long: a\r\n  b\r\n\tc\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\n continued\r\n\r\n",
		"HTTP/1.1 200 OK\r\nNo colon here\r\n\r\n",
		"HTTP/1.1 200 OK\r\nBad Key: x\r\n\r\n",
		"HTTP/1.1 200 OK\r\n: empty key\r\n\r\n",
		"HTTP/1.1 200 OK\r\nKey: a\x01b\r\n\r\n",
		"HTTP/1.1 200 OK\r\nKey: é\r\n\r\n",
		"HTTP/1.1 200 OK\r\nKey : x\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef",
		"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		"HTTP/1.1 200 OK\r\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\rContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 \xff\xfe\r\nContent-Length: 0\r\n\r\n",
	}
	for _, s := range resps {
		req, _ := http.NewRequest("GET", "http://limbo/v1/x", nil)
		resp, err := http.ReadResponse(bufio.NewReaderSize(strings.NewReader(s), 4096), req)
		out := map[string]any{"err": parity.Err(err)}
		if err == nil {
			body, berr := io.ReadAll(resp.Body)
			out["status"] = resp.Status
			out["code"] = resp.StatusCode
			out["location"] = resp.Header.Get("Location")
			out["sha"] = resp.Header.Get("X-Limbo-Sha256")
			out["scan"] = resp.Header.Get("X-Limbo-Scan")
			out["long"] = resp.Header.Get("X-Long")
			out["body"] = string(body)
			out["body_err"] = parity.Err(berr)
		}
		cases = append(cases, parity.Case{Fn: "response", In: s, Out: out})
	}
	// a time inside the answers, as Go 1.27's encoding/json reads it (time.Parse with the RFC 3339 layout, not the strict
	// reading of Go 1.20 to 1.26)
	for _, s := range []string{"2026-11-10T09:00:00Z", "2026-11-10T09:00:00.123456789123Z", "2026-11-10T09:00:00,5+02:00",
		"2026-11-10T9:00:00Z", "2026-11-10T09:00:00+24:00", "2026-11-10T09:00:00-01:60", "2026-11-10T09:00:00+25:00",
		"2026-11-10T09:00:00+01:61", "2026-13-01T00:00:00Z", "2026-00-01T00:00:00Z", "2026-02-29T00:00:00Z", "2024-02-29T00:00:00Z",
		"2026-02-30T00:00:00Z", "2026-11-00T00:00:00Z", "2026-11-1T00:00:00Z", "2026-11-10T24:00:00Z", "2026-11-10T23:60:00Z",
		"2026-11-10T23:59:60Z", "2026-11-10T09:00:00", "2026-11-10T09:00:00Zx", "2026-11-10 09:00:00Z", "2026-11-10T09:00:00.Z",
		"20a6-11-10T09:00:00Z", "2026-11-10T09:00:00+0100", "2026-11-10T09:00:00\u00e9", "2026-1-10T09:00:00Z", "", "yesterday",
		"0001-01-01T00:00:00Z", "9999-12-31T23:59:59.999999999-23:59", "2026-11-10T09:00:00x01:00", "2026-11-10T09:00:00+1:000",
		"2026-11-10T09:00:00+01:0x", "2026-11-10T09:00:00\\\"Z", "2026-11-10T09:00:00\tZ"} {
		var tm time.Time
		err := json.Unmarshal([]byte(`"`+s+`"`), &tm)
		out := map[string]any{"err": parity.Err(err)}
		if err == nil {
			out["time"] = tm.Format(time.RFC3339Nano)
			out["unix"] = tm.UnixNano()
		}
		cases = append(cases, parity.Case{Fn: "time", In: s, Out: out})
	}
	parity.Fixture(t, "cliclient", cases)
}
