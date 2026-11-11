package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/parity"
)

// FlagDef is one flag of a fixture's flag set: kind s (string), b (bool) or i (int).
type FlagDef struct {
	Name, Kind, Default, Usage string
}

// The flag sets of the socket-client commands, as their functions declare them (flag emulation for the Rust CLI).
var parityFlagSets = map[string][]FlagDef{
	"quarantine": {{"socket", "s", "/run/limbo/admin.sock", "admin socket (root only)"}, {"note", "s", "", "verdict: a note for the record"},
		{"reason", "s", "manually quarantined", "restrict: why"}, {"level", "s", "restrict", "restrict: restrict or isolate"}},
	"instance": {{"socket", "s", "/run/limbo/user.sock", "socket: admin.sock as root, user.sock otherwise"}, {"json", "b", "false", "print the server's JSON answer"},
		{"cpus", "i", "0", "set: processors"}, {"memory-mb", "i", "0", "set: memory in MiB"}, {"devices", "s", "\x00", "set: comma-separated\nlist"},
		{"delete-disk", "b", "false", "remove: also delete the guest's own disk"}, {"x", "b", "false", "one letter"}, {"n", "i", "7", "one letter int"}},
}

// TestParityCLI: the pieces the socket-client commands' output is made of (flag parsing and its messages,
// text/tabwriter, json.Indent, a RawMessage's compaction and lookup, %v of a decoded value, RFC3339, size).
func TestParityCLI(t *testing.T) {
	var cases []parity.Case
	r := rand.New(rand.NewSource(20261111))

	argSets := [][]string{
		{}, {"list"}, {"show", "q-1"}, {"verdict", "q-1", "safe", "--note", "a b"}, {"--note=x", "list", "-note", "y"},
		{"-h"}, {"--help"}, {"-nope"}, {"---x"}, {"-=x"}, {"-"}, {"--"}, {"--", "-x", "-x"}, {"list", "--", "--note", "z"},
		{"-note"}, {"-json=maybe"}, {"-json", "false"}, {"-json=0"}, {"-cpus", "0x1F"}, {"-cpus=1_000"}, {"-cpus", "_1"},
		{"-cpus", "1__0"}, {"-cpus", "9223372036854775808"}, {"-cpus", "-9223372036854775808"}, {"-cpus", "0b"}, {"-cpus", "0o17"},
		{"-cpus", "017"}, {"-cpus", "+5"}, {"-cpus", ""}, {"-cpus", "1e3"}, {"-cpus"}, {"-memory-mb", "99999999999999999999"},
		{"-devices", "", "set", "a"}, {"-x"}, {"-n", "3", "-x=true", "a", "-x=F"}, {"--delete-disk", "remove", "lab"},
		{"-socket", "/tmp/s", "-socket=/tmp/t", "list"}, {"a", "-b"}, {"-x=", "a"},
	}
	for _, name := range []string{"instance", "quarantine"} {
		defs := parityFlagSets[name]
		for _, args := range argSets {
			fs := flag.NewFlagSet(name, flag.ContinueOnError)
			var stderr bytes.Buffer
			fs.SetOutput(&stderr)
			vals := map[string]func() string{}
			for _, d := range defs {
				switch d.Kind {
				case "s":
					p := fs.String(d.Name, d.Default, d.Usage)
					vals[d.Name] = func() string { return *p }
				case "b":
					p := fs.Bool(d.Name, d.Default == "true", d.Usage)
					vals[d.Name] = func() string { return fmt.Sprint(*p) }
				case "i":
					var def int
					fmt.Sscan(d.Default, &def)
					p := fs.Int(d.Name, def, d.Usage)
					vals[d.Name] = func() string { return fmt.Sprint(*p) }
				}
			}
			pos, err := parseInterspersed(fs, args)
			got := map[string]string{}
			for k, f := range vals {
				got[k] = f()
			}
			cases = append(cases, parity.Case{Fn: "flags", In: map[string]any{"set": name, "defs": defs, "args": args},
				Out: map[string]any{"pos": pos, "err": parity.Err(err), "stderr": stderr.String(), "values": got}})
		}
	}

	cells := []string{"", "a", "ID", "q-0123456789ab", "héllo", "😀😀", "x y", "lab", "running (changes at next start)", "12.5 GiB", "\uFFFD"}
	// (no byte 0xff: tabwriter takes it as its escape character; cells come from decoded JSON, always valid UTF-8)
	var tabs []string
	for i := 0; i < 60; i++ {
		var b strings.Builder
		cols := 1 + r.Intn(5)
		for l := 0; l < 1+r.Intn(6); l++ {
			n := cols
			if r.Intn(4) == 0 {
				n = 1 + r.Intn(6)
			}
			for c := 0; c < n; c++ {
				if c > 0 {
					b.WriteString([]string{"\t", "\t", "\t", "\v"}[r.Intn(4)])
				}
				b.WriteString(cells[r.Intn(len(cells))])
			}
			b.WriteString([]string{"\n", "\n", "\n", "\f", ""}[r.Intn(5)])
		}
		tabs = append(tabs, b.String())
	}
	tabs = append(tabs, "ID\tGUEST\tSTATUS\n", "a\t", "a\tb", "\n\n", "", "x\ty\tz\nlong cell\t\t\n\tq\n", "a\tb\tc\nonly\nd\te\tf\n")
	for _, s := range tabs {
		var out bytes.Buffer
		tw := tabwriter.NewWriter(&out, 0, 4, 2, ' ', 0)
		fmt.Fprint(tw, s)
		tw.Flush()
		cases = append(cases, parity.Case{Fn: "tabwriter", In: s, Out: out.String()})
	}

	docs := []string{`{}`, `[]`, `{"a":1}`, ` {"a" : [1, 2, {"b":[]}], "c": {} } `, `[ "x\"y" , "é<&>" , null, true ]`, `"s"`, `12 `,
		`  1.0e5`, `{"a":"x"`, `nope`, ``, `{"a":1} {"b":2}`, "{\"k\":\"\xe2\x80\xa8\"}", `{"d":{"d":{"d":[[],[{}]]}}}`, "[1,\n2]\n\n",
		`{"status":{"version":"0.1.0"},"instances":[{"name":"lab"}]}`, `{"instances":1,"instances":[2]}`, `{"instances":"x"}`, `[1]`, `null`, `"str"`}
	for _, d := range docs {
		var ind bytes.Buffer
		ierr := json.Indent(&ind, []byte(d), "", "  ")
		comp, cerr := json.Marshal(json.RawMessage(d))
		var m map[string]json.RawMessage
		merr := json.Unmarshal([]byte(d), &m)
		raw, ok := m["instances"]
		cases = append(cases, parity.Case{Fn: "json", In: d, Out: map[string]any{
			"indent": ind.String(), "indent_err": ierr != nil, "compact": string(comp), "compact_err": cerr != nil,
			"member_err": parity.Err(merr), "member": string(raw), "member_found": ok}})
	}

	floats := []float64{0, 1, -1, 1.5, 100, 1e20, 1e21, 123456789012345678901234, 1e-4, 1e-5, 0.000123, 3.14159, 2.5e-7, -2e30, 1 << 53, math.MaxFloat64, 5e-324}
	for i := 0; i < 40; i++ {
		floats = append(floats, math.Ldexp(r.Float64(), r.Intn(160)-80))
	}
	for _, f := range floats {
		b, _ := json.Marshal(f)
		cases = append(cases, parity.Case{Fn: "float_v", In: string(b), Out: fmt.Sprint(f)})
	}
	sizes := []int64{0, 1023, 1024, 1<<20 - 1, 1 << 20, 1<<30 - 1, 1 << 30, 5*(1<<30) + (1 << 29), 1<<30 + 1<<28, -5000, 1 << 40, 107374182, 1288490188}
	for i := 0; i < 40; i++ {
		sizes = append(sizes, r.Int63n(1<<42))
	}
	for _, n := range sizes {
		cases = append(cases, parity.Case{Fn: "size", In: n, Out: size(n)})
	}
	for _, s := range []string{"2026-11-10T09:00:00Z", "2026-11-10T09:00:00.123456789Z", "2026-11-10T09:00:00.5+02:00", "2026-11-10T09:00:00-07:30", "0001-01-01T00:00:00Z"} {
		tm, _ := time.Parse(time.RFC3339Nano, s)
		cases = append(cases, parity.Case{Fn: "rfc3339", In: s, Out: tm.Format(time.RFC3339)})
	}
	parity.Fixture(t, "cli", cases)
}
