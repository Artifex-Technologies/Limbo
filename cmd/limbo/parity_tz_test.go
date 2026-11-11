package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/parity"
)

// tzZone is one local time type of a made-up TZif file.
type tzZone struct {
	off  int32
	dst  bool
	abbr byte // index into the abbreviations
}

// tzif writes a TZif file: version ('0' writes version 1 with 32-bit times), zones, transitions (times and zone
// indexes), the abbreviations, and the footer's POSIX TZ string (version 2 and 3 only).
func tzif(version byte, zones []tzZone, when []int64, idx []byte, abbrevs, extend string) []byte {
	var b bytes.Buffer
	w32 := func(v uint32) { _ = binary.Write(&b, binary.BigEndian, v) }
	header := func(v byte, n [6]int) {
		b.WriteString("TZif")
		b.WriteByte(v)
		b.Write(make([]byte, 15))
		for _, x := range n {
			w32(uint32(x))
		}
	}
	body := func(size int) {
		for _, t := range when {
			if size == 4 {
				w32(uint32(int32(t)))
			} else {
				_ = binary.Write(&b, binary.BigEndian, uint64(t))
			}
		}
		b.Write(idx)
		for _, z := range zones {
			w32(uint32(z.off))
			if z.dst {
				b.WriteByte(1)
			} else {
				b.WriteByte(0)
			}
			b.WriteByte(z.abbr)
		}
		b.WriteString(abbrevs)
	}
	n := [6]int{0, 0, 0, len(when), len(zones), len(abbrevs)}
	if version == '0' {
		header(0, n)
		body(4)
		return b.Bytes()
	}
	header(version, [6]int{})
	header(version, n)
	body(8)
	b.WriteString("\n" + extend + "\n")
	return b.Bytes()
}

// TestParityTZ: Go's local time zone machinery as `limbo image list` uses it (a time shown in time.Local): TZif files
// read by LoadLocationFromTZData (made up here, so the fixture does not depend on this computer's tzdata) and times
// looked up in them, the POSIX TZ footer included. The choice of the file ($TZ, /etc/localtime) is compared by the CLI
// differential run.
func TestParityTZ(t *testing.T) {
	var cases []parity.Case
	dstZone := []tzZone{{-21036, false, 0}, {-18000, true, 4}, {-21600, false, 8}, {-18000, true, 12}}
	abbr := "LMT\x00CDT\x00CST\x00CWT\x00"
	tx := []int64{-2717643600, -1633273200, -1615132800, -880210800, -769395600, 1710061200, 1730620800}
	ix := []byte{2, 1, 2, 3, 2, 1, 2}
	files := map[string][]byte{
		"dst zone v2":       tzif('2', dstZone, tx, ix, abbr, "CST6CDT,M3.2.0,M11.1.0"),
		"dst zone v3":       tzif('3', dstZone, tx, ix, abbr, "CST6CDT,M3.2.0,M11.1.0"),
		"dst zone v1":       tzif('0', dstZone, tx, ix, abbr, ""),
		"dst zone no rule":  tzif('2', dstZone, tx, ix, abbr, ""),
		"dst zone bad rule": tzif('2', dstZone, tx, ix, abbr, "CST6CDT,M3.2.0"),
		"first dst":         tzif('2', []tzZone{{3600, true, 0}, {0, false, 4}, {3600, true, 0}}, []int64{0, 100000}, []byte{0, 1}, "DST\x00STD\x00", ""),
		"all dst":           tzif('2', []tzZone{{3600, true, 0}}, []int64{0}, []byte{0}, "DST\x00", ""),
		"zone 0 unused":     tzif('2', []tzZone{{-3600, false, 0}, {7200, false, 4}}, []int64{0}, []byte{1}, "AAA\x00BBB\x00", ""),
		"no transitions":    tzif('2', []tzZone{{19800, false, 0}}, nil, nil, "IST\x00", "IST-5:30"),
		"no nul":            tzif('2', []tzZone{{0, false, 0}}, nil, nil, "UTC", ""),
		"not tzif":          []byte("TZf2" + string(make([]byte, 40))),
		"bad version":       append([]byte("TZifx"), make([]byte, 60)...),
		"short":             []byte("TZif2"),
		"no zones":          tzif('2', nil, nil, nil, "", ""),
		"zone index":        tzif('2', []tzZone{{0, false, 0}}, []int64{0}, []byte{3}, "UTC\x00", ""),
		"abbrev index":      tzif('2', []tzZone{{0, false, 9}}, nil, nil, "UTC\x00", ""),
		"cut":               tzif('2', dstZone, tx, ix, abbr, "CST6CDT,M3.2.0,M11.1.0")[:120],
	}
	noNL := tzif('2', dstZone, tx, ix, abbr, "CST6CDT,M3.2.0,M11.1.0")
	files["footer without its last newline"] = noNL[:len(noNL)-1]
	extends := []string{"EST5EDT,M3.2.0,M11.1.0", "<+0330>-3:30", "IST-5:30", "AEST-10AEDT,M10.1.0,M4.1.0/3", "CET-1CEST,M3.5.0,M10.5.0/3",
		"<-03>3<-02>,M3.5.0/-2,M10.5.0/-1", "XXX3YYY,J60/2,J300", "AAA3BBB,59,300/1:30:15", "EST5EDT", "EST5EDT4,M3.2.0/2:00:00,M11.1.0/2:00:00",
		"E5", "EST", "EST5EDT,M13.1.0,M11.1.0", "EST5EDT,M3.2.0", "<abc", "EST5EDT;M3.2.0,M11.1.0", "EST+5EDT-4,M3.2.0,M11.1.0",
		"WART4WARST,J1/0,J365/25", "NZST-12NZDT,M9.5.0,M4.1.0/3", "UTC0", "<+14>-14", "EST5EDT,M3.5.0,M11.5.0", "AAA-167", "AAA-168",
		"EST5EDT,M3.2.7,M11.1.0", "EST5EDT,0,365", "EST5EDT,J0,J365", "Ünï5Ãâ,M3.2.0,M11.1.0", "ESTx5"}
	for _, e := range extends {
		files["rule "+e] = tzif('2', []tzZone{{0, false, 0}}, nil, nil, "ZZZ\x00", e)
	}
	times := []int64{-1 << 40, -2717643601, -2717643600, -100000, -1, 0, 99999, 100000, 1000000000, 1710061199, 1710061200,
		1730620799, 1730620800, 1730620801, 1741510799, 1741510800, 1762156799, 1762156800, 1762843815, 1772000000, 1774749600,
		1774753200, 1792890000, 1800000000, 1900000000, 4102444800, 1 << 40}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := files[name]
		loc, err := time.LoadLocationFromTZData("x", data)
		out := map[string]any{"error": parity.Err(err)}
		if err == nil {
			var zones []map[string]any
			for _, sec := range times {
				t := time.Unix(sec, 0).In(loc)
				zn, off := t.Zone()
				zones = append(zones, map[string]any{"sec": sec, "name": zn, "offset": off, "dst": t.IsDST(),
					"local": t.Format("2006-01-02 15:04")})
			}
			out["zones"] = zones
		}
		cases = append(cases, parity.Case{Fn: "tzdata", In: map[string]any{"name": name, "data": fmt.Sprintf("%x", data)}, Out: out})
	}
	parity.Fixture(t, "tz", cases)
}
