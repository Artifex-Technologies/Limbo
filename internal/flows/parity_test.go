package flows

import (
	"encoding/hex"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/parity"
)

type recEv struct {
	Kind   string            `json:"kind"`
	Guest  string            `json:"guest"`
	Detail map[string]string `json:"detail"`
}

type recorder2 struct{ evs []recEv }

func (r *recorder2) Emit(kind, guest string, d map[string]string) error {
	r.evs = append(r.evs, recEv{kind, guest, d})
	return nil
}

var parityDsts = []string{
	"1.1.1.1", "8.8.8.8", "203.0.113.9", "10.213.4.1", "10.213.4.2", "172.16.5.5", "172.31.255.1", "192.168.1.10",
	"100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.1.1", "224.0.0.251", "239.255.255.250", "0.0.0.0",
	"255.255.255.255", "2606:4700:4700::1111", "fe80::1", "ff02::1", "ff01::1", "::1", "fc00::5", "::",
	"::ffff:10.1.2.3", "::ffff:8.8.4.4", "::ffff:127.0.0.1", "::ffff:100.64.1.1", "::ffff:169.254.0.1", "2001:db8::42",
}

// TestParityFlows: the parsing and the aggregator's decisions on crafted and generated input.
func TestParityFlows(t *testing.T) {
	var cases []parity.Case
	for _, p := range []string{"limbo:lab:a", "limbo:lab:d ", "limbo:lab:h\x00", "limbo:lab:x", "limbo:Lab:a", "limbo:a:b:c", "lim:lab:a",
		"limbo:abcdefghijkl:d", "limbo:abcdefghijklm:d", "limbo::a", "limbo:1ab:a", "limbo:lab:a  \x00 ", ""} {
		g, v, ok := ParsePrefix(p)
		cases = append(cases, parity.Case{Fn: "ParsePrefix", In: p, Out: map[string]any{"guest": g, "verdict": v, "ok": ok}})
	}
	for _, d := range parityDsts {
		a := netip.MustParseAddr(d)
		cases = append(cases, parity.Case{Fn: "Scope", In: hex.EncodeToString(a.AsSlice()), Out: map[string]any{"scope": Scope(a), "string": a.String()}})
	}
	r := rand.New(rand.NewSource(7213))
	packets := [][]byte{nil, {0x45}, {0x60}, {0x10}}
	for _, d := range parityDsts {
		for _, proto := range []byte{6, 17, 1, 58, 47} {
			a := netip.MustParseAddr(d)
			if a.Is4() {
				packets = append(packets, ipv4(d, proto, uint16(r.Intn(65536))))
			} else {
				packets = append(packets, ipv6(d, proto, uint16(r.Intn(65536))))
			}
		}
	}
	// fragments, options, extension headers, short ones
	frag := ipv4("1.2.3.4", 6, 80)
	frag[6], frag[7] = 0x00, 0x10
	packets = append(packets, frag)
	opt := append([]byte{0x46}, make([]byte, 27)...)
	opt[9] = 17
	packets = append(packets, opt)
	ext := ipv6("2001:db8::1", 0, 0)
	ext = append(ext[:40], append([]byte{6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xbb}, make([]byte, 6)...)...)
	packets = append(packets, ext)
	for i := 0; i < 200; i++ {
		b := make([]byte, r.Intn(64))
		r.Read(b)
		if len(b) > 0 {
			b[0] = []byte{0x45, 0x46, 0x4f, 0x60, 0x61, 0x00}[r.Intn(6)]
		}
		packets = append(packets, b)
	}
	for _, b := range packets {
		proto, dst, dport, icmp, err := ParseIP(b)
		ds := ""
		if dst.IsValid() {
			ds = dst.String()
		}
		cases = append(cases, parity.Case{Fn: "ParseIP", In: hex.EncodeToString(b), Out: map[string]any{"proto": proto, "dst": ds, "dport": dport, "icmp": icmp, "error": parity.Err(err)}})
	}
	// netlink: whole kernel messages, several in one read, cut and damaged ones
	var bufs [][]byte
	for i := 0; i < 60; i++ {
		var b []byte
		for j := 0; j < 1+r.Intn(3); j++ {
			d := parityDsts[r.Intn(len(parityDsts))]
			pl := ipv4("9.9.9.9", 6, 443)
			if netip.MustParseAddr(d).Is4() {
				pl = ipv4(d, []byte{6, 17, 1}[r.Intn(3)], uint16(r.Intn(65536)))
			}
			b = append(b, nflogMsg([]string{"limbo:lab:a", "limbo:lab:d", "limbo:web-1:h", "other:x:a"}[r.Intn(4)], pl)...)
		}
		switch r.Intn(4) {
		case 1:
			b = b[:r.Intn(len(b))]
		case 2:
			b[r.Intn(len(b))] ^= byte(1 + r.Intn(255))
		}
		bufs = append(bufs, b)
	}
	for _, b := range bufs {
		var out []map[string]string
		for _, l := range parseMessages(b) {
			o := map[string]string{"prefix": l.prefix, "payload": hex.EncodeToString(l.payload)}
			if p, ok := decode(l); ok {
				o["guest"], o["verdict"], o["proto"], o["dst"] = p.Guest, p.Verdict, p.Proto, p.Dst.String()
				o["dport"], o["icmp"] = itoa(p.DPort), itoa(p.ICMP)
			}
			out = append(out, o)
		}
		cases = append(cases, parity.Case{Fn: "parseMessages", In: hex.EncodeToString(b), Out: out})
	}
	var reqs []string
	for _, b := range bindRequests(7213) {
		reqs = append(reqs, hex.EncodeToString(b))
	}
	cases = append(cases, parity.Case{Fn: "bindRequests", In: 7213, Out: reqs})
	for _, code := range []int32{0, -1, -16, -22} {
		b := make([]byte, 36)
		b[0] = 36
		b[4] = 2
		b[16], b[17], b[18], b[19] = byte(code), byte(code>>8), byte(code>>16), byte(code>>24)
		cases = append(cases, parity.Case{Fn: "ackError", In: hex.EncodeToString(b), Out: parity.Err(ackError(b))})
	}
	cases = append(cases, parity.Case{Fn: "ackError", In: "0400", Out: parity.Err(ackError([]byte{4, 0}))})
	cases = append(cases, parity.Case{Fn: "ackError", In: "08000000", Out: parity.Err(ackError([]byte{8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}[:4]))})

	// the aggregator: generated sequences with a clock, the gateway of guest "lab" known
	for seq := 0; seq < 30; seq++ {
		now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
		rec := &recorder2{}
		a := &Aggregator{Events: rec, Now: func() time.Time { return now }, Gateway: func(g string) (netip.Addr, bool) {
			if g == "lab" {
				return netip.MustParseAddr("10.213.4.1"), true
			}
			return netip.Addr{}, false
		}}
		var steps []map[string]any
		n := 50 + r.Intn(400)
		guests := []string{"lab", "web-1", "r0a1b2c3d"}
		if seq%7 == 6 {
			for i := 0; i < 140; i++ {
				guests = append(guests, "g"+itoa(i))
			}
		}
		for i := 0; i < n; i++ {
			now = now.Add(time.Duration(1+r.Intn(40000)) * time.Millisecond) // never two at one time: Go breaks a tie by map order
			if r.Intn(60) == 0 {
				g := guests[r.Intn(len(guests))]
				a.Forget(g)
				steps = append(steps, map[string]any{"forget": g, "at": now.UnixNano()})
				continue
			}
			d := parityDsts[r.Intn(len(parityDsts))]
			if seq%5 == 4 {
				d = netip.AddrFrom4([4]byte{198, 51, byte(r.Intn(4)), byte(r.Intn(256))}).String()
			}
			p := Packet{Guest: guests[r.Intn(len(guests))], Verdict: []string{"a", "d", "h"}[r.Intn(3)], Proto: []string{"tcp", "udp", "icmp", "icmpv6", "47"}[r.Intn(5)],
				Dst: netip.MustParseAddr(d), DPort: []int{0, 22, 53, 80, 443, 8000, r.Intn(65536)}[r.Intn(7)], ICMP: []int{-1, -1, 0, 8, 135}[r.Intn(5)]}
			a.Handle(p)
			steps = append(steps, map[string]any{"guest": p.Guest, "verdict": p.Verdict, "proto": p.Proto, "dst": hex.EncodeToString(p.Dst.AsSlice()), "dport": p.DPort, "icmp": p.ICMP, "at": now.UnixNano()})
		}
		cases = append(cases, parity.Case{Fn: "Aggregator", In: steps, Out: rec.evs})
	}
	parity.Fixture(t, "flows", cases)
}

func itoa(n int) string {
	if n < 0 {
		return "-" + itoa(-n)
	}
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}
