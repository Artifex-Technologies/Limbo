package flows

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func ipv4(dst string, proto byte, dport uint16) []byte {
	b := make([]byte, 20+8)
	b[0] = 0x45
	b[9] = proto
	d := netip.MustParseAddr(dst).As4()
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[22:24], dport)
	if proto == 1 {
		b[20] = 8 // echo request
	}
	return b
}

func ipv6(dst string, proto byte, dport uint16) []byte {
	b := make([]byte, 40+8)
	b[0] = 0x60
	b[6] = proto
	d := netip.MustParseAddr(dst).As16()
	copy(b[24:40], d[:])
	binary.BigEndian.PutUint16(b[42:44], dport)
	return b
}

// nflogMsg builds what the kernel sends: nlmsghdr, nfgenmsg, then prefix and payload attributes.
func nflogMsg(prefix string, payload []byte) []byte {
	body := []byte{2, 0, 0x1c, 0x2d}
	body = append(body, attr(nfulaPrefix, append([]byte(prefix), 0))...)
	body = append(body, attr(nfulaPayload, payload)...)
	b := make([]byte, nlmsgHdrLen+len(body))
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:6], nfnlSubsysLog<<8|nfulnlMsgPkt)
	copy(b[nlmsgHdrLen:], body)
	return b
}

func TestParseKernelMessages(t *testing.T) {
	buf := append(nflogMsg("limbo:lab:d", ipv4("10.0.0.5", 6, 445)), nflogMsg("limbo:lab:a", ipv4("1.1.1.1", 17, 53))...)
	buf = append(buf, nflogMsg("someone-else", ipv4("1.1.1.1", 6, 1))...)
	buf = append(buf, nflogMsg("limbo:lab:a", ipv6("2001:db8::1", 6, 443))...)
	ls := parseMessages(buf)
	if len(ls) != 4 {
		t.Fatalf("%d messages", len(ls))
	}
	var got []Packet
	for _, l := range ls {
		if p, ok := decode(l); ok {
			got = append(got, p)
		}
	}
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	if got[0].Guest != "lab" || got[0].Verdict != "d" || got[0].Proto != "tcp" || got[0].Dst.String() != "10.0.0.5" || got[0].DPort != 445 {
		t.Fatalf("%+v", got[0])
	}
	if got[1].Proto != "udp" || got[1].DPort != 53 || got[2].Dst.String() != "2001:db8::1" || got[2].DPort != 443 {
		t.Fatalf("%+v", got[1:])
	}
	// Truncated or junk input never panics.
	for i := range buf {
		parseMessages(buf[:i])
	}
	for _, junk := range [][]byte{nil, {0x45}, {0x60, 1}, {0x45, 0, 0, 0, 0, 0, 0, 0, 0, 6}} {
		ParseIP(junk)
	}
}

func TestPrefixesMustBeLimbos(t *testing.T) {
	for _, p := range []string{"limbo:lab:x", "limbo:LAB:d", "limbo:lab", "limbo:a:b:d", "other:lab:d", "limbo:../x:d", "limbo:abcdefghijklm:d"} {
		if _, _, ok := ParsePrefix(p); ok {
			t.Errorf("%q accepted", p)
		}
	}
	if g, v, ok := ParsePrefix("limbo:r0123abcd:h "); !ok || g != "r0123abcd" || v != "h" {
		t.Fatal(g, v, ok)
	}
}

func TestBindRequestsAreWellFormed(t *testing.T) {
	reqs := bindRequests(7213)
	if len(reqs) != 2 {
		t.Fatal(len(reqs))
	}
	for _, r := range reqs {
		if int(binary.NativeEndian.Uint32(r[0:4])) != len(r) || binary.NativeEndian.Uint16(r[4:6]) != 0x0401 || r[18] != 0x1c || r[19] != 0x2d {
			t.Fatalf("% x", r[:20])
		}
	}
	ack := make([]byte, 36)
	binary.NativeEndian.PutUint32(ack[0:4], 36)
	binary.NativeEndian.PutUint16(ack[4:6], nlmsgError)
	if ackError(ack) != nil {
		t.Fatal("positive ack")
	}
	binary.NativeEndian.PutUint32(ack[16:20], uint32(0xffffffff-15)) // -16 EBUSY
	if ackError(ack) == nil {
		t.Fatal("error ack")
	}
}

type rec struct {
	evs []struct {
		kind, guest string
		d           map[string]string
	}
}

func (r *rec) Emit(kind, guest string, d map[string]string) error {
	r.evs = append(r.evs, struct {
		kind, guest string
		d           map[string]string
	}{kind, guest, d})
	return nil
}

func (r *rec) count(kind string) int {
	n := 0
	for _, e := range r.evs {
		if e.kind == kind {
			n++
		}
	}
	return n
}

func (r *rec) anomalies() map[string]int {
	out := map[string]int{}
	for _, e := range r.evs {
		if e.kind == KindAnomaly {
			out[e.d["reason"]]++
		}
	}
	return out
}

func agg() (*Aggregator, *rec, *time.Time) {
	r := &rec{}
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	a := &Aggregator{Events: r, Now: func() time.Time { return now }, Gateway: func(g string) (netip.Addr, bool) {
		return netip.MustParseAddr("10.213.4.1"), true
	}}
	return a, r, &now
}

func pkt(v, proto, dst string, port int) Packet {
	return Packet{Guest: "lab", Verdict: v, Proto: proto, Dst: netip.MustParseAddr(dst), DPort: port, ICMP: -1}
}

func TestFirstFlowOnlyAndRefusalsByScope(t *testing.T) {
	a, r, _ := agg()
	for i := 0; i < 5; i++ {
		a.Handle(pkt("a", "tcp", "1.1.1.1", 443))
	}
	if r.count(KindFlow) != 1 || r.evs[0].d["scope"] != "internet" || r.evs[0].d["verdict"] != "allowed" {
		t.Fatalf("%+v", r.evs)
	}
	a.Handle(pkt("d", "tcp", "172.16.5.5", 80))
	a.Handle(pkt("h", "tcp", "10.213.4.1", 8000))
	a.Handle(pkt("h", "udp", "10.213.4.1", 53)) // DNS where none is given: refused, not probing
	a.Handle(pkt("d", "tcp", "2606:4700:4700::1111", 443))
	a.Handle(pkt("d", "icmpv6", "fe80::1", 0)) // link-local chatter is not an IPv6 anomaly
	an := r.anomalies()
	if an[ReasonLANProbe] != 1 || an[ReasonHostProbe] != 1 || an[ReasonIPv6] != 1 || len(an) != 3 {
		t.Fatalf("%v", an)
	}
	if r.count(KindBlocked) != 5 {
		t.Fatalf("blocked %d", r.count(KindBlocked))
	}
}

func TestAnomaliesAreQuietForTenMinutesAndCountMeanwhile(t *testing.T) {
	a, r, now := agg()
	for port := 1; port <= 5; port++ {
		a.Handle(pkt("h", "tcp", "10.213.4.1", port))
	}
	if r.anomalies()[ReasonHostProbe] != 1 {
		t.Fatalf("%v", r.anomalies())
	}
	*now = now.Add(11 * time.Minute)
	a.Handle(pkt("h", "tcp", "10.213.4.1", 22))
	var last map[string]string
	for _, e := range r.evs {
		if e.kind == KindAnomaly {
			last = e.d
		}
	}
	if r.anomalies()[ReasonHostProbe] != 2 || last["count"] != "5" {
		t.Fatalf("%v %v", r.anomalies(), last)
	}
}

func TestScanAndBudget(t *testing.T) {
	a, r, _ := agg()
	for i := 0; i < scanThreshold; i++ {
		a.Handle(pkt("d", "tcp", "203.0.113.9", 1000+i)) // public, refused (allowlist mode): only the scan rule fires
	}
	if an := r.anomalies(); an[ReasonScan] != 1 || len(an) != 1 {
		t.Fatalf("%v", an)
	}
	for i := 0; i < 1000; i++ {
		a.Handle(pkt("a", "tcp", netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}).String(), 443))
	}
	if r.count(KindCapped) != 1 || r.count(KindFlow)+r.count(KindBlocked) != maxKeysPerGuest {
		t.Fatalf("capped %d flows %d blocked %d", r.count(KindCapped), r.count(KindFlow), r.count(KindBlocked))
	}
	a.Forget("lab")
	a.Handle(pkt("a", "tcp", "1.1.1.1", 443))
	if r.evs[len(r.evs)-1].kind != KindFlow {
		t.Fatal("a forgotten guest starts fresh")
	}
}

func TestGuestsRememberedAreBounded(t *testing.T) {
	a, _, now := agg()
	for i := 0; i < maxGuests+50; i++ {
		*now = now.Add(time.Second)
		p := pkt("a", "tcp", "1.1.1.1", 443)
		p.Guest = "g" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		a.Handle(p)
	}
	if len(a.guests) > maxGuests {
		t.Fatalf("%d guests remembered", len(a.guests))
	}
}
