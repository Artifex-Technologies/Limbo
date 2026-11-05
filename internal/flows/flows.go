// Package flows turns what guests' firewalls log into events for Heimdall (docs/EVENTS.md, "Guest network"):
// where each guest connects, what it was refused, and when its refusals look like probing.
//
// The guests' nftables tables (package policy) copy two things to one NFLOG group: the first packet of each new
// connection a guest is allowed to make ("a"), and each unicast packet it is refused ("d", or "h" when addressed to the
// host), both rate-limited in the kernel. limbo serve reads the group (listen_linux.go); nothing polls. This file is the
// part that does not touch the kernel: reading a packet's addresses, and deciding what is worth an event. Events are
// bounded per guest so a guest cannot flood the log Heimdall reads.
package flows

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Event kinds (additive to the contract in docs/EVENTS.md).
const (
	KindFlow    = "net.flow"    // first time a guest opened a connection to a destination (allowed)
	KindBlocked = "net.blocked" // first time a guest was refused a destination
	KindAnomaly = "net.anomaly" // a guest's refusals look like probing (see Reason*)
	KindCapped  = "net.capped"  // a guest reached its event budget; further flows are only counted
)

// Anomaly reasons.
const (
	ReasonHostProbe = "host_probe" // reached for a service on the host (anything but DNS)
	ReasonLANProbe  = "lan_probe"  // reached for the LAN, other guests or other private ranges
	ReasonScan      = "scan"       // many distinct refused destinations in a short time
	ReasonIPv6      = "ipv6"       // tried to send IPv6 off its link (it has none)
)

// Verdict letters in the log prefix (package policy).
const (
	VerdictAllowed = "a"
	VerdictDropped = "d"
	VerdictHost    = "h"
)

// Packet is one logged packet, reduced to what an event needs.
type Packet struct {
	Guest   string
	Verdict string // a, d or h
	Proto   string // tcp, udp, icmp, icmpv6, or the protocol number
	Dst     netip.Addr
	DPort   int // 0 when the protocol has no ports
	ICMP    int // ICMP type, -1 if not ICMP
}

// ParsePrefix reads "limbo:<guest>:<verdict>" (a trailing space is allowed).
func ParsePrefix(p string) (guest, verdict string, ok bool) {
	p = strings.TrimRight(p, " \x00")
	parts := strings.Split(p, ":")
	if len(parts) != 3 || parts[0] != "limbo" || !guestOK(parts[1]) {
		return "", "", false
	}
	switch parts[2] {
	case VerdictAllowed, VerdictDropped, VerdictHost:
		return parts[1], parts[2], true
	}
	return "", "", false
}

func guestOK(n string) bool {
	if len(n) == 0 || len(n) > 12 || n[0] < 'a' || n[0] > 'z' {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// ParseIP reads the destination, protocol and port from the start of an IPv4 or IPv6 packet.
func ParseIP(b []byte) (proto string, dst netip.Addr, dport, icmp int, err error) {
	icmp = -1
	if len(b) < 1 {
		return "", dst, 0, icmp, fmt.Errorf("flows: empty packet")
	}
	var next byte
	var rest []byte
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		if len(b) < 20 || ihl < 20 || len(b) < ihl {
			return "", dst, 0, icmp, fmt.Errorf("flows: short IPv4 header")
		}
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		next = b[9]
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 { // a later fragment: no transport header
			return protoName(next), dst, 0, icmp, nil
		}
		rest = b[ihl:]
	case 6:
		if len(b) < 40 {
			return "", dst, 0, icmp, fmt.Errorf("flows: short IPv6 header")
		}
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		next = b[6]
		rest = b[40:]
		// Skip the common extension headers (hop-by-hop, routing, destination options) to reach the transport header.
		for i := 0; i < 4 && (next == 0 || next == 43 || next == 60) && len(rest) >= 8; i++ {
			l := (int(rest[1]) + 1) * 8
			if len(rest) < l {
				break
			}
			next, rest = rest[0], rest[l:]
		}
	default:
		return "", dst, 0, icmp, fmt.Errorf("flows: not an IP packet")
	}
	proto = protoName(next)
	switch next {
	case 6, 17:
		if len(rest) >= 4 {
			dport = int(binary.BigEndian.Uint16(rest[2:4]))
		}
	case 1, 58:
		if len(rest) >= 1 {
			icmp = int(rest[0])
		}
	}
	return proto, dst, dport, icmp, nil
}

func protoName(n byte) string {
	switch n {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	}
	return fmt.Sprint(n)
}

// Emitter writes the audit log.
type Emitter interface {
	Emit(kind, guest string, detail map[string]string) error
}

// Limits: per guest, so one guest cannot drown the log.
const (
	maxKeysPerGuest = 256              // distinct flows/refusals reported per guest; then net.capped, then counting only
	maxGuests       = 128              // guests remembered at once (oldest forgotten first)
	scanWindow      = time.Minute      // ...
	scanThreshold   = 20               // distinct refused destinations within scanWindow make a "scan"
	anomalyQuiet    = 10 * time.Minute // one anomaly event per guest and reason in this time
)

type guestState struct {
	seen       map[string]bool
	capped     bool
	suppressed int
	recent     []time.Time // times of new distinct refusals, for the scan rule
	lastAnom   map[string]time.Time
	anomCount  map[string]int
	touched    time.Time
}

// Aggregator decides which packets become events.
type Aggregator struct {
	Events Emitter
	Now    func() time.Time
	// Gateway returns the guest's gateway address (its host side), so DNS to it is told apart from probing the host.
	Gateway func(guest string) (netip.Addr, bool)

	mu     sync.Mutex
	guests map[string]*guestState
}

func (a *Aggregator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Aggregator) state(g string) *guestState {
	if a.guests == nil {
		a.guests = map[string]*guestState{}
	}
	st := a.guests[g]
	if st == nil {
		if len(a.guests) >= maxGuests {
			var oldest string
			var t time.Time
			for n, s := range a.guests {
				if oldest == "" || s.touched.Before(t) {
					oldest, t = n, s.touched
				}
			}
			delete(a.guests, oldest)
		}
		st = &guestState{seen: map[string]bool{}, lastAnom: map[string]time.Time{}, anomCount: map[string]int{}}
		a.guests[g] = st
	}
	st.touched = a.now()
	return st
}

// Forget drops what is remembered about a guest (it was torn down; a new guest may reuse the name).
func (a *Aggregator) Forget(guest string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.guests, guest)
}

// Scope says where a destination is.
func Scope(dst netip.Addr) string {
	switch {
	case dst.Is6() && !dst.Is4In6():
		return "ipv6"
	case dst.IsLoopback():
		return "loopback"
	case dst.IsPrivate() || dst.IsLinkLocalUnicast() || inCGNAT(dst):
		return "lan"
	case dst.IsMulticast() || dst.IsUnspecified():
		return "other"
	}
	return "internet"
}

func inCGNAT(a netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(a.Unmap())
}

// Handle turns one packet into zero or more events.
func (a *Aggregator) Handle(p Packet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.state(p.Guest)
	scope := Scope(p.Dst)
	if p.Verdict == VerdictHost {
		scope = "host"
	}
	kind := KindBlocked
	verdict := "dropped"
	if p.Verdict == VerdictAllowed {
		kind, verdict = KindFlow, "allowed"
	}
	key := p.Verdict + "|" + p.Proto + "|" + p.Dst.String() + "|" + fmt.Sprint(p.DPort)
	fresh := !st.seen[key]
	if fresh {
		if len(st.seen) >= maxKeysPerGuest {
			if !st.capped {
				st.capped = true
				a.emit(KindCapped, p.Guest, map[string]string{"limit": fmt.Sprint(maxKeysPerGuest)})
			}
			st.suppressed++
		} else {
			st.seen[key] = true
			d := map[string]string{"proto": p.Proto, "dst": p.Dst.String(), "verdict": verdict, "scope": scope}
			if p.DPort > 0 {
				d["dport"] = fmt.Sprint(p.DPort)
			}
			if p.ICMP >= 0 {
				d["icmp_type"] = fmt.Sprint(p.ICMP)
			}
			a.emit(kind, p.Guest, d)
		}
	}
	if p.Verdict == VerdictAllowed {
		return
	}
	// Refused: is it probing?
	switch {
	case scope == "host":
		if gw, ok := a.gateway(p.Guest); ok && p.Dst == gw && p.DPort == 53 {
			break // a resolver asking the gateway for DNS where it gets none: refused, not probing
		}
		if p.Proto == "tcp" || p.Proto == "udp" {
			a.anomaly(st, p, ReasonHostProbe)
		}
	case scope == "lan" || scope == "loopback":
		a.anomaly(st, p, ReasonLANProbe)
	case scope == "ipv6":
		if !p.Dst.IsLinkLocalUnicast() && !p.Dst.IsLinkLocalMulticast() && !p.Dst.IsInterfaceLocalMulticast() {
			a.anomaly(st, p, ReasonIPv6)
		}
	}
	if fresh {
		now := a.now()
		keep := st.recent[:0]
		for _, t := range st.recent {
			if now.Sub(t) < scanWindow {
				keep = append(keep, t)
			}
		}
		st.recent = append(keep, now)
		if len(st.recent) >= scanThreshold {
			a.anomaly(st, p, ReasonScan)
			st.recent = st.recent[:0]
		}
	}
}

func (a *Aggregator) gateway(g string) (netip.Addr, bool) {
	if a.Gateway == nil {
		return netip.Addr{}, false
	}
	return a.Gateway(g)
}

// anomaly reports once per guest and reason per quiet period, with how many times it happened meanwhile.
func (a *Aggregator) anomaly(st *guestState, p Packet, reason string) {
	st.anomCount[reason]++
	now := a.now()
	if last, ok := st.lastAnom[reason]; ok && now.Sub(last) < anomalyQuiet {
		return
	}
	st.lastAnom[reason] = now
	d := map[string]string{"reason": reason, "proto": p.Proto, "dst": p.Dst.String(), "count": fmt.Sprint(st.anomCount[reason])}
	if p.DPort > 0 {
		d["dport"] = fmt.Sprint(p.DPort)
	}
	if reason == ReasonScan {
		d["window_seconds"] = fmt.Sprint(int(scanWindow.Seconds()))
		d["threshold"] = fmt.Sprint(scanThreshold)
	}
	st.anomCount[reason] = 0
	a.emit(KindAnomaly, p.Guest, d)
}

func (a *Aggregator) emit(kind, guest string, d map[string]string) {
	if a.Events != nil {
		_ = a.Events.Emit(kind, guest, d)
	}
}
