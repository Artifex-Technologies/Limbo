// Package hostfw makes room for a guest's private bridge in the host's own firewall.
//
// Limbo's per-guest nftables table (package policy) hooks at priority -10 and only
// ever drops or accepts inside itself: an accept there ends that table, it does not
// override a drop in someone else's. So on a host whose firewall drops everything by
// default (UFW does: input and forward policy are drop) the guest's DHCP request never
// reaches dnsmasq, and the guest never gets an address. This found out by booting a real
// guest on Labyrinth OS, which ships UFW enabled.
//
// The fix is to let the bridge through the host firewall and leave the restricting to
// Limbo's own table, which runs first and whose drops are final. Opening the bridge
// therefore widens nothing: what a guest may do is still exactly what its manifest says.
package hostfw

import (
	"bufio"
	"os"
	"strings"
)

// UFWActive reports whether UFW is installed and switched on (`ENABLED=yes` in its config).
func UFWActive() bool {
	if _, err := os.Stat("/usr/bin/ufw"); err != nil {
		if _, err := os.Stat("/usr/sbin/ufw"); err != nil {
			return false
		}
	}
	return ufwEnabled("/etc/ufw/ufw.conf")
}

func ufwEnabled(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "ENABLED" {
			return strings.EqualFold(strings.Trim(strings.TrimSpace(v), `"'`), "yes")
		}
	}
	return false
}

// rules are what the bridge needs from the host: DHCP and DNS to the host's dnsmasq, and
// permission to be forwarded from (replies come back under the firewall's own
// established/related rule).
func rules(bridge string) [][]string {
	return [][]string{
		{"allow", "in", "on", bridge, "to", "any", "port", "67", "proto", "udp"},
		{"allow", "in", "on", bridge, "to", "any", "port", "53", "proto", "udp"},
		{"allow", "in", "on", bridge, "to", "any", "port", "53", "proto", "tcp"},
		{"route", "allow", "in", "on", bridge},
	}
}

// UFWOpen is the list of `ufw` argument lists that let the bridge through.
func UFWOpen(bridge string) [][]string {
	out := rules(bridge)
	for i := range out {
		out[i] = append(out[i], "comment", "limbo")
	}
	return out
}

// UFWClose is the list that takes them out again.
func UFWClose(bridge string) [][]string {
	out := rules(bridge)
	for i := range out {
		if out[i][0] == "route" {
			// a route rule is deleted as `ufw route delete ...`; `ufw delete route ...` is a syntax error
			// (found by running `limbo down` against a real UFW)
			out[i] = append([]string{"--force", "route", "delete"}, out[i][1:]...)
		} else {
			out[i] = append([]string{"--force", "delete"}, out[i]...)
		}
	}
	return out
}
