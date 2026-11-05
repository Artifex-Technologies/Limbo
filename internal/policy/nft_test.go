package policy

import (
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

func guest(t *testing.T, network string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Parse([]byte(`{
 "name":"lab","os":"linux",
 "image":{"path":"/x.qcow2","sha256":"` + strings.Repeat("0", 64) + `"},
 "access":{"user":"analyst"},` + network + `
 "app":{"name":"A","exec":"a"}}`))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNFT(t *testing.T) {
	tests := []struct {
		name, network string
		must, mustNot []string
	}{
		{
			name: "default is none",
			must: []string{`iifname "lb-lab" goto blocked`, `iifname "lb-lab" goto hostblocked`, `oifname "lb-lab" drop`, "udp sport 68 udp dport 67 accept"},
			// No guest-initiated accept and no DNS to host when there is no network.
			mustNot: []string{`iifname "lb-lab" accept`, "dport 53"},
		},
		{
			name:    "internet-only blocks private ranges before accepting",
			network: `"network":{"mode":"internet-only"},`,
			must:    []string{"192.168.0.0/16", "fc00::/7", `iifname "lb-lab" accept`, "udp dport 53 accept", "udp sport 68 udp dport 67 accept"},
		},
		{
			name:    "allowlist",
			network: `"network":{"mode":"allowlist","allow":[{"addr":"203.0.113.0/24","port":443},{"addr":"2001:db8::1","port":53,"proto":"udp"}]},`,
			must:    []string{"ip daddr 203.0.113.0/24 tcp dport 443 accept", "ip6 daddr 2001:db8::1/128 udp dport 53 accept"},
			// No DNS to the host gateway in allowlist mode (exfiltration channel).
			mustNot: []string{`iifname "lb-lab" accept`, "ip daddr 10.213."},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := NFT(guest(t, tc.network))
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range tc.must {
				if !strings.Contains(out, s) {
					t.Errorf("missing %q in:\n%s", s, out)
				}
			}
			for _, s := range tc.mustNot {
				if strings.Contains(out, s) {
					t.Errorf("unexpected %q in:\n%s", s, out)
				}
			}
		})
	}
}

// The last guest-initiated rule must always be a drop (through the "blocked" chain, which logs and then drops): a bug
// that forgot a mode's rules must fail closed.
func TestForwardEndsInDrop(t *testing.T) {
	for _, n := range []string{"", `"network":{"mode":"internet-only"},`} {
		out, _ := NFT(guest(t, n))
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if got := strings.TrimSpace(lines[len(lines)-3]); got != `iifname "lb-lab" goto blocked` {
			t.Errorf("forward chain ends with %q", got)
		}
	}
}

func TestNFTReplaceIsAtomicScriptWithDenyAllRestrict(t *testing.T) {
	m := guest(t, `"network":{"mode":"internet-only"},`)
	r, err := NFTRestrict(m)
	if err != nil {
		t.Fatal(err)
	}
	// Declare, delete, recreate: nft applies the script as one transaction.
	want := "table inet limbo_lab\ndelete table inet limbo_lab\ntable inet limbo_lab {"
	if !strings.HasPrefix(r, want) {
		t.Fatalf("not a replace script:\n%s", r)
	}
	// Whatever the manifest asked for, restrict is deny-all: no guest-initiated
	// accept, no DNS to the host.
	for _, bad := range []string{`iifname "lb-lab" accept`, "dport 53"} {
		if strings.Contains(r, bad) {
			t.Errorf("restrict ruleset contains %q:\n%s", bad, r)
		}
	}
	rel, _ := NFTRelease(m)
	if !strings.Contains(rel, `iifname "lb-lab" accept`) {
		t.Errorf("release must restore the manifest's internet-only rules:\n%s", rel)
	}
	if m.Network.Mode != "internet-only" {
		t.Error("NFTRestrict must not modify the manifest it was given")
	}
}

// IPv6 a guest sends itself never leaves in internet-only mode (the one that otherwise accepts), and is dropped by the
// final rule in the others.
func TestIPv6FromAGuestIsDropped(t *testing.T) {
	out, err := NFT(guest(t, `"network":{"mode":"internet-only"},`))
	if err != nil {
		t.Fatal(err)
	}
	v6, acc := strings.Index(out, `iifname "lb-lab" meta nfproto ipv6 goto blocked`), strings.Index(out, `iifname "lb-lab" accept`)
	if v6 < 0 || acc < 0 || v6 > acc {
		t.Fatalf("IPv6 must be dropped before the accept:\n%s", out)
	}
	for _, mode := range []string{"", `"network":{"mode":"allowlist","allow":[{"addr":"203.0.113.1","port":443}]},`} {
		out, _ := NFT(guest(t, mode))
		if strings.Contains(out, `iifname "lb-lab" accept`) || !strings.HasSuffix(strings.TrimSpace(out[:strings.LastIndex(out, "}")]), "}") {
			t.Fatalf("unexpected accept:\n%s", out)
		}
	}
}

// What a guest is refused is logged to limbo serve's NFLOG group and then dropped; the drop never depends on the log.
func TestRefusalsAreLoggedThenDropped(t *testing.T) {
	for _, mode := range []string{"", `"network":{"mode":"internet-only"},`, `"network":{"mode":"allowlist","allow":[{"addr":"203.0.113.1","port":443}]},`} {
		out, err := NFT(guest(t, mode))
		if err != nil {
			t.Fatal(err)
		}
		for _, chain := range []string{"hostblocked", "blocked"} {
			i := strings.Index(out, "chain "+chain+" {")
			if i < 0 {
				t.Fatalf("no %s chain:\n%s", chain, out)
			}
			body := out[i : i+strings.Index(out[i:], "}")]
			lines := strings.Split(strings.TrimSpace(body), "\n")
			if strings.TrimSpace(lines[len(lines)-1]) != "drop" || !strings.Contains(body, "group 7213") || !strings.Contains(body, "limit rate") || !strings.Contains(body, "pkttype unicast") {
				t.Fatalf("%s must log (unicast, limited) then drop:\n%s", chain, body)
			}
		}
		if !strings.Contains(out, `prefix "limbo:lab:h"`) || !strings.Contains(out, `prefix "limbo:lab:d"`) {
			t.Fatalf("prefixes:\n%s", out)
		}
		// Guest-made traffic never reaches a bare drop without passing a log chain (bare drops are only for traffic to the guest).
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, `iifname "lb-lab"`) && strings.HasSuffix(strings.TrimSpace(line), " drop") {
				t.Fatalf("unlogged guest drop: %s", line)
			}
		}
	}
	out, _ := NFT(guest(t, `"network":{"mode":"internet-only"},`))
	if a, acc := strings.Index(out, `prefix "limbo:lab:a"`), strings.Index(out, `iifname "lb-lab" accept`); a < 0 || a > acc {
		t.Fatalf("a new allowed connection is logged before the accept:\n%s", out)
	}
}
