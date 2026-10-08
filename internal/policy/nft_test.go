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
			must: []string{`iifname "lb-lab" drop`, `oifname "lb-lab" drop`, "udp sport 68 udp dport 67 accept"},
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

// The last guest-initiated rule must always be a drop: a bug that forgot a
// mode's rules must fail closed.
func TestForwardEndsInDrop(t *testing.T) {
	for _, n := range []string{"", `"network":{"mode":"internet-only"},`} {
		out, _ := NFT(guest(t, n))
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if got := strings.TrimSpace(lines[len(lines)-3]); got != `iifname "lb-lab" drop` {
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
