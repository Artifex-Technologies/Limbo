package hostfw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUFWEnabledReadsTheConfig(t *testing.T) {
	d := t.TempDir()
	for body, want := range map[string]bool{
		"# comment\nENABLED=yes\nLOGLEVEL=low\n": true,
		"ENABLED=no\n":                           false,
		"#ENABLED=yes\n":                         false,
		"ENABLED = \"YES\"\n":                    true,
		"":                                       false,
	} {
		p := filepath.Join(d, "ufw.conf")
		os.WriteFile(p, []byte(body), 0o644)
		if got := ufwEnabled(p); got != want {
			t.Errorf("%q: got %v, want %v", body, got, want)
		}
	}
	if ufwEnabled(filepath.Join(d, "missing")) {
		t.Error("a missing config is not an enabled firewall")
	}
}

func TestOpenAndCloseMatchRuleForRule(t *testing.T) {
	open, closeR := UFWOpen("lb-lab"), UFWClose("lb-lab")
	if len(open) != len(closeR) || len(open) == 0 {
		t.Fatalf("%v / %v", open, closeR)
	}
	for i := range open {
		if !strings.Contains(strings.Join(open[i], " "), "on lb-lab") {
			t.Errorf("rule is not tied to the bridge: %v", open[i])
		}
		// the close rule is the open rule (minus the comment) after `--force delete`
		want := strings.Join(open[i][:len(open[i])-2], " ")
		var got string
		if open[i][0] == "route" {
			// ufw spells it `ufw route delete allow in on BRIDGE`
			if strings.Join(closeR[i][:3], " ") != "--force route delete" {
				t.Errorf("a route rule is deleted with `route delete`: %v", closeR[i])
			}
			got = "route " + strings.Join(closeR[i][3:], " ")
		} else {
			if closeR[i][0] != "--force" || closeR[i][1] != "delete" {
				t.Errorf("%v", closeR[i])
			}
			got = strings.Join(closeR[i][2:], " ")
		}
		if got != want {
			t.Errorf("close %q does not undo open %q", got, want)
		}
	}
}
