package main

import (
	"strings"
	"testing"
)

func TestRootUsesTheDaemonsStateFolder(t *testing.T) {
	defer func(f func() int) { geteuid = f }(geteuid)
	t.Setenv("LIMBO_STATE_DIR", "")
	geteuid = func() int { return 0 }
	if d := defaultStateDir(); d != daemonStateDir {
		t.Fatalf("root default: %s", d)
	}
	if checkRootStateDir(daemonStateDir+"/", false) != nil {
		t.Fatal("the daemon's own folder refused")
	}
	if checkRootStateDir("/tmp/elsewhere", false) == nil {
		t.Fatal("root may not skip the holds by pointing elsewhere")
	}
	if checkRootStateDir("/tmp/elsewhere", true) != nil {
		t.Fatal("--i-know is the person's override")
	}
	geteuid = func() int { return 1000 }
	if checkRootStateDir("/tmp/elsewhere", false) != nil || defaultStateDir() == daemonStateDir {
		t.Fatal("an ordinary user keeps their own folder")
	}
}

func TestNetworkChangeReadsAllowEntries(t *testing.T) {
	n, err := networkChange("allowlist", "192.0.2.10:tcp:443, fd00::1:udp:53,10.0.0.0/24:tcp:22")
	if err != nil {
		t.Fatal(err)
	}
	list := n["allow"].([]map[string]any)
	if n["mode"] != "allowlist" || len(list) != 3 || list[1]["addr"] != "fd00::1" || list[1]["proto"] != "udp" || list[1]["port"] != 53 || list[2]["addr"] != "10.0.0.0/24" {
		t.Fatalf("%v", n)
	}
	for _, bad := range []string{"192.0.2.10", "192.0.2.10:443", "192.0.2.10:tcp:https"} {
		if _, err := networkChange("allowlist", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if n, _ := networkChange("none", ""); len(n["allow"].([]map[string]any)) != 0 {
		t.Fatal("no destinations for none")
	}
}

func TestWindowsPasswords(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p := newPassword()
		if len(p) != 20 || strings.ContainsAny(p, "0O1lI") {
			t.Fatalf("bad password %q", p)
		}
		if !strings.ContainsAny(p[:1], "abcdefghijkmnopqrstuvwxyz") || !strings.ContainsAny(p[1:2], "ABCDEFGHJKLMNPQRSTUVWXYZ") || !strings.ContainsAny(p[2:3], "23456789") {
			t.Fatalf("missing a kind of character: %q", p)
		}
		if seen[p] {
			t.Fatal("the same password twice")
		}
		seen[p] = true
	}
}
