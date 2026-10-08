package launch

import (
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

func m(os, extra string) *manifest.Manifest {
	mm, err := manifest.Parse([]byte(`{"name":"lab","os":"` + os + `",
 "image":{"path":"/x.qcow2","sha256":"` + strings.Repeat("0", 64) + `"},
 "access":{"user":"analyst"},` + extra + `
 "app":{"name":"Word","exec":"C:\\Program Files\\Word.exe"}}`))
	if err != nil {
		panic(err)
	}
	return mm
}

func TestLinuxUsesWaypipe(t *testing.T) {
	c, err := Build(m("linux", ""))
	if err != nil {
		t.Fatal(err)
	}
	if c.Args[0] != "waypipe" || c.PasswordPrompt {
		t.Fatalf("unexpected: %+v", c)
	}
	if !strings.HasPrefix(c.Args[len(c.Args)-2], "analyst@10.213.") {
		t.Fatalf("host arg wrong: %v", c.Args)
	}
}

func TestWindowsRemoteAppIsLockedDown(t *testing.T) {
	c, _ := Build(m("windows", ""))
	joined := " " + strings.Join(c.Args, " ") + " "
	for _, want := range []string{" /from-stdin ", " -clipboard ", " -drives ", " -sound ", " -microphone ", `/app:program:C:\Program Files\Word.exe,name:Word`} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, c.Args)
		}
	}
	if strings.Contains(joined, "/p:") || strings.Contains(joined, "home-drive") {
		t.Errorf("password or home drive on command line: %v", c.Args)
	}
	if !c.PasswordPrompt {
		t.Error("windows launch must take password on stdin")
	}
	c, _ = Build(m("windows", `"clipboard":"text",`))
	if !strings.Contains(strings.Join(c.Args, " "), "+clipboard") {
		t.Error("clipboard text not honoured")
	}
}
