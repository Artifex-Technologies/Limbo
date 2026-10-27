package runs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleExec is the fake executor plus the ability to carry a sample.
type sampleExec struct {
	*fakeExec
	gotSample []byte
	gotCmd    string
}

func (s *sampleExec) RunSample(_ context.Context, _, _, _, command string, sample []byte, _ int) (string, string, int, bool, error) {
	s.gotSample, s.gotCmd = sample, command
	return "triage output\n", "", 0, false, nil
}

// sealSample makes the test profile a sealed sample profile (no network, allow_sample) and gives the manager an inbox with a file.
func sealSample(t *testing.T, x *env, allow bool) string {
	t.Helper()
	p := filepath.Join(x.m.ProfileDir, x.prof+".json")
	raw, _ := os.ReadFile(p)
	s := strings.Replace(string(raw), `"network":{"mode":"allowlist","allow":[{"addr":"203.0.113.5","port":443}]}`, `"network":{"mode":"none"}`, 1)
	if allow {
		s = strings.Replace(s, `"max_seconds":30`, `"max_seconds":30,"allow_sample":true`, 1)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	x.m.SampleDir = t.TempDir()
	os.WriteFile(filepath.Join(x.m.SampleDir, "abc.sample"), []byte("\x7fELF hostile"), 0o600)
	return "abc.sample"
}

func TestSampleReachesASealedGuestAndIsAudited(t *testing.T) {
	x := setup(t, true)
	name := sealSample(t, x, true)
	se := &sampleExec{fakeExec: x.ex}
	x.m.Exec = se
	id, err := x.m.StartSample(context.Background(), x.prof, "limbo-decompile triage sample", name, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := wait(t, x.m, id)
	if r.Status != Done || !strings.Contains(r.Stdout, "triage output") || string(se.gotSample) != "\x7fELF hostile" || se.gotCmd != "limbo-decompile triage sample" {
		t.Fatalf("%+v %q", r, se.gotSample)
	}
	logged := false
	for _, e := range x.ev.list {
		logged = logged || strings.Contains(e, "sample_sha256")
	}
	if !logged {
		t.Fatal("the sample's hash must be in the audit log")
	}
}

func TestSamplesOnlyGoToSealedProfilesThatAllowThem(t *testing.T) {
	x := setup(t, true)
	name := sealSample(t, x, false)
	x.m.Exec = &sampleExec{fakeExec: x.ex}
	if _, err := x.m.StartSample(context.Background(), x.prof, "true", name, 0); err == nil {
		t.Fatal("a profile without allow_sample must refuse")
	}
	// allowed, but with a network: refused
	y := setup(t, true)
	p := filepath.Join(y.m.ProfileDir, y.prof+".json")
	raw, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(raw), `"max_seconds":30`, `"max_seconds":30,"allow_sample":true`, 1)), 0o644)
	y.m.SampleDir = t.TempDir()
	os.WriteFile(filepath.Join(y.m.SampleDir, "a.sample"), []byte("x"), 0o600)
	y.m.Exec = &sampleExec{fakeExec: y.ex}
	if _, err := y.m.StartSample(context.Background(), y.prof, "true", "a.sample", 0); err == nil {
		t.Fatal("a profile with a network must refuse samples")
	}
}

func TestSampleNamesStayInTheInbox(t *testing.T) {
	x := setup(t, true)
	sealSample(t, x, true)
	x.m.Exec = &sampleExec{fakeExec: x.ex}
	outside := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(outside, []byte("secret"), 0o600)
	os.Symlink(outside, filepath.Join(x.m.SampleDir, "link.sample"))
	for _, n := range []string{"../secret", "/etc/shadow", "link.sample", "", "missing.sample"} {
		if _, err := x.m.StartSample(context.Background(), x.prof, "true", n, 0); err == nil {
			t.Fatalf("%q must be refused", n)
		}
	}
}

func TestContainmentRefusesAndStopsAgentRunsButNotSamples(t *testing.T) {
	x := setup(t, true)
	contained := false
	x.m.Contained = func() bool { return contained }
	x.ex.block = make(chan struct{})
	id, err := x.m.Start(context.Background(), x.prof, "sleep 100", 0)
	if err != nil {
		t.Fatal(err)
	}
	contained = true
	if _, err := x.m.Start(context.Background(), x.prof, "true", 0); err == nil || !strings.Contains(err.Error(), "contained") {
		t.Fatalf("an agent run while contained must be refused: %v", err)
	}
	if n := x.m.StopAgentRuns(); n != 1 {
		t.Fatalf("stopped %d", n)
	}
	if r := wait(t, x.m, id); r.Status == Done && r.ExitCode != nil && *r.ExitCode == 0 && r.Error == "" {
		t.Fatalf("the running agent run must end, not finish normally: %+v", r)
	}
	// a sample run for Heimdall still works while Sarina is contained
	name := sealSample(t, x, true)
	x.ex.block = nil
	x.m.Exec = &sampleExec{fakeExec: x.ex}
	sid, err := x.m.StartSample(context.Background(), x.prof, "limbo-decompile triage sample", name, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := wait(t, x.m, sid); r.Status != Done {
		t.Fatalf("%+v", r)
	}
}

func TestSampleWrapStoresReadOnlyThenRuns(t *testing.T) {
	w := sampleWrap("limbo-decompile triage sample")
	i, j, k := strings.Index(w, `cat > "$HOME/sample/sample"`), strings.Index(w, `chmod 0400`), strings.Index(w, "limbo-decompile")
	if !(0 < i && i < j && j < k) || !strings.Contains(w, `LIMBO_SAMPLE_DIR="$HOME/sample"`) {
		t.Fatalf("wrong order: %s", w)
	}
}

// Agent runs at their limit leave the sample slot free: Sarina cannot starve Heimdall's analysis.
func TestAgentRunsCannotTakeTheSampleSlot(t *testing.T) {
	x := setup(t, true)
	name := sealSample(t, x, true)
	x.m.Exec = &sampleExec{fakeExec: x.ex}
	x.ex.block = make(chan struct{})
	var ids []string
	for i := 0; i < maxConcurrent; i++ {
		id, err := x.m.Start(context.Background(), x.prof, "true", 0)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	id, err := x.m.StartSample(context.Background(), x.prof, "true", name, 0)
	if err != nil {
		t.Fatalf("the sample was refused while agent runs were busy: %v", err)
	}
	if _, err := x.m.StartSample(context.Background(), x.prof, "true", name, 0); err == nil {
		t.Fatal("a second sample beyond its slot accepted")
	}
	close(x.ex.block)
	for _, i := range append(ids, id) {
		wait(t, x.m, i)
	}
}
