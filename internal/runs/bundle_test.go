package runs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bundleExec is the fake executor plus the ability to carry a tar.
type bundleExec struct {
	*fakeExec
	gotBundle []byte
	gotCmd    string
}

func (b *bundleExec) RunBundle(_ context.Context, _, _, _, command string, bundle []byte, _ int) (string, string, int, bool, error) {
	b.gotBundle, b.gotCmd = bundle, command
	return "agent output\n", "", 0, false, nil
}

func allowBundles(t *testing.T, x *env) {
	t.Helper()
	p := filepath.Join(x.m.ProfileDir, x.prof+".json")
	raw, _ := os.ReadFile(p)
	s := strings.Replace(string(raw), `"max_seconds":30`, `"max_seconds":30,"allow_bundle":true`, 1)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBundleRefusedUnlessTheProfileAllowsIt(t *testing.T) {
	x := setup(t, true)
	x.m.Exec = &bundleExec{fakeExec: x.ex}
	if _, err := x.m.StartBundle(context.Background(), x.prof, "python3 main.py", []byte("tar"), 0); err == nil {
		t.Fatal("a profile that did not opt in must refuse a bundle")
	}
}

func TestBundleTooLargeIsRefused(t *testing.T) {
	x := setup(t, true)
	allowBundles(t, x)
	x.m.Exec = &bundleExec{fakeExec: x.ex}
	if _, err := x.m.StartBundle(context.Background(), x.prof, "true", make([]byte, maxBundle+1), 0); err == nil {
		t.Fatal("an oversized bundle must be refused")
	}
}

func TestBundleNeedsAnExecutorThatCanCarryIt(t *testing.T) {
	x := setup(t, true)
	allowBundles(t, x)
	if _, err := x.m.StartBundle(context.Background(), x.prof, "true", []byte("tar"), 0); err == nil {
		t.Fatal("an executor that cannot carry files must refuse")
	}
}

func TestBundleReachesTheGuestAndIsAudited(t *testing.T) {
	x := setup(t, true)
	allowBundles(t, x)
	be := &bundleExec{fakeExec: x.ex}
	x.m.Exec = be
	id, err := x.m.StartBundle(context.Background(), x.prof, "python3 main.py", []byte("TARDATA"), 0)
	if err != nil {
		t.Fatal(err)
	}
	r := wait(t, x.m, id)
	if r.Status != Done || !strings.Contains(r.Stdout, "agent output") || string(be.gotBundle) != "TARDATA" || be.gotCmd != "python3 main.py" {
		t.Fatalf("%+v %q %q", r, be.gotBundle, be.gotCmd)
	}
	logged := false
	for _, e := range x.ev.list {
		if strings.Contains(e, "bundle_sha256") {
			logged = true
		}
	}
	if !logged {
		t.Fatalf("the bundle's hash must be in the audit log: %v", x.ev.list)
	}
}

func TestBundleWrapUnpacksFirstThenRunsInsideTheFolder(t *testing.T) {
	w := bundleWrap("python3 main.py")
	i, j, k := strings.Index(w, "tar --no-same-owner"), strings.Index(w, "cd \"$HOME/agent\""), strings.Index(w, "python3 main.py")
	if !(0 < i && i < j && j < k) {
		t.Fatalf("wrong order: %s", w)
	}
}
