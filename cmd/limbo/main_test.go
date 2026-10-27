package main

import "testing"

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
