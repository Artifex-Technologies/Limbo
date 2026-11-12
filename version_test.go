package limbo

import (
	"regexp"
	"testing"
)

func TestVersionIsTheVersionFile(t *testing.T) {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(Version) {
		t.Fatalf("Version is %q, not MAJOR.MINOR.PATCH from the VERSION file", Version)
	}
}
