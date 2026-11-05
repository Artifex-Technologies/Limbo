package exchange

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The real scanner, against the industry's harmless test file (EICAR) and a plain file. Slow (clamscan loads its
// database each time), so only with LIMBO_CLAMAV=1. The EICAR text is assembled at run time, never stored in the repo,
// so no scanner flags the source.
func TestRealClamAV(t *testing.T) {
	if os.Getenv("LIMBO_CLAMAV") != "1" {
		t.Skip("set LIMBO_CLAMAV=1 to run ClamAV for real")
	}
	d := t.TempDir()
	parts := []string{`X5O!P%@AP[4\PZX54(P^)7CC)7}$`, `EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`}
	eicar := filepath.Join(d, "e.com")
	os.WriteFile(eicar, []byte(strings.Join(parts, "")), 0o600)
	plain := filepath.Join(d, "p.txt")
	os.WriteFile(plain, []byte("a report\n"), 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, sig, err := ClamAV{}.Scan(ctx, eicar)
	if err != nil || res != Infected || !strings.Contains(sig, "Eicar") {
		t.Fatalf("eicar: %q %q %v", res, sig, err)
	}
	res, _, err = ClamAV{}.Scan(ctx, plain)
	if err != nil || res != Clean {
		t.Fatalf("plain: %q %v", res, err)
	}
	t.Logf("eicar -> %s (%s); plain -> clean", Infected, sig)
}
