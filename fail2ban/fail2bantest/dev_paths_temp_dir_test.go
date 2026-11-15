package fail2bantest

import (
	"os"
	"testing"
)

// TestKeepTempDirUnderDevPaths pins that a TMPDIR the dev-path allowlist
// refuses moves to /tmp, an admitted one stays, and ALLOW_DEV_PATHS is left as
// the caller had it. Neither directory needs to exist: the allowlist decides
// on the path.
func TestKeepTempDirUnderDevPaths(t *testing.T) {
	tests := []struct {
		name, tmpdir, want string
	}{
		{"refused directory moves to /tmp", "/srv/f2b-not-admitted", "/tmp"},
		{"admitted directory stays", "/tmp/f2b-admitted", "/tmp/f2b-admitted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TMPDIR", tt.tmpdir)
			t.Setenv("ALLOW_DEV_PATHS", "0")

			if err := KeepTempDirUnderDevPaths(); err != nil {
				t.Fatalf("KeepTempDirUnderDevPaths: %v", err)
			}

			if got := os.Getenv("TMPDIR"); got != tt.want {
				t.Errorf("TMPDIR = %q, want %q", got, tt.want)
			}
			if got := os.Getenv("ALLOW_DEV_PATHS"); got != "0" {
				t.Errorf("ALLOW_DEV_PATHS = %q, want it restored to %q", got, "0")
			}
		})
	}
}
