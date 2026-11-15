package fail2ban_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestMain keeps TMPDIR under the dev-path allowlist: the path tests write
// their logs and filters under t.TempDir() with ALLOW_DEV_PATHS set.
func TestMain(m *testing.M) {
	if err := fail2bantest.KeepTempDirUnderDevPaths(); err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
