//go:build unix

package fail2ban_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestOSRunnerRefusesHostileArguments asserts on the stubs' side effect: the
// arguments go through sudo as root, so nothing may run once they fail.
func TestOSRunnerRefusesHostileArguments(t *testing.T) {
	dir := useSudoStubs(t)
	marker := filepath.Join(t.TempDir(), "executed")
	writeStub(t, dir, "sudo", `: > "`+marker+`"`)
	writeStub(t, dir, "fail2ban-client", `: > "`+marker+`"`)
	orig := fail2ban.GetSudoChecker()
	fail2ban.SetSudoChecker(&fail2bantest.MockSudoChecker{MockHasPrivileges: true, ExplicitPrivilegesSet: true})
	t.Cleanup(func() { fail2ban.SetSudoChecker(orig) })

	_, err := (&fail2ban.OSRunner{}).CombinedOutputWithSudoContext(
		context.Background(),
		"fail2ban-client",
		"status;reboot",
	)

	require.Error(t, err)
	assert.NoFileExists(t, marker, "a command ran after its arguments failed validation")
}
