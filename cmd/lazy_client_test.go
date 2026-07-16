package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// setInvalidTestCfg points the global cfg at a traversal path so any real
// client construction fails, and restores the original cfg on cleanup.
func setInvalidTestCfg(t *testing.T) {
	t.Helper()
	originalCfg := cfg
	t.Cleanup(func() { cfg = originalCfg })
	cfg = Config{
		LogDir:    "../../../etc",
		FilterDir: "../../../etc",
		Format:    PlainFormat,
	}
}

// setValidMockedTestCfg sets up a mock runner/sudo checker with standard
// responses and points cfg at the default directories, restoring on cleanup.
func setValidMockedTestCfg(t *testing.T) {
	t.Helper()
	originalCfg := cfg
	t.Cleanup(func() { cfg = originalCfg })
	_, cleanup := fail2ban.SetupMockEnvironmentWithStandardResponses(t)
	t.Cleanup(cleanup)
	cfg = Config{
		LogDir:    constants.DefaultLogDir,
		FilterDir: constants.DefaultFilterDir,
		Format:    PlainFormat,
	}
}

// TestNewLazyClientDefersConstruction verifies that NewLazyClient does not
// construct the underlying client eagerly: with an invalid cfg.LogDir no error
// surfaces until the first client method call.
func TestNewLazyClientDefersConstruction(t *testing.T) {
	setInvalidTestCfg(t)

	// Construction must succeed even though cfg is invalid.
	client := NewLazyClient()
	require.NotNil(t, client)

	// The first method call resolves the real client and surfaces the error.
	jails, err := client.ListJails()
	require.Error(t, err)
	assert.Nil(t, jails)
}

// TestLazyClientCachesConstructionError verifies the sync.Once error caching:
// a second call returns the identical error without re-resolving, even after
// cfg has been fixed and a working mock environment installed.
func TestLazyClientCachesConstructionError(t *testing.T) {
	setInvalidTestCfg(t)

	client := NewLazyClient()
	_, err1 := client.ListJails()
	require.Error(t, err1)

	// Fix the environment: valid cfg plus a mock runner that would let
	// construction succeed. The cached error must still be returned.
	setValidMockedTestCfg(t)

	_, err2 := client.StatusAll()
	require.Error(t, err2)
	assert.Equal(t, err1, err2, "second call must return the cached construction error")
}

// TestLazyClientResolvesAndDelegates verifies that with a valid mocked
// environment the lazy client resolves on first use and delegates calls to the
// real client.
func TestLazyClientResolvesAndDelegates(t *testing.T) {
	setValidMockedTestCfg(t)

	client := NewLazyClient()

	jails, err := client.ListJails()
	require.NoError(t, err)
	assert.Contains(t, jails, "sshd")

	// Subsequent calls reuse the already-resolved client.
	status, err := client.StatusAll()
	require.NoError(t, err)
	assert.NotEmpty(t, status)
}
