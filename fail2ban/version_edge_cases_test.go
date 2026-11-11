// Package fail2ban_test provides external tests for the fail2ban package,
// ensuring proper isolation and testing of exported interfaces.
package fail2ban_test

import (
	"testing"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestVersionComparisonEdgeCases tests the minimum-version check through
// NewClient, around the 0.11.0 boundary.
func TestVersionComparisonEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectError bool
	}{
		{name: "exact minimum version", version: "0.11.0", expectError: false},
		{name: "higher patch version", version: "0.11.10", expectError: false},
		{name: "higher minor version", version: "0.12.0", expectError: false},
		{name: "higher major version", version: "1.0.0", expectError: false},
		{name: "just below minimum", version: "0.10.99", expectError: true},
		{name: "much older version", version: "0.9.0", expectError: true},
		{name: "version with extra parts", version: "0.11.2.1", expectError: false},
		{name: "version with non-numeric parts", version: "0.11.2-beta", expectError: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &fail2bantest.MockRunner{
				Responses: make(map[string][]byte),
				Errors:    make(map[string]error),
			}
			mock.SetResponse("fail2ban-client -V", []byte(tt.version))
			if !tt.expectError {
				mock.SetResponse("fail2ban-client ping", []byte("pong"))
				mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
			}
			t.Cleanup(fail2bantest.WithTestRunner(t, mock))

			_, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)

			fail2bantest.AssertError(t, err, tt.expectError, tt.name)
		})
	}
}
