// Package fail2ban_test provides external tests for the fail2ban package,
// ensuring proper isolation and testing of exported interfaces.
package fail2ban_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestClientInitializationEdgeCases tests edge cases in client initialization
func TestClientInitializationEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*fail2bantest.MockRunner)
		expectError bool
		errorMsg    string
	}{
		{
			name: "version command returns error",
			setupMock: func(m *fail2bantest.MockRunner) {
				m.SetError("fail2ban-client -V", fmt.Errorf("command not found"))
			},
			expectError: true,
			errorMsg:    "version check failed",
		},
		{
			name: "ping command returns error",
			setupMock: func(m *fail2bantest.MockRunner) {
				m.SetResponse("fail2ban-client -V", []byte("0.11.2"))
				m.SetError("fail2ban-client ping", fmt.Errorf("connection refused"))
			},
			expectError: true,
			errorMsg:    "fail2ban ping failed",
		},
		{
			name: "status command returns unparseable output",
			setupMock: func(m *fail2bantest.MockRunner) {
				m.SetResponse("fail2ban-client -V", []byte("0.11.2"))
				m.SetResponse("fail2ban-client ping", []byte("pong"))
				m.SetResponse("fail2ban-client status", []byte("Invalid status output"))
			},
			expectError: true,
			errorMsg:    "failed to parse jails",
		},
		{
			name: "empty jail list",
			setupMock: func(m *fail2bantest.MockRunner) {
				m.SetResponse("fail2ban-client -V", []byte("0.11.2"))
				m.SetResponse("fail2ban-client ping", []byte("pong"))
				m.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 0\n`- Jail list:"))
			},
			expectError: false, // Changed to false since we now allow empty jail lists
			errorMsg:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &fail2bantest.MockRunner{
				Responses: make(map[string][]byte),
				Errors:    make(map[string]error),
			}
			tt.setupMock(mock)
			t.Cleanup(fail2bantest.WithTestRunner(t, mock))

			_, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)

			fail2bantest.AssertError(t, err, tt.expectError, tt.name)
			if tt.expectError && tt.errorMsg != "" {
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			}
		})
	}
}
