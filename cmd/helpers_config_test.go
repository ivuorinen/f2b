package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestProcessBanOperation tests the ProcessBanOperation function
func TestProcessBanOperation(t *testing.T) {
	// Save and restore original runner
	originalRunner := fail2ban.GetRunner()
	defer fail2ban.SetRunner(originalRunner)

	tests := []struct {
		name        string
		setupMock   func(*fail2ban.MockRunner)
		ip          string
		jails       []string
		expectError bool
		expectCount int
	}{
		{
			name: "successful ban single jail",
			setupMock: func(m *fail2ban.MockRunner) {
				setupBasicMockResponses(m)
				m.SetResponse("fail2ban-client set sshd banip 192.168.1.1", []byte("1"))
				m.SetResponse("sudo fail2ban-client set sshd banip 192.168.1.1", []byte("1"))
			},
			ip:          "192.168.1.1",
			jails:       []string{"sshd"},
			expectError: false,
			expectCount: 1,
		},
		{
			name: "successful ban multiple jails",
			setupMock: func(m *fail2ban.MockRunner) {
				setupBasicMockResponses(m)
				m.SetResponse("fail2ban-client set sshd banip 192.168.1.1", []byte("1"))
				m.SetResponse("sudo fail2ban-client set sshd banip 192.168.1.1", []byte("1"))
				m.SetResponse("fail2ban-client set apache banip 192.168.1.1", []byte("1"))
				m.SetResponse("sudo fail2ban-client set apache banip 192.168.1.1", []byte("1"))
			},
			ip:          "192.168.1.1",
			jails:       []string{"sshd", "apache"},
			expectError: false,
			expectCount: 2,
		},
		{
			name: "invalid IP address",
			setupMock: func(m *fail2ban.MockRunner) {
				setupBasicMockResponses(m)
			},
			ip:          "invalid.ip",
			jails:       []string{"sshd"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRunner := fail2ban.NewMockRunner()
			tt.setupMock(mockRunner)
			fail2ban.SetRunner(mockRunner)

			client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
			require.NoError(t, err)

			results, err := ProcessBanOperation(client, tt.ip, tt.jails)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, results, tt.expectCount)

				// Verify result structure
				for _, result := range results {
					assert.Equal(t, tt.ip, result.IP)
					assert.NotEmpty(t, result.Jail)
					assert.NotEmpty(t, result.Status)
				}
			}
		})
	}
}

// TestParseTimeoutFromEnv tests the parseTimeoutFromEnv function
func TestParseTimeoutFromEnv(t *testing.T) {
	tests := []struct {
		name         string
		envVarName   string
		envValue     string
		defaultValue time.Duration
		expected     time.Duration
	}{
		{
			name:         "valid timeout value",
			envVarName:   "TEST_TIMEOUT",
			envValue:     "5s",
			defaultValue: 1 * time.Second,
			expected:     5 * time.Second,
		},
		{
			name:         "empty environment variable uses default",
			envVarName:   "EMPTY_TIMEOUT",
			envValue:     "",
			defaultValue: 2 * time.Second,
			expected:     2 * time.Second,
		},
		{
			name:         "invalid timeout value uses default",
			envVarName:   "INVALID_TIMEOUT",
			envValue:     "not-a-duration",
			defaultValue: 3 * time.Second,
			expected:     3 * time.Second,
		},
		{
			name:         "negative timeout value uses default",
			envVarName:   "NEGATIVE_TIMEOUT",
			envValue:     "-100ms",
			defaultValue: 4 * time.Second,
			expected:     4 * time.Second,
		},
		{
			name:         "zero timeout uses default",
			envVarName:   "ZERO_TIMEOUT",
			envValue:     "0",
			defaultValue: 5 * time.Second,
			expected:     5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set test value using t.Setenv (auto-cleanup)
			if tt.envValue != "" {
				t.Setenv(tt.envVarName, tt.envValue)
			}

			result := parseTimeoutFromEnv(tt.envVarName, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// setupBasicMockResponses is a helper for setting up version check and ping responses
func setupBasicMockResponses(m *fail2ban.MockRunner) {
	m.SetResponse("fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	m.SetResponse("sudo fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	m.SetResponse("fail2ban-client ping", []byte("Server replied: pong"))
	m.SetResponse("sudo fail2ban-client ping", []byte("Server replied: pong"))
	m.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 2\n`- Jail list: sshd, apache"))
	m.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 2\n`- Jail list: sshd, apache"))
}
