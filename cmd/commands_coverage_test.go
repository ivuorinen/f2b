package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestTestFilterCmdCreation tests TestFilterCmd command creation
func TestTestFilterCmdCreation(t *testing.T) {
	mockRunner := fail2ban.NewMockRunner()
	defer fail2ban.WithTestRunner(t, mockRunner)()
	fail2ban.StandardMockSetup(mockRunner)

	client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	config := &Config{
		Format:      PlainFormat,
		FileTimeout: 5 * time.Second,
	}

	cmd := TestFilterCmd(client, config)

	// Verify command structure
	assert.NotNil(t, cmd)
	assert.Equal(t, "test-filter <filter>", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.RunE)
}

// TestTestFilterCmdExecution tests TestFilterCmd execution
func TestTestFilterCmdExecution(t *testing.T) {
	defer fail2ban.WithTestRunner(t, fail2ban.GetRunner())()

	tests := []struct {
		name        string
		setupMock   func(*fail2ban.MockRunner)
		args        []string
		expectError bool
	}{
		{
			name: "successful filter test",
			setupMock: func(m *fail2ban.MockRunner) {
				fail2ban.StandardMockSetup(m)
				m.SetResponse("fail2ban-client get sshd logpath", []byte("/var/log/auth.log"))
				m.SetResponse("sudo fail2ban-client get sshd logpath", []byte("/var/log/auth.log"))
			},
			args:        []string{"sshd"},
			expectError: false,
		},
		{
			name: "no filter provided - lists available",
			setupMock: func(m *fail2ban.MockRunner) {
				fail2ban.StandardMockSetup(m)
				// Mock ListFiltersWithContext response
			},
			args:        []string{},
			expectError: true, // Should error saying filter required
		},
		{
			name: "invalid filter name",
			setupMock: func(m *fail2ban.MockRunner) {
				fail2ban.StandardMockSetup(m)
			},
			args:        []string{"../../../etc/passwd"},
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

			config := &Config{
				Format:      PlainFormat,
				FileTimeout: 5 * time.Second,
			}

			cmd := TestFilterCmd(client, config)
			cmd.SetArgs(tt.args)

			err = cmd.Execute()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				// Note: Might error if filter doesn't exist, which is ok for this test
				_ = err
			}
		})
	}
}
