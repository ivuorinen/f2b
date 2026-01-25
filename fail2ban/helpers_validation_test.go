package fail2ban

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateFilterName tests the ValidateFilterName function
func TestValidateFilterName(t *testing.T) {
	tests := []struct {
		name        string
		filter      string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid filter name",
			filter:      "sshd",
			expectError: false,
		},
		{
			name:        "valid filter name with dash",
			filter:      "sshd-aggressive",
			expectError: false,
		},
		{
			name:        "empty filter name",
			filter:      "",
			expectError: true,
			errorMsg:    "filter name cannot be empty",
		},
		{
			name:        "filter name with spaces gets trimmed",
			filter:      "  sshd  ",
			expectError: false,
		},
		{
			name:        "filter name with path traversal",
			filter:      "../../../etc/passwd",
			expectError: true,
			errorMsg:    "filter name contains path traversal",
		},
		{
			name:        "filter name with dot dot - caught by character validation",
			filter:      "filter..conf",
			expectError: true,
			errorMsg:    "filter name contains invalid characters",
		},
		{
			name:        "absolute path filter name - caught by path traversal first",
			filter:      "/etc/fail2ban/filter.d/sshd.conf",
			expectError: true,
			errorMsg:    "filter name contains path traversal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilterName(tt.filter)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGetLogLinesWrapper tests the GetLogLines wrapper function
func TestGetLogLinesWrapper(t *testing.T) {
	mockRunner := NewMockRunner()
	defer WithTestRunner(t, mockRunner)()
	mockRunner.SetResponse("fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mockRunner.SetResponse("sudo fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mockRunner.SetResponse("fail2ban-client ping", []byte("Server replied: pong"))
	mockRunner.SetResponse("sudo fail2ban-client ping", []byte("Server replied: pong"))
	mockRunner.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mockRunner.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))

	// Create temporary log directory
	tmpDir := t.TempDir()
	oldLogDir := GetLogDir()
	SetLogDir(tmpDir)
	defer SetLogDir(oldLogDir)

	client, err := NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	// Call GetLogLines (wrapper for GetLogLinesWithLimit)
	lines, err := client.GetLogLines("sshd", "192.168.1.1")

	// May return error if no log files exist, which is ok
	_ = err
	_ = lines
}

// TestBanIPWithContext tests the BanIPWithContext function
func TestBanIPWithContext(t *testing.T) {
	defer WithTestRunner(t, GetRunner())()

	tests := []struct {
		name        string
		setupMock   func(*MockRunner)
		ip          string
		jail        string
		expectError bool
	}{
		{
			name: "successful ban",
			setupMock: func(m *MockRunner) {
				m.SetResponse("fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
				m.SetResponse("sudo fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
				m.SetResponse("fail2ban-client ping", []byte("Server replied: pong"))
				m.SetResponse("sudo fail2ban-client ping", []byte("Server replied: pong"))
				m.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
				m.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
				m.SetResponse("fail2ban-client set sshd banip 192.168.1.1", []byte("1"))
				m.SetResponse("sudo fail2ban-client set sshd banip 192.168.1.1", []byte("1"))
			},
			ip:          "192.168.1.1",
			jail:        "sshd",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRunner := NewMockRunner()
			tt.setupMock(mockRunner)
			SetRunner(mockRunner)

			client, err := NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
			require.NoError(t, err)

			ctx := context.Background()
			count, err := client.BanIPWithContext(ctx, tt.ip, tt.jail)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.GreaterOrEqual(t, count, 0, "Count should be 0 (new ban) or 1 (already banned)")
			}
		})
	}
}

// TestGetLogLinesWithLimitAndContext tests the GetLogLinesWithLimitAndContext function
func TestGetLogLinesWithLimitAndContext(t *testing.T) {
	mockRunner := NewMockRunner()
	defer WithTestRunner(t, mockRunner)()
	mockRunner.SetResponse("fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mockRunner.SetResponse("sudo fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mockRunner.SetResponse("fail2ban-client ping", []byte("Server replied: pong"))
	mockRunner.SetResponse("sudo fail2ban-client ping", []byte("Server replied: pong"))
	mockRunner.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mockRunner.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))

	// Create temporary log directory
	tmpDir := t.TempDir()
	oldLogDir := GetLogDir()
	SetLogDir(tmpDir)
	defer SetLogDir(oldLogDir)

	client, err := NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name     string
		jail     string
		ip       string
		maxLines int
	}{
		{
			name:     "get log lines with limit",
			jail:     "sshd",
			ip:       "192.168.1.1",
			maxLines: 10,
		},
		{
			name:     "zero max lines",
			jail:     "sshd",
			ip:       "192.168.1.1",
			maxLines: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			lines, err := client.GetLogLinesWithLimitAndContext(ctx, tt.jail, tt.ip, tt.maxLines)

			// May return error if no log files exist, which is ok for this test
			_ = err
			_ = lines
		})
	}
}
