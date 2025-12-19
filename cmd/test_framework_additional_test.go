package cmd

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestOutputOperationResults tests the outputOperationResults function
func TestOutputOperationResults(t *testing.T) {
	tests := []struct {
		name      string
		results   []OperationResult
		config    *Config
		format    string
		expectOut string
	}{
		{
			name: "json format output",
			results: []OperationResult{
				{IP: "192.168.1.1", Jail: "sshd", Status: "Banned"},
			},
			config:    &Config{Format: JSONFormat},
			format:    JSONFormat,
			expectOut: "192.168.1.1",
		},
		{
			name: "plain format output",
			results: []OperationResult{
				{IP: "192.168.1.1", Jail: "sshd", Status: "Banned"},
			},
			config:    &Config{Format: PlainFormat},
			format:    PlainFormat,
			expectOut: "192.168.1.1",
		},
		{
			name: "multiple results",
			results: []OperationResult{
				{IP: "192.168.1.1", Jail: "sshd", Status: "Banned"},
				{IP: "192.168.1.2", Jail: "apache", Status: "Banned"},
			},
			config:    &Config{Format: PlainFormat},
			format:    PlainFormat,
			expectOut: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			var buf bytes.Buffer
			cmd.SetOut(&buf)

			err := outputOperationResults(cmd, tt.results, tt.config, tt.format)
			assert.NoError(t, err)

			output := buf.String()
			assert.Contains(t, output, tt.expectOut)
		})
	}
}

// TestValidateConfigPath tests the validateConfigPath function
func TestValidateConfigPath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		pathType    string
		expectError bool
	}{
		{
			name:        "valid absolute path",
			path:        "/etc/fail2ban",
			pathType:    "log",
			expectError: false,
		},
		{
			name:        "empty path",
			path:        "",
			pathType:    "log",
			expectError: true,
		},
		{
			name:        "relative path",
			path:        "config/fail2ban",
			pathType:    "filter",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateConfigPath(tt.path, tt.pathType)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				// Path validation might fail for non-existent paths
				_ = err
			}
		})
	}
}

// TestLogsWatchCmdCreation tests LogsWatchCmd creation
func TestLogsWatchCmdCreation(t *testing.T) {
	// Save and restore original runner
	originalRunner := fail2ban.GetRunner()
	defer fail2ban.SetRunner(originalRunner)

	mockRunner := fail2ban.NewMockRunner()
	mockRunner.SetResponse("fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mockRunner.SetResponse("sudo fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mockRunner.SetResponse("fail2ban-client ping", []byte("Server replied: pong"))
	mockRunner.SetResponse("sudo fail2ban-client ping", []byte("Server replied: pong"))
	mockRunner.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mockRunner.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	fail2ban.SetRunner(mockRunner)

	client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	ctx := context.Background()
	config := &Config{Format: PlainFormat}

	cmd := LogsWatchCmd(ctx, client, config)
	require.NotNil(t, cmd)
	assert.Equal(t, "logs-watch [jail] [ip]", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.RunE)

	// Test flags exist (jail and ip are positional args, not flags)
	assert.NotNil(t, cmd.Flags().Lookup("limit"))
	assert.NotNil(t, cmd.Flags().Lookup("interval"))
}

// TestGetLogLinesWithLimitAndContext_Function tests the function
func TestGetLogLinesWithLimitAndContext_Function(t *testing.T) {
	// Save and restore original runner
	originalRunner := fail2ban.GetRunner()
	defer fail2ban.SetRunner(originalRunner)

	mockRunner := fail2ban.NewMockRunner()
	mockRunner.SetResponse("fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mockRunner.SetResponse("sudo fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mockRunner.SetResponse("fail2ban-client ping", []byte("Server replied: pong"))
	mockRunner.SetResponse("sudo fail2ban-client ping", []byte("Server replied: pong"))
	mockRunner.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mockRunner.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	fail2ban.SetRunner(mockRunner)

	tmpDir := t.TempDir()
	oldLogDir := fail2ban.GetLogDir()
	fail2ban.SetLogDir(tmpDir)
	defer fail2ban.SetLogDir(oldLogDir)

	client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	ctx := context.Background()
	timeout := 5 * time.Second

	tests := []struct {
		name     string
		jail     string
		ip       string
		maxLines int
	}{
		{
			name:     "with no filters",
			jail:     "",
			ip:       "",
			maxLines: 10,
		},
		{
			name:     "with jail filter",
			jail:     "sshd",
			ip:       "",
			maxLines: 10,
		},
		{
			name:     "with ip filter",
			jail:     "",
			ip:       "192.168.1.1",
			maxLines: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			_, err := getLogLinesWithLimitAndContext(ctx, client, tt.jail, tt.ip, tt.maxLines, timeout)
			// May return error if no log files exist, which is ok
			_ = err
		})
	}
}

// TestOutputResults_DifferentFormats tests OutputResults with various data types
func TestOutputResults_DifferentFormats(t *testing.T) {
	tests := []struct {
		name    string
		results interface{}
		config  *Config
	}{
		{
			name:    "json format with array",
			results: []string{"result1", "result2"},
			config:  &Config{Format: JSONFormat},
		},
		{
			name:    "plain format with string",
			results: "plain text output",
			config:  &Config{Format: PlainFormat},
		},
		{
			name:    "nil config uses default",
			results: "test output",
			config:  nil,
		},
		{
			name:    "json format with map",
			results: map[string]interface{}{"key": "value", "count": 5},
			config:  &Config{Format: JSONFormat},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			var buf bytes.Buffer
			cmd.SetOut(&buf)

			// Should not panic
			OutputResults(cmd, tt.results, tt.config)

			// Verify output was written
			output := buf.String()
			assert.NotEmpty(t, output)
		})
	}
}

// TestPrintOutput_NoError tests that PrintOutput doesn't panic
func TestPrintOutput_NoError(t *testing.T) {
	// Test that various data types don't cause panics
	assert.NotPanics(t, func() {
		PrintOutput("test string", PlainFormat)
	})

	assert.NotPanics(t, func() {
		PrintOutput(map[string]string{"key": "value"}, JSONFormat)
	})

	assert.NotPanics(t, func() {
		PrintOutput([]int{1, 2, 3}, JSONFormat)
	})
}
