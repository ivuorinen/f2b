package fail2ban_test

import (
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

func TestNewClientPathTraversalProtection(t *testing.T) {
	// Set up mock environment with standard responses
	_, cleanup := fail2bantest.SetupMockEnvironmentWithStandardResponses(t)
	defer cleanup()

	tests := []struct {
		name          string
		logDir        string
		filterDir     string
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid paths",
			logDir:      "/var/log",
			filterDir:   "/etc/fail2ban/filter.d",
			expectError: false,
		},
		{
			name:          "path traversal in logDir",
			logDir:        "/var/log/../../../etc/passwd",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "path traversal in filterDir",
			logDir:        "/var/log",
			filterDir:     "/etc/fail2ban/../../../etc/passwd",
			expectError:   true,
			errorContains: "invalid filter directory",
		},
		{
			name:          "URL encoded path traversal in logDir",
			logDir:        "/var/log/%2e%2e/%2e%2e/etc/passwd",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "null byte in logDir",
			logDir:        "/var/log\x00/malicious",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "null byte in filterDir",
			logDir:        "/var/log",
			filterDir:     "/etc/fail2ban/filter.d\x00/malicious",
			expectError:   true,
			errorContains: "invalid filter directory",
		},
		{
			name:          "non-allowed base path for logDir",
			logDir:        "/etc/passwd",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "non-allowed base path for filterDir",
			logDir:        "/var/log",
			filterDir:     "/var/log/filter.d", // filter dir should be in /etc/fail2ban
			expectError:   true,
			errorContains: "invalid filter directory",
		},
		{
			name:        "allowed alternative paths",
			logDir:      "/var/log/myapp",
			filterDir:   "/opt/fail2ban/filters",
			expectError: false,
		},
		{
			// test-filter makes root read the logpath, so arbitrary
			// application trees are not an allowed log location.
			name:          "log dir under /opt rejected",
			logDir:        "/opt/myapp/logs",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "log dir under /home rejected",
			logDir:        "/home/user/logs",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "filter dir under /home rejected",
			logDir:        "/var/log",
			filterDir:     "/home/user/filters",
			expectError:   true,
			errorContains: "invalid filter directory",
		},
		{
			name:          "mixed case traversal in logDir",
			logDir:        "/var/LOG/../../../etc/passwd",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "multiple slashes traversal in logDir",
			logDir:        "/var/log////../../etc/passwd",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "unicode normalization attack in logDir",
			logDir:        "/var/log/\u002e\u002e/\u002e\u002e/etc/passwd",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "windows-style paths on unix in logDir",
			logDir:        "/var/log\\..\\..\\..\\etc\\passwd",
			filterDir:     "/etc/fail2ban/filter.d",
			expectError:   true,
			errorContains: "invalid log directory",
		},
		{
			name:          "mixed case traversal in filterDir",
			logDir:        "/var/log",
			filterDir:     "/etc/fail2ban/FILTER.D/../../../etc/passwd",
			expectError:   true,
			errorContains: "invalid filter directory",
		},
		{
			name:          "multiple slashes traversal in filterDir",
			logDir:        "/var/log",
			filterDir:     "/etc/fail2ban/filter.d////../../etc/passwd",
			expectError:   true,
			errorContains: "invalid filter directory",
		},
		{
			name:          "unicode normalization attack in filterDir",
			logDir:        "/var/log",
			filterDir:     "/etc/fail2ban/filter.d/\u002e\u002e/\u002e\u002e/etc/passwd",
			expectError:   true,
			errorContains: "invalid filter directory",
		},
		{
			name:          "windows-style paths on unix in filterDir",
			logDir:        "/var/log",
			filterDir:     "/etc/fail2ban/filter.d\\..\\..\\..\\etc\\passwd",
			expectError:   true,
			errorContains: "invalid filter directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fail2ban.NewClient(tt.logDir, tt.filterDir)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error containing %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestNewClientDefaultPathValidation(t *testing.T) {
	// Set up mock environment with standard responses
	_, cleanup := fail2bantest.SetupMockEnvironmentWithStandardResponses(t)
	defer cleanup()

	// Test with empty paths (should use defaults and validate them)
	client, err := fail2ban.NewClient("", "")
	if err != nil {
		t.Fatalf("unexpected error with default paths: %v", err)
	}

	// Verify defaults were applied
	if client.LogDir != constants.DefaultLogDir {
		t.Errorf("expected LogDir to be %s, got %s", constants.DefaultLogDir, client.LogDir)
	}

	if client.FilterDir != constants.DefaultFilterDir {
		// The validator resolves symlinked ancestors (e.g. /etc on macOS).
		if resolved, err := fail2ban.ValidateClientFilterPath(constants.DefaultFilterDir); err == nil {
			if client.FilterDir != resolved {
				t.Errorf(
					"expected FilterDir to be %s or %s, got %s",
					constants.DefaultFilterDir,
					resolved,
					client.FilterDir,
				)
			}
		} else {
			t.Errorf("expected FilterDir to be %s, got %s", constants.DefaultFilterDir, client.FilterDir)
		}
	}
}
