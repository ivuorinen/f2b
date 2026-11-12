package fail2ban_test

import (
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// clientDirCase is one NewClient call. errorContains names the directory that
// must be rejected, or is empty when both directories are allowed.
type clientDirCase struct {
	name, logDir, filterDir, errorContains string
}

// clientDirCases lists log and filter directories NewClient must accept or
// reject: traversal, encoding tricks, and trees outside the allowlist.
func clientDirCases() []clientDirCase {
	const (
		goodLog, goodFilter = "/var/log", "/etc/fail2ban/filter.d"
		badLog, badFilter   = "invalid log directory", "invalid filter directory"
	)
	return []clientDirCase{
		{"valid paths", goodLog, goodFilter, ""},
		{"allowed alternative paths", "/var/log/myapp", "/opt/fail2ban/filters", ""},
		{"path traversal in logDir", "/var/log/../../../etc/passwd", goodFilter, badLog},
		{"path traversal in filterDir", goodLog, "/etc/fail2ban/../../../etc/passwd", badFilter},
		{"URL encoded path traversal in logDir", "/var/log/%2e%2e/%2e%2e/etc/passwd", goodFilter, badLog},
		{"null byte in logDir", "/var/log\x00/malicious", goodFilter, badLog},
		{"null byte in filterDir", goodLog, "/etc/fail2ban/filter.d\x00/malicious", badFilter},
		{"non-allowed base path for logDir", "/etc/passwd", goodFilter, badLog},
		// A filter directory belongs under /etc/fail2ban, not /var/log.
		{"non-allowed base path for filterDir", goodLog, "/var/log/filter.d", badFilter},
		// test-filter makes root read the logpath, so arbitrary application
		// trees are not an allowed log location.
		{"log dir under /opt rejected", "/opt/myapp/logs", goodFilter, badLog},
		{"log dir under /home rejected", "/home/user/logs", goodFilter, badLog},
		{"filter dir under /home rejected", goodLog, "/home/user/filters", badFilter},
		{"mixed case traversal in logDir", "/var/LOG/../../../etc/passwd", goodFilter, badLog},
		{"multiple slashes traversal in logDir", "/var/log////../../etc/passwd", goodFilter, badLog},
		{"unicode normalization attack in logDir", "/var/log/\u002e\u002e/\u002e\u002e/etc/passwd", goodFilter, badLog},
		{"windows-style paths on unix in logDir", "/var/log\\..\\..\\..\\etc\\passwd", goodFilter, badLog},
		{"mixed case traversal in filterDir", goodLog, "/etc/fail2ban/FILTER.D/../../../etc/passwd", badFilter},
		{"multiple slashes traversal in filterDir", goodLog, "/etc/fail2ban/filter.d////../../etc/passwd", badFilter},
		{"unicode normalization attack in filterDir", goodLog,
			"/etc/fail2ban/filter.d/\u002e\u002e/\u002e\u002e/etc/passwd", badFilter},
		{"windows-style paths on unix in filterDir", goodLog,
			"/etc/fail2ban/filter.d\\..\\..\\..\\etc\\passwd", badFilter},
	}
}

func TestNewClientPathTraversalProtection(t *testing.T) {
	_, cleanup := fail2bantest.SetupMockEnvironmentWithStandardResponses(t)
	defer cleanup()

	for _, tt := range clientDirCases() {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fail2ban.NewClient(tt.logDir, tt.filterDir)

			switch {
			case tt.errorContains == "":
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			case err == nil:
				t.Errorf("expected error but got none")
			case !strings.Contains(err.Error(), tt.errorContains):
				t.Errorf("expected error containing %q, got %q", tt.errorContains, err.Error())
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
