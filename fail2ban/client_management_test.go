package fail2ban

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/constants"
)

// TestNewClientIgnoresInstalledBinaryPath pins the argv an injected mock runner
// observes to the bare command name, regardless of whether the host has
// fail2ban installed.
//
// Client construction resolves fail2ban-client through exec.LookPath. When the
// binary exists, that yields an absolute path (/usr/bin/fail2ban-client), while
// every mock registers responses under the bare name — so the whole suite
// passed on CI, where fail2ban is absent, and failed on any machine with
// fail2ban installed. Planting a fake binary on PATH reproduces that split here
// instead of leaving it to the maintainer's workstation to discover.
func TestNewClientIgnoresInstalledBinaryPath(t *testing.T) {
	// A stub is enough: the mock runner intercepts execution, so this file is
	// only ever resolved by LookPath, never run.
	stubDir := t.TempDir()
	stub := filepath.Join(stubDir, constants.Fail2BanClientCommand)
	// #nosec G306 -- the executable bit is the point: exec.LookPath only returns
	// executable files, so a 0600 stub would make this test vacuous. The file is
	// a no-op script in a per-test temp dir that nothing ever executes.
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fail2ban-client stub: %v", err)
	}
	t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, cleanup := SetupMockEnvironmentWithStandardResponses(t)
	defer cleanup()

	client, err := NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
	if err != nil {
		t.Fatalf("client creation must not depend on a fail2ban binary being installed: %v", err)
	}
	if client.Path != constants.Fail2BanClientCommand {
		t.Errorf("expected mock-visible argv %q, got %q", constants.Fail2BanClientCommand, client.Path)
	}
}

func TestNewClient(t *testing.T) {
	// Test normal client creation (in test environment, sudo checking is skipped)
	t.Run("normal client creation", func(t *testing.T) {
		// Set up mock environment with standard responses
		_, cleanup := SetupMockEnvironmentWithStandardResponses(t)
		defer cleanup()

		client, err := NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if client == nil {
			t.Fatal("expected client to be non-nil")
		}
	})
}

func TestSudoRequirementsChecking(t *testing.T) {
	tests := []struct {
		name          string
		hasPrivileges bool
		expectError   bool
		errorContains string
	}{
		{
			name:          "with sudo privileges",
			hasPrivileges: true,
			expectError:   false,
		},
		{
			name:          "without sudo privileges",
			hasPrivileges: false,
			expectError:   true,
			errorContains: "fail2ban operations require sudo privileges",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock environment
			_, cleanup := SetupMockEnvironmentWithSudo(t, tt.hasPrivileges)
			defer cleanup()

			// Test the sudo checking function directly
			err := CheckSudoRequirements()

			AssertError(t, err, tt.expectError, tt.name)
			if tt.expectError {
				if tt.errorContains != "" && err != nil && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
				return
			}
		})
	}
}
