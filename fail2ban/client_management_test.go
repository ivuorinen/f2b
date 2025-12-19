package fail2ban

import (
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/shared"
)

func TestNewClient(t *testing.T) {
	// Test normal client creation (in test environment, sudo checking is skipped)
	t.Run("normal client creation", func(t *testing.T) {
		// Set up mock environment with standard responses
		_, cleanup := SetupMockEnvironmentWithStandardResponses(t)
		defer cleanup()

		client, err := NewClient(shared.DefaultLogDir, shared.DefaultFilterDir)
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
