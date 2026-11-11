package fail2ban_test

import (
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

func TestVersionComparison(t *testing.T) {
	tests := []struct {
		name           string
		versionOutput  string
		expectError    bool
		errorSubstring string
	}{
		{
			name:          "prefixed supported version",
			versionOutput: "Fail2Ban v0.11.2",
			expectError:   false,
		},
		{
			name:          "plain supported version",
			versionOutput: "0.12.0",
			expectError:   false,
		},
		{
			name:           "unsupported version",
			versionOutput:  "Fail2Ban v0.10.9",
			expectError:    true,
			errorSubstring: "fail2ban >=0.11.0 required",
		},
		{
			name:           "unparseable version",
			versionOutput:  "unexpected output",
			expectError:    true,
			errorSubstring: "failed to parse fail2ban version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, true)
			defer cleanup()

			mock := fail2bantest.MustMockRunner(t)
			mock.SetResponse("fail2ban-client -V", []byte(tt.versionOutput))
			mock.SetResponse("sudo fail2ban-client -V", []byte(tt.versionOutput))

			if !tt.expectError {
				mock.SetResponse("fail2ban-client ping", []byte("pong"))
				mock.SetResponse("sudo fail2ban-client ping", []byte("pong"))
				statusOutput := []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd")
				mock.SetResponse("fail2ban-client status", statusOutput)
				mock.SetResponse("sudo fail2ban-client status", statusOutput)
			}

			_, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)

			fail2bantest.AssertError(t, err, tt.expectError, tt.name)
			if tt.expectError && tt.errorSubstring != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errorSubstring) {
					t.Fatalf("expected error containing %q, got %v", tt.errorSubstring, err)
				}
			}
		})
	}
}

func TestExtractFail2BanVersion(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expect    string
		expectErr bool
	}{
		{
			name:   "prefixed output",
			input:  "Fail2Ban v0.11.2",
			expect: "0.11.2",
		},
		{
			name:   "with extra context",
			input:  "fail2ban 0.12.0 (Python 3)",
			expect: "0.12.0",
		},
		{
			name:   "plain version",
			input:  "0.13.1",
			expect: "0.13.1",
		},
		{
			name:   "leading v",
			input:  "v1.0.0",
			expect: "1.0.0",
		},
		{
			name:      "invalid output",
			input:     "not a version",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := fail2ban.ExtractFail2BanVersion(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
			if version != tt.expect {
				t.Fatalf("expected version %q, got %q", tt.expect, version)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{
			name:     "equal versions",
			v1:       "1.0.0",
			v2:       "1.0.0",
			expected: 0,
		},
		{
			name:     "v1 less than v2",
			v1:       "0.11.0",
			v2:       "1.0.0",
			expected: -1,
		},
		{
			name:     "v1 greater than v2",
			v1:       "1.2.0",
			v2:       "1.0.0",
			expected: 1,
		},
		{
			name:     "patch version difference",
			v1:       "1.0.1",
			v2:       "1.0.2",
			expected: -1,
		},
		{
			name:     "prerelease versions",
			v1:       "1.0.0-alpha",
			v2:       "1.0.0",
			expected: -1,
		},
		{
			name:     "invalid version strings fallback to string comparison",
			v1:       "invalid.version",
			v2:       "another.invalid",
			expected: 1, // "invalid.version" > "another.invalid" lexicographically
		},
		{
			name:     "mixed valid and invalid",
			v1:       "1.0.0",
			v2:       "invalid",
			expected: -1, // string comparison: "1.0.0" < "invalid"
		},
		{
			name:     "version with build metadata",
			v1:       "1.0.0+build.1",
			v2:       "1.0.0+build.2",
			expected: 0, // build metadata should be ignored in semantic versioning
		},
		{
			name:     "numeric prerelease identifiers compare numerically",
			v1:       "0.11.0-rc.9",
			v2:       "0.11.0-rc.10",
			expected: -1,
		},
		{
			name:     "numeric prerelease sorts before alphanumeric",
			v1:       "1.0.0-alpha.1",
			v2:       "1.0.0-alpha.beta",
			expected: -1,
		},
		{
			name:     "shorter prerelease sorts first",
			v1:       "1.0.0-alpha",
			v2:       "1.0.0-alpha.1",
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fail2ban.CompareVersions(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("CompareVersions(%q, %q) = %d, expected %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}
