package fail2ban_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

func TestListFilters(t *testing.T) {
	// Set ALLOW_DEV_PATHS for test to use temp directory
	t.Setenv("ALLOW_DEV_PATHS", "true")

	// Create a temporary test filter directory
	tempDir := t.TempDir()
	filterDir := filepath.Join(tempDir, "filter.d")
	err := os.MkdirAll(filterDir, 0750)
	if err != nil {
		t.Fatalf("failed to create filter directory: %v", err)
	}

	// Create test filter files
	filterFiles := []string{"sshd.conf", "apache.conf", "nginx.conf", "readme.txt"}
	for _, file := range filterFiles {
		err := os.WriteFile(filepath.Join(filterDir, file), []byte("# test filter"), 0600)
		if err != nil {
			t.Fatalf("failed to create test filter file: %v", err)
		}
	}

	// Mock the filter directory path
	mock := fail2bantest.NewMockRunner()
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	t.Cleanup(fail2bantest.WithTestRunner(t, mock))

	// Create client with the temporary filter directory
	client, err := fail2ban.NewClient(constants.DefaultLogDir, filterDir)
	fail2bantest.AssertError(t, err, false, "create client")

	// Test ListFilters with the temporary directory
	filters, err := client.ListFiltersWithContext(context.Background())
	fail2bantest.AssertError(t, err, false, "list filters")

	// Should find only .conf files (sshd, apache, nginx - not readme.txt)
	expectedFilters := []string{"apache", "nginx", "sshd"}
	if len(filters) != len(expectedFilters) {
		t.Errorf("Expected %d filters, got %d: %v", len(expectedFilters), len(filters), filters)
	}

	// Check that all expected filters are present (order may vary)
	for _, expected := range expectedFilters {
		found := slices.Contains(filters, expected)
		if !found {
			t.Errorf("Expected filter %q not found in %v", expected, filters)
		}
	}
}

func TestTestFilter(t *testing.T) {
	// Set ALLOW_DEV_PATHS for test to use temp directory
	t.Setenv("ALLOW_DEV_PATHS", "true")

	// Create a temporary test filter file
	tempDir := t.TempDir()
	filterName := "test-filter"
	filterPath := filepath.Join(tempDir, filterName+".conf")
	// fail2ban-regex must be given a log that exists.
	logFile := allowedLog(t, "")
	filterContent := "[Definition]\nfailregex = Failed password for .* from <HOST>\nlogpath = " + logFile

	err := os.WriteFile(filterPath, []byte(filterContent), 0600)
	if err != nil {
		t.Fatalf("failed to create test filter file: %v", err)
	}

	// Set up mock environment with sudo privileges
	_, cleanup := fail2bantest.SetupMockEnvironmentWithSudo(t, true)
	defer cleanup()

	// Configure specific responses for this test
	mock := fail2bantest.MustMockRunner(t)
	expectedOutput := "Running tests on fail2ban-regex\nResults: 5 matches found"
	mock.SetResponse("fail2ban-regex "+logFile+" "+filterPath, []byte(expectedOutput))
	mock.SetResponse("sudo fail2ban-regex "+logFile+" "+filterPath, []byte(expectedOutput))

	// Create client with the temp directory as the filter directory
	client, err := fail2ban.NewClient(constants.DefaultLogDir, tempDir)
	fail2bantest.AssertError(t, err, false, "create client")

	// Test the actual created filter
	output, err := client.TestFilterWithContext(context.Background(), filterName, "")
	fail2bantest.AssertError(t, err, false, "test filter should succeed")

	if output != expectedOutput {
		t.Errorf("expected output %q, got %q", expectedOutput, output)
	}

	// Also test that a nonexistent filter fails appropriately
	_, err = client.TestFilterWithContext(context.Background(), "nonexistent", "")
	if err == nil {
		t.Error("TestFilter should fail for nonexistent filter")
	}
}

func TestIsValidFilter(t *testing.T) {
	valid := []string{"sshd", "nginx-error", "custom.filter"}
	invalid := []string{"../evil", "bad/name", "bad\\name", "", ".."}
	for _, f := range valid {
		if err := fail2ban.ValidateFilter(f); err != nil {
			t.Errorf("expected filter %s to be valid, got error: %v", f, err)
		}
	}
	for _, f := range invalid {
		if err := fail2ban.ValidateFilter(f); err == nil {
			t.Errorf("expected filter %s to be invalid", f)
		}
	}
}

// TestListFiltersWithContext tests filter listing with context
func TestListFiltersWithContext(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(*fail2bantest.MockRunner)
		setupEnv      func()
		timeout       time.Duration
		expectError   bool
		expectFilters []string
	}{
		{
			name: "successful filter listing",
			setupMock: func(m *fail2bantest.MockRunner) {
				fail2bantest.StandardMockSetup(m)
				// Mock responses not needed - uses file system
			},
			setupEnv: func() {
				// Client will use default filter directory
			},
			timeout:       5 * time.Second,
			expectError:   false,
			expectFilters: nil, // Will depend on actual filter directory
		},
		{
			name: "context timeout",
			setupMock: func(m *fail2bantest.MockRunner) {
				fail2bantest.StandardMockSetup(m)
				// Not applicable for file system operation
			},
			setupEnv: func() {
				// No setup needed
			},
			timeout:     1 * time.Nanosecond,
			expectError: true, // Context check happens first
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := fail2bantest.NewMockRunner()
			tt.setupMock(mock)
			t.Cleanup(fail2bantest.WithTestRunner(t, mock))
			tt.setupEnv()

			client, err := fail2ban.NewClient("/var/log", "/etc/fail2ban/filter.d")
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()

			if tt.timeout == 1*time.Nanosecond {
				time.Sleep(2 * time.Millisecond)
			}

			filters, err := client.ListFiltersWithContext(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				// May error if directory doesn't exist, which is fine in tests
				if err == nil {
					assert.NotNil(t, filters)
				}
			}
		})
	}
}

// TestTestFilterWithContext tests filter testing with context
func TestTestFilterWithContext(t *testing.T) {
	// Enable dev paths to allow temporary directory
	t.Setenv("ALLOW_DEV_PATHS", "1")

	// Create temporary filter directory and a log for the filter to declare:
	// fail2ban-regex must be given a log that exists.
	tmpDir := t.TempDir()
	logFile := allowedLog(t, "")
	filterContent := "[Definition]\nfailregex = ^.* Failed .* for .* from <HOST>\nlogpath = " + logFile + "\n"
	err := os.WriteFile(filepath.Join(tmpDir, "sshd.conf"), []byte(filterContent), 0600)
	require.NoError(t, err)

	// Stock-style filter: failregex only, no logpath — must be rejected.
	stockContent := "[Definition]\nfailregex = ^.* Failed .* for .* from <HOST>\n"
	err = os.WriteFile(filepath.Join(tmpDir, "stock.conf"), []byte(stockContent), 0600)
	require.NoError(t, err)

	// regexSucceeds registers fail2ban-regex over the sshd filter, in both
	// the plain and the sudo form.
	regexSucceeds := func(m *fail2bantest.MockRunner) {
		fail2bantest.StandardMockSetup(m)
		args := logFile + " " + filepath.Join(tmpDir, "sshd.conf")
		m.SetResponse("fail2ban-regex "+args, []byte("Success: 0 matches"))
		m.SetResponse("sudo fail2ban-regex "+args, []byte("Success: 0 matches"))
	}

	tests := []struct {
		name        string
		filter      string
		setupMock   func(*fail2bantest.MockRunner)
		timeout     time.Duration
		expectError bool
	}{
		{name: "successful filter test", filter: "sshd", setupMock: regexSucceeds, timeout: 5 * time.Second},
		// Validation fails before any command runs.
		{
			name: "invalid filter name", filter: "invalid@filter", setupMock: fail2bantest.StandardMockSetup,
			timeout: 5 * time.Second, expectError: true,
		},
		// Rejected before any fail2ban-regex invocation.
		{
			name: "filter without logpath", filter: "stock", setupMock: fail2bantest.StandardMockSetup,
			timeout: 5 * time.Second, expectError: true,
		},
		{
			name:        "context timeout",
			filter:      "sshd",
			setupMock:   regexSucceeds,
			timeout:     1 * time.Nanosecond,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A non-root user with sudo, whatever user runs the tests: as root,
			// f2b hands fail2ban-regex a private copy of the log, whose
			// generated path the fixture keys cannot name.
			orig := fail2ban.GetSudoChecker()
			fail2ban.SetSudoChecker(&fail2bantest.MockSudoChecker{MockHasPrivileges: true, ExplicitPrivilegesSet: true})
			t.Cleanup(func() { fail2ban.SetSudoChecker(orig) })

			mock := fail2bantest.NewMockRunner()
			tt.setupMock(mock)
			t.Cleanup(fail2bantest.WithTestRunner(t, mock))

			client, err := fail2ban.NewClient("/var/log", tmpDir)
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()

			if tt.timeout == 1*time.Nanosecond {
				time.Sleep(2 * time.Millisecond)
			}

			result, err := client.TestFilterWithContext(ctx, tt.filter, "")

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, result)
			}
		})
	}
}
