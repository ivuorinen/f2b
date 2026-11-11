package fail2ban_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

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
	filterContent := `[Definition]
failregex = Failed password for .* from <HOST>
logpath = /var/log/auth.log`

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
	mock.SetResponse("fail2ban-regex /var/log/auth.log "+filterPath, []byte(expectedOutput))
	mock.SetResponse("sudo fail2ban-regex /var/log/auth.log "+filterPath, []byte(expectedOutput))

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
