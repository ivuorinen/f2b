package fail2ban

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPathTraversalDetection tests detection of various path traversal patterns
func TestPathTraversalDetection(t *testing.T) {
	maliciousPaths := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32",
		"/var/log/../../../etc/shadow",
		"log/../../../root/.ssh/id_rsa",
		"./../../etc/hosts",
		"...//etc/passwd",
		"%2e%2e/%2e%2e/%2e%2e/etc/passwd",               // URL encoded ../../../etc/passwd
		"%2e%2e\\%2e%2e\\%2e%2e\\etc\\passwd",           // URL encoded ..\..\..\etc\passwd
		"/var/log/\u002e\u002e/\u002e\u002e/etc/passwd", // Unicode ..
		"/var/log/\uff0e\uff0e/\uff0e\uff0e/etc/passwd", // Full-width Unicode ..
		"/var/log//../../etc/passwd",
		"/var/log\\\\..\\\\..\\\\etc\\\\passwd",
		"log\x00/../../etc/passwd", // Null byte injection
	}

	tempDir := t.TempDir()
	config := PathSecurityConfig{
		AllowedBasePaths: []string{tempDir},
		MaxPathLength:    4096,
		AllowSymlinks:    false,
		ResolveSymlinks:  true,
	}

	for _, maliciousPath := range maliciousPaths {
		t.Run("malicious_path", func(t *testing.T) {
			_, err := validatePathWithSecurity(maliciousPath, config)
			if err == nil {
				t.Errorf("expected error for malicious path %q, but validation passed", maliciousPath)
			}
		})
	}
}

// TestValidPaths tests that legitimate paths are accepted
func TestValidPaths(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test file
	testFile := filepath.Join(tempDir, "test.log")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	config := PathSecurityConfig{
		AllowedBasePaths: []string{tempDir},
		MaxPathLength:    4096,
		AllowSymlinks:    false,
		ResolveSymlinks:  true,
	}

	validPaths := []string{
		testFile,
		tempDir,
		filepath.Join(tempDir, "subdir/file.log"),
		filepath.Join(tempDir, "app-2024.log"),
		filepath.Join(tempDir, "server_01.log"),
	}

	for _, validPath := range validPaths {
		t.Run("valid_path", func(t *testing.T) {
			result, err := validatePathWithSecurity(validPath, config)
			if err != nil {
				t.Errorf("expected valid path %q to pass validation, got error: %v", validPath, err)
			}
			if !strings.HasPrefix(result, tempDir) {
				t.Errorf("expected result path %q to be within temp dir %q", result, tempDir)
			}
		})
	}
}

// TestSymlinkHandling tests symlink security handling
func TestSymlinkHandling(t *testing.T) {
	tempDir := t.TempDir()

	// Create a regular file
	regularFile := filepath.Join(tempDir, "regular.log")
	if err := os.WriteFile(regularFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create regular file: %v", err)
	}

	// Create a symlink pointing outside the allowed directory
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside.log")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0644); err != nil {
		t.Fatalf("failed to create outside file: %v", err)
	}

	symlinkPath := filepath.Join(tempDir, "dangerous_symlink")
	if err := os.Symlink(outsideFile, symlinkPath); err != nil {
		t.Skipf("failed to create symlink (may not be supported): %v", err)
	}

	// Test with symlinks disabled
	configNoSymlinks := PathSecurityConfig{
		AllowedBasePaths: []string{tempDir},
		MaxPathLength:    4096,
		AllowSymlinks:    false,
		ResolveSymlinks:  true,
	}

	_, err := validatePathWithSecurity(symlinkPath, configNoSymlinks)
	if err == nil {
		t.Error("expected error for symlink when symlinks are disabled")
	}

	// Test with symlinks enabled but resolving
	configWithSymlinks := PathSecurityConfig{
		AllowedBasePaths: []string{tempDir},
		MaxPathLength:    4096,
		AllowSymlinks:    true,
		ResolveSymlinks:  true,
	}

	_, err = validatePathWithSecurity(symlinkPath, configWithSymlinks)
	if err == nil {
		t.Error("expected error for symlink pointing outside allowed directory")
	}
}

// TestFileTypeValidation tests validation of different file types
func TestFileTypeValidation(t *testing.T) {
	tempDir := t.TempDir()

	// Create a regular file
	regularFile := filepath.Join(tempDir, "regular.log")
	if err := os.WriteFile(regularFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create regular file: %v", err)
	}

	// Test regular file (should pass)
	err := validateFileType(regularFile)
	if err != nil {
		t.Errorf("regular file should pass validation: %v", err)
	}

	// Test directory (should pass)
	err = validateFileType(tempDir)
	if err != nil {
		t.Errorf("directory should pass validation: %v", err)
	}

	// Test non-existent file (should pass - files that don't exist yet are allowed)
	nonExistent := filepath.Join(tempDir, "nonexistent.log")
	err = validateFileType(nonExistent)
	if err != nil {
		t.Errorf("non-existent file should pass validation: %v", err)
	}
}

// TestUnicodeNormalization tests unicode character normalization
func TestUnicodeNormalization(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
		name     string
	}{
		{
			input:    "/var/log/\u002e\u002e/passwd",
			expected: "/var/log/../passwd",
			name:     "unicode_dots",
		},
		{
			input:    "/var/log\u002ftest",
			expected: "/var/log/test",
			name:     "unicode_slash",
		},
		{
			input:    "/var\u005clog\u005ctest",
			expected: "/var\\log\\test",
			name:     "unicode_backslash",
		},
		{
			input:    "/var/log/\uff0e\uff0e/passwd",
			expected: "/var/log/../passwd",
			name:     "fullwidth_dots",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := normalizeUnicode(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

// TestPathLengthLimits tests path length validation
func TestPathLengthLimits(t *testing.T) {
	tempDir := t.TempDir()

	// Test normal length path
	normalPath := filepath.Join(tempDir, "normal.log")
	config := PathSecurityConfig{
		AllowedBasePaths: []string{tempDir},
		MaxPathLength:    4096,
		AllowSymlinks:    false,
		ResolveSymlinks:  true,
	}

	_, err := validatePathWithSecurity(normalPath, config)
	if err != nil {
		t.Errorf("normal length path should pass: %v", err)
	}

	// Test extremely long path
	longName := strings.Repeat("a", 5000)
	longPath := filepath.Join(tempDir, longName)

	_, err = validatePathWithSecurity(longPath, config)
	if err == nil {
		t.Error("extremely long path should fail validation")
	}
}

// TestFilterValidation tests the enhanced filter validation
func TestFilterValidation(t *testing.T) {
	validFilters := []string{
		"sshd",
		"apache-auth",
		"nginx_error",
		"postfix.conf",
		"custom@domain",
		"filter+variant",
		"test~backup",
	}

	for _, filter := range validFilters {
		t.Run("valid_filter_"+filter, func(t *testing.T) {
			if !isValidFilter(filter) {
				t.Errorf("filter %q should be valid", filter)
			}
		})
	}

	invalidFilters := []string{
		"",                        // empty
		"../../../etc/passwd",     // path traversal
		"filter/with/slash",       // contains slash
		"filter\\with\\backslash", // contains backslash
		"filter\x00null",          // null byte
		"%2e%2e",                  // URL encoded ..
		"\u002e\u002e",            // Unicode ..
		strings.Repeat("a", 300),  // too long
		"filter|with|pipes",       // dangerous characters
		"filter<script>",          // HTML-like injection
		"filter;command",          // command injection attempt
	}

	for _, filter := range invalidFilters {
		t.Run("invalid_filter", func(t *testing.T) {
			if isValidFilter(filter) {
				t.Errorf("filter %q should be invalid", filter)
			}
		})
	}
}

// TestBasePath​Validation tests base path containment
func TestBasePathValidation(t *testing.T) {
	tempDir1 := t.TempDir()
	tempDir2 := t.TempDir()

	allowedPaths := []string{tempDir1, tempDir2}

	// Test path within allowed directory
	validPath := filepath.Join(tempDir1, "subdir", "file.log")
	err := validateBasePath(validPath, allowedPaths)
	if err != nil {
		t.Errorf("path within allowed directory should pass: %v", err)
	}

	// Test path outside allowed directories
	outsideDir := t.TempDir()
	invalidPath := filepath.Join(outsideDir, "file.log")
	err = validateBasePath(invalidPath, allowedPaths)
	if err == nil {
		t.Error("path outside allowed directories should fail")
	}

	// Test exact match with allowed directory
	err = validateBasePath(tempDir1, allowedPaths)
	if err != nil {
		t.Errorf("exact match with allowed directory should pass: %v", err)
	}
}

// BenchmarkPathValidation benchmarks the path validation performance
func BenchmarkPathValidation(b *testing.B) {
	tempDir := b.TempDir()
	config := PathSecurityConfig{
		AllowedBasePaths: []string{tempDir},
		MaxPathLength:    4096,
		AllowSymlinks:    false,
		ResolveSymlinks:  true,
	}

	testPath := filepath.Join(tempDir, "test.log")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := validatePathWithSecurity(testPath, config)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
