package cmd

import (
	"strings"
	"testing"
)

func TestContainsPathTraversal(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
		category string
	}{
		// Safe paths (should return false)
		{"empty path", "", false, "safe"},
		{"normal path", "/var/log/fail2ban.log", false, "safe"},
		{"relative safe path", "logs/fail2ban.log", false, "safe"},
		{"path with dots in filename", "fail2ban.log.1", false, "safe"},
		{"path with single dot", "./logs", false, "safe"},

		// Basic path traversal (should return true)
		{"basic double dot", "..", true, "basic"},
		{"double dot with slash", "../", true, "basic"},
		{"double dot with backslash", "..\\", true, "basic"},
		{"nested path traversal", "logs/../../../etc/passwd", true, "basic"},
		{"multiple traversals", "../../../etc/passwd", true, "basic"},

		// URL encoded attacks (should return true)
		{"url encoded double dot", "%2e%2e", true, "url_encoded"},
		{"url encoded uppercase", "%2E%2E", true, "url_encoded"},
		{"mixed case url encoding", "%2e%2E", true, "url_encoded"},
		{"mixed case reverse", "%2E%2e", true, "url_encoded"},
		{"url encoded with slash", "%2e%2e%2f", true, "url_encoded"},
		{"url encoded with backslash", "%2e%2e%5c", true, "url_encoded"},
		{"url encoded backslash uppercase", "%2e%2e%5C", true, "url_encoded"},

		// Double URL encoding (should return true)
		{"double url encoded", "%252e%252e", true, "double_encoded"},
		{"double url encoded uppercase", "%252E%252E", true, "double_encoded"},
		{"triple url encoded", "%25252e%25252e", true, "triple_encoded"},

		// Unicode escapes (should return true)
		{"unicode escape", "\\u002e\\u002e", true, "unicode"},
		{"extended unicode escape", "\\u00002e\\u00002e", true, "unicode"},
		{"actual unicode chars", "\u002e\u002e", true, "unicode"},

		// Mixed encoding techniques (should return true)
		{"mixed literal and encoded", "..%2f", true, "mixed"},
		{"mixed encoded dot", ".%2e", true, "mixed"},
		{"reverse mixed encoded", "%2e.", true, "mixed"},
		{"extra dots with slashes", "...//", true, "mixed"},

		// Null byte injection (should return true)
		{"null byte with traversal", "..%00", true, "null_injection"},
		{"null byte literal with dots", "..\x00", true, "null_injection"},

		// Creative separator attacks (should return true)
		{"semicolon separator", "..;/", true, "creative"},
		{"url encoded semicolon", "..%3b", true, "creative"},

		// Complex realistic attack vectors (should return true)
		{"realistic attack 1", "/var/log/../../../etc/passwd", true, "realistic"},
		{"realistic attack 2", "logs/%2e%2e/%2e%2e/etc/passwd", true, "realistic"},
		{"realistic attack 3", "fail2ban.log%00../../../etc/shadow", true, "realistic"},
		{"realistic attack 4", "%252e%252e%252f%252e%252e%252fetc%252fpasswd", true, "realistic"},

		// Edge cases that should be safe
		{"legitimate dots in path", "/var/log/fail2ban.log.1.gz", false, "edge_safe"},
		{"legitimate relative path", "config/fail2ban.conf", false, "edge_safe"},
		{"path with version dots", "/usr/local/go1.21/bin", false, "edge_safe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsPathTraversal(tt.path)
			if result != tt.expected {
				t.Errorf("containsPathTraversal(%q) = %v, expected %v (category: %s)",
					tt.path, result, tt.expected, tt.category)
			}
		})
	}
}

func TestContainsPathTraversalURLDecoding(t *testing.T) {
	// Test that URL decoding works correctly
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"single encoded traversal", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", true},
		{"double encoded traversal", "%252e%252e%252f", true},
		{"mixed single and double", "%2e%252e", true},
		{"encoded null byte", "%2e%2e%00", true},
		{"complex encoded path", "logs%2f%2e%2e%2f%2e%2e%2fetc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsPathTraversal(tt.path)
			if result != tt.expected {
				t.Errorf("containsPathTraversal(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestValidateConfigPathSecurity(t *testing.T) {
	// Test that validateConfigPath properly uses the new security function
	maliciousPaths := []string{
		"../../../etc/passwd",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"logs\\..\\..\\windows\\system32",
		"..%00/etc/shadow",
		"%252e%252e%252f",
	}

	for _, path := range maliciousPaths {
		t.Run("malicious_path_"+path, func(t *testing.T) {
			_, err := validateConfigPath(path, "log")
			if err == nil {
				t.Errorf("validateConfigPath should have rejected malicious path: %s", path)
			}
			if !strings.Contains(err.Error(), "path traversal") {
				t.Errorf("Error should mention path traversal, got: %s", err.Error())
			}
		})
	}
}

func TestValidateConfigPathLegitimate(t *testing.T) {
	// Test that legitimate paths still work
	legitimatePaths := []string{
		"/var/log",
		"/tmp/test-logs",
		"/home/user/logs",
	}

	for _, path := range legitimatePaths {
		t.Run("legitimate_path_"+path, func(t *testing.T) {
			// Note: These might still fail due to other validation (like path existence)
			// but they should NOT fail due to path traversal detection
			if containsPathTraversal(path) {
				t.Errorf("containsPathTraversal should not detect traversal in legitimate path: %s", path)
			}
		})
	}
}

// Benchmark the new security function
func BenchmarkContainsPathTraversal(b *testing.B) {
	testPaths := []string{
		"/var/log/fail2ban.log",
		"../../../etc/passwd",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"logs/fail2ban.log.1",
		"%252e%252e%252f",
	}

	b.ResetTimer()
	for b.Loop() {
		for _, path := range testPaths {
			containsPathTraversal(path)
		}
	}
}
