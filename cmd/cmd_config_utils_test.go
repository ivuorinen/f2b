package cmd

import (
	"testing"

	"github.com/ivuorinen/f2b/constants"
)

// TestValidateConfigPathSecurity checks that config paths go through the
// fail2ban path policy and its traversal/encoding detection.
func TestValidateConfigPathSecurity(t *testing.T) {
	maliciousPaths := []string{
		"../../../etc/passwd",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"logs\\..\\..\\windows\\system32",
		"..%00/etc/shadow",
		"%252e%252e%252f",
	}

	for _, path := range maliciousPaths {
		t.Run("malicious_path_"+path, func(t *testing.T) {
			if _, err := validateConfigPath(path, constants.PathTypeLog); err == nil {
				t.Errorf("validateConfigPath should have rejected malicious path: %s", path)
			}
		})
	}
}

// TestValidateConfigPathUsesClientPolicy pins that cmd and the client agree:
// cmd's former strings.HasPrefix check had no separator boundary, so /var/logx
// passed here and failed later in fail2ban.ValidateClientLogPath.
func TestValidateConfigPathUsesClientPolicy(t *testing.T) {
	t.Setenv("ALLOW_DEV_PATHS", "")
	tests := []struct {
		path, pathType string
		wantErr        bool
	}{
		{"/var/log", constants.PathTypeLog, false},
		{"/var/log/fail2ban", constants.PathTypeLog, false},
		{"/var/logx", constants.PathTypeLog, true},
		{"/var/logs-evil", constants.PathTypeLog, true},
		{"/home/user/logs", constants.PathTypeLog, true},
		{"/etc/fail2ban", constants.PathTypeLog, true},
		{"/etc/fail2ban/filter.d", constants.PathTypeFilter, false},
		{"/etc/fail2banx", constants.PathTypeFilter, true},
		{"/var/log", constants.PathTypeFilter, true},
		{"config/fail2ban", constants.PathTypeFilter, true},
		{"", constants.PathTypeLog, true},
		{"/var/log", "unknown", true},
	}
	for _, tt := range tests {
		t.Run(tt.pathType+"_"+tt.path, func(t *testing.T) {
			_, err := validateConfigPath(tt.path, tt.pathType)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfigPath(%q, %q) error = %v, wantErr %v", tt.path, tt.pathType, err, tt.wantErr)
			}
		})
	}
}
