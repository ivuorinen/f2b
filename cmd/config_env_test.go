package cmd

import (
	"testing"

	"github.com/ivuorinen/f2b/constants"
)

// TestExplicitInvalidLogDirFailsFast verifies an explicitly-set but invalid
// F2B_LOG_DIR is a fatal config error rather than a silent fallback.
func TestExplicitInvalidLogDirFailsFast(t *testing.T) {
	t.Setenv("F2B_LOG_DIR", "/srv/definitely-not-allowed")
	cfg := NewConfigFromEnv()
	if cfg.configErr == nil {
		t.Fatal("expected a config error for an explicitly-set invalid F2B_LOG_DIR")
	}
	if err := Execute(NewLazyClient(), cfg); err == nil {
		t.Fatal("Execute should return the config error and not run commands")
	}
}

// TestUnsetDirsDoNotError verifies that leaving the dir env vars unset uses the
// (valid) defaults without producing a config error.
func TestUnsetDirsDoNotError(t *testing.T) {
	t.Setenv("F2B_LOG_DIR", "")
	t.Setenv("F2B_FILTER_DIR", "")
	if cfg := NewConfigFromEnv(); cfg.configErr != nil {
		t.Fatalf("unset dir env vars should not error: %v", cfg.configErr)
	}
}

// TestNewConfigFromEnvAppliesValidOverride pins the success path of an
// explicit override: valid F2B_LOG_DIR/F2B_FILTER_DIR values must reach the
// config, not be replaced by the defaults.
func TestNewConfigFromEnvAppliesValidOverride(t *testing.T) {
	t.Setenv("ALLOW_DEV_PATHS", "")
	const logDir, filterDir = "/var/log/fail2ban", "/etc/fail2ban/custom-filter.d"
	t.Setenv("F2B_LOG_DIR", logDir)
	t.Setenv("F2B_FILTER_DIR", filterDir)

	wantLog, err := validateConfigPath(logDir, constants.PathTypeLog)
	if err != nil {
		t.Fatalf("fixture log dir rejected: %v", err)
	}
	wantFilter, err := validateConfigPath(filterDir, constants.PathTypeFilter)
	if err != nil {
		t.Fatalf("fixture filter dir rejected: %v", err)
	}

	cfg := NewConfigFromEnv()
	if cfg.configErr != nil {
		t.Fatalf("valid overrides produced a config error: %v", cfg.configErr)
	}
	if cfg.LogDir != wantLog || cfg.LogDir == constants.DefaultLogDir {
		t.Errorf("LogDir = %q, want the override %q", cfg.LogDir, wantLog)
	}
	if cfg.FilterDir != wantFilter || cfg.FilterDir == constants.DefaultFilterDir {
		t.Errorf("FilterDir = %q, want the override %q", cfg.FilterDir, wantFilter)
	}
}
