package cmd

import "testing"

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
