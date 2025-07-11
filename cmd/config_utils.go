package cmd

import "os"

// NewConfigFromEnv builds Config from environment variables with defaults.
func NewConfigFromEnv() Config {
	cfg := Config{}
	cfg.LogDir = os.Getenv("F2B_LOG_DIR")
	if cfg.LogDir == "" {
		cfg.LogDir = "/var/log"
	}
	cfg.FilterDir = os.Getenv("F2B_FILTER_DIR")
	if cfg.FilterDir == "" {
		cfg.FilterDir = "/etc/fail2ban/filter.d"
	}
	cfg.Format = "plain"
	return cfg
}
