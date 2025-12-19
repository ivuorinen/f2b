package cmd

// initLogging configures logging for the application
// This replaces the automatic init() side effect from fail2ban package
// Note: fail2ban.ConfigureCITestLogging() is not needed here because:
// 1. cmd/output.go's init() already calls configureCIFriendlyLogging()
// 2. main.go sets fail2ban.SetLogger to use cmd.Logger
// 3. Therefore fail2ban uses the same logger that's already configured
func initLogging() {
	// No-op: logging is configured by cmd/output.go's init() and main.go's fail2ban.SetLogger()
}
