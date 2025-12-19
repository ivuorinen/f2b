package cmd

import "github.com/ivuorinen/f2b/fail2ban"

// initLogging configures logging for the application
// This replaces the automatic init() side effect from fail2ban package
func initLogging() {
	fail2ban.ConfigureCITestLogging()
}
