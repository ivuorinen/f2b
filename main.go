// Package main provides the f2b command-line interface for managing Fail2Ban
// jails and bans with secure sudo handling, input validation, and comprehensive testing.
package main

import (
	"fmt"
	"os"

	"github.com/ivuorinen/f2b/cmd"
	"github.com/ivuorinen/f2b/fail2ban"
)

func main() {
	// Set up centralized logging - the fail2ban package logs through cmd.Logger,
	// which implements fail2ban.LoggerInterface directly (slog-backed).
	fail2ban.SetLogger(cmd.Logger)

	// Reuse the config the cmd package built at init (its flags are bound to
	// that instance); building a second one here just duplicated env-var
	// warning logs.
	config := cmd.EnvConfig()

	// Use a lazily-constructed client: the real fail2ban client is built (and
	// its sudo/service checks run) only when a command actually invokes a
	// client operation. Commands that need no client — help, version,
	// completion, service — therefore work without fail2ban installed, and the
	// client is built after cobra parses --log-dir/--filter-dir.
	client := cmd.NewLazyClient()

	if err := cmd.Execute(client, config); err != nil {
		// Command handlers report their own errors via PrintError; everything
		// else (cobra flag/command errors, config failures) would otherwise be
		// silent because the root command sets SilenceErrors.
		if !cmd.IsPrinted(err) {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		// An interrupted command usually surfaces as a context error, so the
		// signal exit code must win here too — otherwise only commands that
		// return nil on cancellation (logs-watch) ever exited 130/143.
		if code := cmd.SignalExitCode(); code != 0 {
			os.Exit(code)
		}
		os.Exit(1)
	}

	// A signal-interrupted but gracefully completed run (Ctrl-C on logs-watch)
	// exits 130/143 so scripts can tell interruption from success. Exiting
	// here, after Execute's deferred cleanup ran, keeps graceful shutdown
	// (metrics persisted, log file closed) intact.
	if code := cmd.SignalExitCode(); code != 0 {
		os.Exit(code)
	}
}
