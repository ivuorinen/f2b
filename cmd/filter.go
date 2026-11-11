package cmd

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestFilterCmd returns the test-filter command with injected client and config
func TestFilterCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return withArgs(cobra.MaximumNArgs(2), NewCommand(
		"test-filter <filter> [logfile]",
		"Test a Fail2Ban filter against a log file (required for filters that declare no logpath)",
		nil,
		func(cmd *cobra.Command, args []string) error {
			// Create timeout context for filter testing (use file timeout as it involves file operations)
			ctx, cancel := context.WithTimeout(cmd.Context(), config.FileTimeout)
			defer cancel()

			if len(args) < 1 {
				filters, err := client.ListFiltersWithContext(ctx)
				if err != nil {
					return HandleClientError(err)
				}
				if err := PrintOutputTo(
					GetCmdOutput(cmd), "Available filters: "+strings.Join(filters, ", "), config.Format,
				); err != nil {
					return err
				}
				return HandleClientError(fail2ban.ErrFilterRequiredError)
			}

			filterName := args[0]
			if err := RequireNonEmptyArgument(filterName, "filter name"); err != nil {
				return HandleValidationError(err)
			}

			// Same validator the client applies, so every filter ListFilters
			// prints (e.g. "foo.bar") is also accepted here; a stricter
			// cmd-only check rejected names the listing had just offered.
			if err := fail2ban.ValidateFilter(filterName); err != nil {
				return HandleValidationError(err)
			}

			out, err := client.TestFilterWithContext(ctx, filterName, ParseOptionalArgs(args, 2)[1])
			if err != nil {
				return HandleClientError(err)
			}

			// fail2ban-regex echoes the log lines it reads.
			return printLogText(GetCmdOutput(cmd), out, config.Format)
		}))
}
