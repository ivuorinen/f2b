package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// UnbanCmd returns the unban command with injected client and config
func UnbanCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewCommand(
		"unban <ip> [jail]",
		"Unban an IP address",
		[]string{"unbanip", "ub"},
		func(cmd *cobra.Command, args []string) error {
			// Create timeout context for the entire unban operation
			ctx, cancel := context.WithTimeout(context.Background(), config.CommandTimeout)
			defer cancel()

			// Validate IP argument
			ip, err := ValidateIPArgument(args)
			if err != nil {
				return PrintErrorAndReturn(err)
			}

			// Get jails from arguments or client (with timeout context)
			jails, err := GetJailsFromArgsWithContext(ctx, client, args, 1)
			if err != nil {
				return HandleClientError(err)
			}

			// Process unban operation with timeout context (use parallel processing for multiple jails)
			var results []OperationResult
			if len(jails) > 1 {
				// Use parallel timeout for multi-jail operations
				parallelCtx, parallelCancel := context.WithTimeout(ctx, config.ParallelTimeout)
				defer parallelCancel()
				results, err = ProcessUnbanOperationParallelWithContext(parallelCtx, client, ip, jails)
			} else {
				results, err = ProcessUnbanOperationWithContext(ctx, client, ip, jails)
			}
			if err != nil {
				return HandleClientError(err)
			}

			// Output results
			if config != nil && config.Format == JSONFormat {
				PrintOutputTo(GetCmdOutput(cmd), results, JSONFormat)
			} else {
				for _, r := range results {
					if _, err := fmt.Fprintf(GetCmdOutput(cmd), "%s %s in %s\n", r.Status, r.IP, r.Jail); err != nil {
						return err
					}
				}
			}
			return nil
		})
}
