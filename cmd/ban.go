// Package cmd contains the command packages for the f2b tool.
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// BanCmd returns the ban command with injected client and config
func BanCmd(client fail2ban.Client, config *Config) *cobra.Command {
	return NewCommand("ban <ip> [jail]", "Ban an IP address", []string{"banip", "b"},
		func(cmd *cobra.Command, args []string) error {
			// Get the contextual logger
			logger := GetContextualLogger()

			// Create timeout context for the entire ban operation
			ctx, cancel := context.WithTimeout(context.Background(), config.CommandTimeout)
			defer cancel()

			// Add command context
			ctx = WithCommand(ctx, "ban")

			// Log operation with timing
			return logger.LogOperation(ctx, "ban_command", func() error {
				// Validate IP argument
				ip, err := ValidateIPArgument(args)
				if err != nil {
					return PrintErrorAndReturn(err)
				}

				// Add IP to context
				ctx = WithIP(ctx, ip)

				// Get jails from arguments or client (with timeout context)
				jails, err := GetJailsFromArgsWithContext(ctx, client, args, 1)
				if err != nil {
					return HandleClientError(err)
				}

				// Process ban operation with timeout context (use parallel processing for multiple jails)
				var results []OperationResult
				if len(jails) > 1 {
					// Use parallel timeout for multi-jail operations
					parallelCtx, parallelCancel := context.WithTimeout(ctx, config.ParallelTimeout)
					defer parallelCancel()
					results, err = ProcessBanOperationParallelWithContext(parallelCtx, client, ip, jails)
				} else {
					results, err = ProcessBanOperationWithContext(ctx, client, ip, jails)
				}
				if err != nil {
					return HandleClientError(err)
				}

				// Read the format flag and override config.Format if set
				format, _ := cmd.Flags().GetString("format")
				if format != "" {
					config.Format = format
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
		})
}
