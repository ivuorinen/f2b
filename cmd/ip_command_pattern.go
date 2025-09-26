// Package cmd provides command pattern abstractions to reduce code duplication.
// This module handles common patterns for IP-based operations (ban/unban) that
// share identical structure but different processing functions.
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

// IPOperationProcessor defines the interface for processing IP-based operations
type IPOperationProcessor interface {
	// ProcessSingle processes a single jail operation
	ProcessSingle(ctx context.Context, client fail2ban.Client, ip string, jails []string) ([]OperationResult, error)
	// ProcessParallel processes multiple jails in parallel
	ProcessParallel(ctx context.Context, client fail2ban.Client, ip string, jails []string) ([]OperationResult, error)
}

// IPCommandConfig holds configuration for IP-based commands
type IPCommandConfig struct {
	CommandName   string   // e.g., "ban", "unban"
	Usage         string   // e.g., "ban <ip> [jail]"
	Description   string   // e.g., "Ban an IP address"
	Aliases       []string // e.g., ["banip", "b"]
	OperationName string   // e.g., "ban_command", "unban_command"
	Processor     IPOperationProcessor
}

// ExecuteIPCommand provides a unified execution pattern for IP-based commands
func ExecuteIPCommand(
	client fail2ban.Client,
	config *Config,
	cmdConfig IPCommandConfig,
) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		// Get the contextual logger
		logger := GetContextualLogger()

		// Create timeout context for the entire operation
		ctx, cancel := context.WithTimeout(context.Background(), config.CommandTimeout)
		defer cancel()

		// Add command context
		ctx = WithCommand(ctx, cmdConfig.CommandName)

		// Log operation with timing
		return logger.LogOperation(ctx, cmdConfig.OperationName, func() error {
			// Validate IP argument
			ip, err := ValidateIPArgument(args)
			if err != nil {
				return HandleValidationError(err)
			}

			// Add IP to context
			ctx = WithIP(ctx, ip)

			// Get jails from arguments or client (with timeout context)
			jails, err := GetJailsFromArgsWithContext(ctx, client, args, 1)
			if err != nil {
				return HandleClientError(err)
			}

			// Process operation with timeout context (use parallel processing for multiple jails)
			var results []OperationResult
			if len(jails) > 1 {
				// Use parallel timeout for multi-jail operations
				parallelCtx, parallelCancel := context.WithTimeout(ctx, config.ParallelTimeout)
				defer parallelCancel()
				results, err = cmdConfig.Processor.ProcessParallel(parallelCtx, client, ip, jails)
			} else {
				results, err = cmdConfig.Processor.ProcessSingle(ctx, client, ip, jails)
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
				OutputResults(cmd, results, config)
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
}

// NewIPCommand creates a new IP-based command using the unified pattern
func NewIPCommand(client fail2ban.Client, config *Config, cmdConfig IPCommandConfig) *cobra.Command {
	return NewCommand(
		cmdConfig.Usage,
		cmdConfig.Description,
		cmdConfig.Aliases,
		ExecuteIPCommand(client, config, cmdConfig),
	)
}
