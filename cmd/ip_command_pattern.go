// Package cmd provides command pattern abstractions to reduce code duplication.
// This module handles common patterns for IP-based operations (ban/unban) that
// share identical structure but different processing functions.
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// IPCommandConfig holds configuration for IP-based commands
type IPCommandConfig struct {
	CommandName   string   // e.g., "ban", "unban"
	Usage         string   // e.g., "ban <ip> [jail]"
	Description   string   // e.g., "Ban an IP address"
	Aliases       []string // e.g., ["banip", "b"]
	OperationName string   // e.g., "ban_command", "unban_command"
	// SingleOp handles the one-jail path; ParallelOp handles the multi-jail
	// path. Both are wrapped in processWithValidation before executing.
	SingleOp   multiJailOperationFunc
	ParallelOp multiJailOperationFunc
}

// resolveOutputFormat determines the final output format from config and command flags
func resolveOutputFormat(config *Config, cmd *cobra.Command) string {
	finalFormat := ""
	if config != nil {
		finalFormat = config.Format
	}
	format, _ := cmd.Flags().GetString(constants.FlagFormat)
	if format != "" {
		finalFormat = format
	}
	return finalFormat
}

// outputOperationResults outputs the operation results in the specified format
func outputOperationResults(cmd *cobra.Command, results []OperationResult, _ *Config, format string) error {
	if format == JSONFormat {
		// Use the format resolved by the caller directly; routing through
		// OutputResults would re-derive it from config.Format and silently
		// print plain whenever the two diverge.
		PrintOutputTo(GetCmdOutput(cmd), results, format)
		return nil
	}

	for _, r := range results {
		if _, err := fmt.Fprintf(GetCmdOutput(cmd), "%s %s in %s\n", r.Status, r.IP, r.Jail); err != nil {
			return err
		}
	}
	return nil
}

// processIPOperation handles the parallel vs single processing logic.
// rootCtx is the un-CommandTimeout'd request context; opCtx carries the
// per-command timeout. The multi-jail budget must derive from rootCtx, not
// opCtx: a context cannot outlive its parent, so wrapping the CommandTimeout
// context with ParallelTimeout previously capped the batch at
// min(CommandTimeout, ParallelTimeout) and made F2B_PARALLEL_TIMEOUT a no-op
// whenever it exceeded F2B_COMMAND_TIMEOUT.
func processIPOperation(
	rootCtx, opCtx context.Context,
	config *Config,
	cmdConfig IPCommandConfig,
	client fail2ban.Client,
	ip string,
	jails []string,
) ([]OperationResult, error) {
	if len(jails) > 1 {
		parallelCtx, parallelCancel := context.WithTimeout(rootCtx, config.ParallelTimeout)
		defer parallelCancel()
		return processWithValidation(parallelCtx, client, ip, jails, cmdConfig.ParallelOp)
	}
	return processWithValidation(opCtx, client, ip, jails, cmdConfig.SingleOp)
}

// ExecuteIPCommand provides a unified execution pattern for IP-based commands
func ExecuteIPCommand(
	client fail2ban.Client,
	config *Config,
	cmdConfig IPCommandConfig,
) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		logger := GetContextualLogger()

		// cmd.Context() inherits Cobra's signal cancellation; runIPOperation
		// reaches it again via cmd.Context() so the multi-jail parallel path
		// can use the full ParallelTimeout rather than being capped by
		// CommandTimeout.
		ctx, cancel := createTimeoutContext(cmd.Context(), config)
		defer cancel()
		ctx = WithCommand(ctx, cmdConfig.CommandName)

		return logger.LogOperation(ctx, cmdConfig.OperationName, func() error {
			return runIPOperation(ctx, cmd, client, config, cmdConfig, args)
		})
	}
}

// runIPOperation executes the validated IP command body: validate the IP and
// jails, run the per-jail operation, and print results (including partial
// results when the operation fails after changing some jails).
func runIPOperation(
	ctx context.Context,
	cmd *cobra.Command,
	client fail2ban.Client,
	config *Config,
	cmdConfig IPCommandConfig,
	args []string,
) error {
	ip, err := ValidateIPArgumentWithContext(ctx, args)
	if err != nil {
		return HandleValidationError(err)
	}
	ctx = WithIP(ctx, ip)

	jails, err := GetJailsFromArgsWithContext(ctx, client, args, 1)
	if err != nil {
		return HandleClientError(err)
	}
	// Guard against a silent no-op: with no jail argument and no jails
	// configured, the operation loop would run zero times and report success
	// without banning anything.
	if len(jails) == 0 {
		return HandleValidationError(
			fmt.Errorf("no jails configured; nothing to %s", cmdConfig.CommandName),
		)
	}

	// processIPOperation takes the signal-scoped root context (cmd.Context())
	// for its parallel path plus the timeout ctx for single-jail work.
	results, err := processIPOperation(cmd.Context(), ctx, config, cmdConfig, client, ip, jails)
	finalFormat := resolveOutputFormat(config, cmd)
	if err != nil {
		// Partial failure still changed firewall state in the jails that
		// succeeded — show the per-jail results (failed jails carry the error
		// in their Status) before reporting the error.
		if len(results) > 0 {
			if outErr := outputOperationResults(cmd, results, config, finalFormat); outErr != nil {
				Logger.WithError(outErr).Warn("failed to print partial results")
			}
		}
		return HandleClientError(err)
	}
	return outputOperationResults(cmd, results, config, finalFormat)
}

// NewIPCommand creates a new IP-based command using the unified pattern
func NewIPCommand(client fail2ban.Client, config *Config, cmdConfig IPCommandConfig) *cobra.Command {
	c := NewCommand(
		cmdConfig.Usage,
		cmdConfig.Description,
		cmdConfig.Aliases,
		ExecuteIPCommand(client, config, cmdConfig),
	)
	// <ip> [jail]: a third argument was previously ignored without any
	// message ("f2b ban 1.2.3.4 sshd apache" silently skipped apache).
	c.Args = cobra.MaximumNArgs(2)
	return c
}
