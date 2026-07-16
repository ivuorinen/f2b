package cmd

import (
	"context"

	"github.com/spf13/cobra"
)

// TestIPCmd returns the test command with injected client and config
func TestIPCmd(client interface {
	BannedInWithContext(context.Context, string) ([]string, error)
}, config *Config) *cobra.Command {
	return NewCommand("test <ip>", "Test if an IP is banned", nil, func(cmd *cobra.Command, args []string) error {
		// Create timeout context for testing IP
		ctx, cancel := createTimeoutContext(cmd.Context(), config)
		defer cancel()

		// Validate IP argument
		ip, err := ValidateIPArgumentWithContext(ctx, args)
		if err != nil {
			return HandleValidationError(err)
		}

		jails, err := client.BannedInWithContext(ctx, ip)
		if err != nil {
			return HandleClientError(err)
		}

		result := FormatBannedResult(ip, jails)
		PrintOutputTo(GetCmdOutput(cmd), result, config.Format)
		return nil
	})
}
