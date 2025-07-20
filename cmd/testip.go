package cmd

import (
	"github.com/spf13/cobra"
)

// TestIPCmd returns the test command with injected client and config
func TestIPCmd(client interface {
	BannedIn(string) ([]string, error)
}, format string) *cobra.Command {
	return NewCommand("test <ip>", "Test if an IP is banned", nil, func(cmd *cobra.Command, args []string) error {
		// Validate IP argument
		ip, err := ValidateIPArgument(args)
		if err != nil {
			return PrintErrorAndReturn(err)
		}

		jails, err := client.BannedIn(ip)
		if err != nil {
			return HandleClientError(err)
		}

		result := FormatBannedResult(ip, jails)
		PrintOutputTo(GetCmdOutput(cmd), result, format)
		return nil
	})
}
