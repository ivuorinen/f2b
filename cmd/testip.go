package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// TestIPCmd returns the test command with injected client and config
func TestIPCmd(client interface {
	BannedIn(string) ([]string, error)
}, format string) *cobra.Command {
	return &cobra.Command{
		Use:   "test <ip>",
		Short: "Test if an IP is banned",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				PrintError(fmt.Errorf("IP address required"))
				return fmt.Errorf("IP address required")
			}
			ip := args[0]
			jails, err := client.BannedIn(ip)
			if err != nil {
				PrintError(err)
				return err
			}
			if len(jails) == 0 {
				PrintOutputTo(GetCmdOutput(cmd), fmt.Sprintf("IP %s is not banned", ip), format)
			} else {
				PrintOutputTo(GetCmdOutput(cmd), fmt.Sprintf("IP %s is banned in: %v", ip, jails), format)
			}
			return nil
		},
	}
}
