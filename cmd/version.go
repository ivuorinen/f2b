package cmd

import (
	"github.com/spf13/cobra"
)

// VersionCmd returns the version command with output consistency
func VersionCmd(format string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show f2b version",
		Run: func(cmd *cobra.Command, args []string) {
			PrintOutputTo(GetCmdOutput(cmd), "f2b version 1.0.0", format)
		},
	}
}
