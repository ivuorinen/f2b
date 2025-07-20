package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version holds the build version and can be overridden at build time with ldflags
var version = "dev"

// VersionCmd returns the version command with output consistency
func VersionCmd(format string) *cobra.Command {
	cmd := NewCommand("version", "Show f2b version", nil, func(cmd *cobra.Command, args []string) error {
		PrintOutputTo(GetCmdOutput(cmd), fmt.Sprintf("f2b version %s", version), format)
		return nil
	})

	// Override Run to keep existing behavior (no error handling for version)
	cmd.Run = func(cmd *cobra.Command, args []string) {
		PrintOutputTo(GetCmdOutput(cmd), fmt.Sprintf("f2b version %s", version), format)
	}
	cmd.RunE = nil

	return cmd
}
