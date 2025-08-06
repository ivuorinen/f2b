package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version holds the build version and can be overridden at build time with ldflags
var Version = "dev"

// VersionCmd returns the version command with output consistency
func VersionCmd(config *Config) *cobra.Command {
	cmd := NewCommand("version", "Show f2b version", nil, func(cmd *cobra.Command, _ []string) error {
		PrintOutputTo(GetCmdOutput(cmd), fmt.Sprintf("f2b version %s", Version), config.Format)
		return nil
	})

	// Override Run to keep existing behavior (no error handling for version)
	cmd.Run = func(cmd *cobra.Command, _ []string) {
		PrintOutputTo(GetCmdOutput(cmd), fmt.Sprintf("f2b version %s", Version), config.Format)
	}
	cmd.RunE = nil

	return cmd
}
