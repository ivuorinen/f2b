package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version holds the build version and can be overridden at build time with ldflags
var version = "dev"

// VersionCmd returns the version command with output consistency
func VersionCmd(format string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show f2b version",
		Run: func(cmd *cobra.Command, args []string) {
			PrintOutputTo(GetCmdOutput(cmd), fmt.Sprintf("f2b version %s", version), format)
		},
	}
}
