package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/constants"
)

// Version holds the build version and can be overridden at build time with ldflags
var Version = "dev"

// VersionCmd returns the version command with output consistency
func VersionCmd(config *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   constants.CLICmdVersion,
		Short: "Show f2b version",
		Run: func(cmd *cobra.Command, _ []string) {
			PrintOutputTo(GetCmdOutput(cmd), fmt.Sprintf(constants.VersionFormat, Version), config.Format)
		},
	}

	return cmd
}
