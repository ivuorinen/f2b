// f2b main package
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ivuorinen/f2b/cmd"
	"github.com/ivuorinen/f2b/fail2ban"
)

func main() {
	args := os.Args
	var client fail2ban.Client
	var err error

	// Build config from env/flags
	config := cmd.NewConfigFromEnv()

	skip := false
	if len(args) > 1 {
		skip = cmd.IsSkipCommand(args[1])
	}

	if !skip {
		client, err = fail2ban.NewClient(config.LogDir, config.FilterDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			// Check if this is a sudo privilege error
			if strings.Contains(err.Error(), "fail2ban operations require sudo privileges") {
				fmt.Fprintln(os.Stderr, "Hint: Try running with 'sudo' or ensure your user is in the sudo group")
				fmt.Fprintln(os.Stderr, "Example: sudo", strings.Join(os.Args, " "))
			}
			os.Exit(1)
		}
	} else {
		// Use a no-op client for skip-only commands to prevent nil-pointer dereferences
		client = fail2ban.NewNoOpClient()
	}

	if err := cmd.Execute(client, config); err != nil {
		os.Exit(1)
	}
}
