package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/fail2ban"
)

const (
	// JSONFormat represents the JSON output format
	JSONFormat = "json"
)

// Logger is the global logger for the CLI.
var Logger = logrus.New()

func init() {
	// Set logrus to output to stderr and use a readable format by default.
	Logger.SetOutput(os.Stderr)
	Logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
}

// PrintOutput prints data to stdout in the specified format ("plain" or "json").
func PrintOutput(data interface{}, format string) {
	switch format {
	case JSONFormat:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			Logger.WithError(err).Error("Failed to encode JSON output")
			// Fallback to plain text output
			if _, printErr := fmt.Fprintln(os.Stdout, data); printErr != nil {
				Logger.WithError(printErr).Error("Failed to write fallback output")
			}
		}
	default:
		fmt.Println(data)
	}
}

// PrintOutputTo prints data to the specified writer in the given format.
func PrintOutputTo(w io.Writer, data interface{}, format string) {
	switch format {
	case JSONFormat:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			Logger.WithError(err).Error("Failed to encode JSON output")
			// Fallback to plain text output
			if _, printErr := fmt.Fprintln(w, data); printErr != nil {
				Logger.WithError(printErr).Error("Failed to write fallback output")
			}
		}
	default:
		if _, err := fmt.Fprintln(w, data); err != nil {
			Logger.WithError(err).Error("Failed to write plain output")
		}
	}
}

// PrintError logs and prints an error to stderr with enhanced context if available.
func PrintError(err error) {
	if err == nil {
		return
	}

	// Check if error provides enhanced context
	var contextErr *fail2ban.ContextualError
	if errors.As(err, &contextErr) {
		Logger.WithFields(map[string]interface{}{
			"error":    err.Error(),
			"category": string(contextErr.GetCategory()),
		}).Error("Command failed")

		fmt.Fprintln(os.Stderr, "Error:", err)
		if remediation := contextErr.GetRemediation(); remediation != "" {
			fmt.Fprintln(os.Stderr, "Hint:", remediation)
		}
	} else {
		Logger.WithError(err).Error("Command failed")
		fmt.Fprintln(os.Stderr, "Error:", err)
	}
}

// PrintErrorf logs and prints a formatted error to stderr.
func PrintErrorf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	Logger.Error(msg)
	fmt.Fprintln(os.Stderr, "Error:", msg)
}

// GetCmdOutput returns the command's output writer if available, otherwise os.Stdout
func GetCmdOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil && cmd.OutOrStdout() != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

// GetCmdError returns the command's error writer if available, otherwise os.Stderr
func GetCmdError(cmd *cobra.Command) io.Writer {
	if cmd != nil && cmd.ErrOrStderr() != nil {
		return cmd.ErrOrStderr()
	}
	return os.Stderr
}
