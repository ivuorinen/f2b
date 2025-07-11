package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
		}
	default:
		if _, err := fmt.Fprintln(w, data); err != nil {
			Logger.WithError(err).Error("Failed to write plain output")
		}
	}
}

// PrintError logs and prints an error to stderr in a consistent way.
func PrintError(err error) {
	if err == nil {
		return
	}
	Logger.WithError(err).Error("Command failed")
	fmt.Fprintln(os.Stderr, "Error:", err)
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
