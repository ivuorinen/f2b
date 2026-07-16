// Package cmd provides output formatting and display utilities for the f2b CLI.
// This package handles structured output in both plain text and JSON formats,
// supporting consistent CLI output patterns across all commands.
package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

const (
	// JSONFormat represents the JSON output format
	JSONFormat = "json"
	// PlainFormat represents the plain text output format
	PlainFormat = "plain"
)

// Logger is the global logger for the CLI. It writes human-readable text to
// os.Stderr and satisfies fail2ban.LoggerInterface, so the fail2ban package
// logs through it (wired in main).
var Logger = fail2ban.NewSlogLogger(fail2ban.SlogText)

func init() {
	// Reduce log verbosity in CI/test environments. The logger already writes
	// text to os.Stderr by construction.
	configureCIFriendlyLogging()
}

// configureCIFriendlyLogging sets appropriate log levels for CI/test environments
func configureCIFriendlyLogging() {
	// Detect CI environments by checking common CI environment variables
	// If in CI or test environment, reduce logging noise unless explicitly overridden
	if (IsCI() || IsTestEnvironment()) && os.Getenv("F2B_LOG_LEVEL") == "" && os.Getenv("F2B_VERBOSE_TESTS") == "" {
		Logger.SetLevel(slog.LevelError)
	}
}

// PrintOutput prints data to stdout in the specified format (PlainFormat or JSONFormat).
func PrintOutput(data any, format string) {
	switch format {
	case JSONFormat:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			Logger.WithError(err).Error(constants.MsgFailedToEncodeJSON)
			// Fallback goes to stderr: injecting plain text into the JSON
			// stream would corrupt it for downstream consumers (jq etc.).
			if _, printErr := fmt.Fprintln(os.Stderr, data); printErr != nil {
				Logger.WithError(printErr).Error(constants.MsgFailedToWriteOutput)
			}
		}
	default:
		fmt.Println(data)
	}
}

// PrintOutputTo prints data to the specified writer in the given format.
func PrintOutputTo(w io.Writer, data any, format string) {
	switch format {
	case JSONFormat:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			Logger.WithError(err).Error(constants.MsgFailedToEncodeJSON)
			// Fallback goes to stderr: injecting plain text into the JSON
			// stream would corrupt it for downstream consumers (jq etc.).
			if _, printErr := fmt.Fprintln(os.Stderr, data); printErr != nil {
				Logger.WithError(printErr).Error(constants.MsgFailedToWriteOutput)
			}
		}
	default:
		if _, err := fmt.Fprintln(w, data); err != nil {
			Logger.WithError(err).Error("Failed to write plain output")
		}
	}
}

// printedError marks an error that was already reported to the user via
// PrintError, so main doesn't print it a second time. Unwrap keeps
// errors.Is/errors.As working on the underlying error.
type printedError struct{ error }

func (p printedError) Unwrap() error { return p.error }

// IsPrinted reports whether err (or an error it wraps) was already reported
// to the user by an error handler. main prints unmarked errors before exiting
// so cobra/config failures aren't silent under SilenceErrors.
func IsPrinted(err error) bool {
	var p printedError
	return errors.As(err, &p)
}

// PrintError logs and prints an error to stderr with enhanced context if available.
func PrintError(err error) {
	if err == nil {
		return
	}

	// Check if error provides enhanced context
	if contextErr, ok := errors.AsType[*fail2ban.ContextualError](err); ok {
		Logger.WithFields(map[string]any{
			"error":    err.Error(),
			"category": string(contextErr.GetCategory()),
		}).Error(constants.MsgCommandFailed)

		fmt.Fprintln(os.Stderr, constants.ErrorPrefix, err)
		if remediation := contextErr.GetRemediation(); remediation != "" {
			fmt.Fprintln(os.Stderr, "Hint:", remediation)
		}
	} else {
		Logger.WithError(err).Error(constants.MsgCommandFailed)
		fmt.Fprintln(os.Stderr, constants.ErrorPrefix, err)
	}
}

// GetCmdOutput returns the command's output writer if available, otherwise os.Stdout
func GetCmdOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil && cmd.OutOrStdout() != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}
