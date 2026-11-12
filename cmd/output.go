// Output formatting for the f2b CLI in plain text and JSON.

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

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
// os.Stderr until PersistentPreRunE chooses the format, and satisfies
// fail2ban.LoggerEntry, so the fail2ban package logs through it (wired in main).
var Logger = fail2ban.NewSlogLogger(fail2ban.SlogText)

// PrintOutput prints data to stdout in the specified format (PlainFormat or JSONFormat).
func PrintOutput(data any, format string) error {
	return PrintOutputTo(os.Stdout, data, format)
}

// PrintOutputTo writes data to w in the given format and returns any encode or
// write error. Commands return it, so a failed write (full disk, closed pipe)
// fails the command instead of exiting 0 with truncated output. Nothing is
// written to w on an encode error, so JSON consumers never see a partial
// document mixed with fallback text.
func PrintOutputTo(w io.Writer, data any, format string) error {
	if format == JSONFormat {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			return fmt.Errorf("%s: %w", constants.MsgFailedToEncodeJSON, err)
		}
		return nil
	}
	if _, err := fmt.Fprintln(w, data); err != nil {
		return fmt.Errorf("%s: %w", constants.MsgFailedToWriteOutput, err)
	}
	return nil
}

// escapeControlChars replaces every control character in s except tab and
// newline (C0, DEL and C1) with a visible \xHH escape, for plain output of
// log-derived text: a log line could otherwise retitle the terminal, move the
// cursor or hide lines. A byte that is not valid UTF-8 is judged on its own, so
// a raw 8-bit C1 byte, which 8-bit terminals act on, is escaped too. JSON
// output needs none of this: the encoder escapes control characters.
func escapeControlChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			r = rune(s[i])
		}
		if unicode.IsControl(r) && r != '\t' && r != '\n' {
			fmt.Fprintf(&b, `\x%02x`, r)
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
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

// writesToStderr reports whether the log output w is os.Stderr. A record of a
// failure whose error is returned would there repeat the Error: line printed
// for it, so such records are written only to another sink (a --log-file).
func writesToStderr(w io.Writer) bool {
	return w == io.Writer(os.Stderr)
}

// PrintError logs and prints an error to stderr with enhanced context if available.
func PrintError(err error) {
	if err == nil {
		return
	}

	contextErr, hasContext := errors.AsType[*fail2ban.ContextualError](err)

	// With logs on stderr the record would only repeat the Error: line below;
	// with a --log-file it is the copy that outlives the run.
	if !writesToStderr(Logger.Output()) {
		entry := Logger.WithError(err)
		if hasContext {
			entry = entry.WithField("category", string(contextErr.GetCategory()))
		}
		entry.Error(constants.MsgCommandFailed)
	}

	fmt.Fprintln(os.Stderr, constants.ErrorPrefix, err)
	if hasContext {
		if remediation := contextErr.GetRemediation(); remediation != "" {
			fmt.Fprintln(os.Stderr, "Hint:", remediation)
		}
	}
}

// GetCmdOutput returns the command's output writer if available, otherwise os.Stdout
func GetCmdOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil && cmd.OutOrStdout() != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}
