// Common data structures and the logging interface.

package fail2ban

import (
	"time"
)

// BanRecord represents a single ban entry with jail, IP, ban time, and remaining duration.
// The JSON keys are lowercase like every other JSON output of the CLI.
type BanRecord struct {
	Jail      string    `json:"jail"`
	IP        string    `json:"ip"`
	BannedAt  time.Time `json:"banned_at"`
	Remaining string    `json:"remaining"`
}

// Fields represents a map of structured log fields (decoupled from logrus)
type Fields map[string]any

// LoggerEntry is the structured, chainable logging interface the fail2ban
// package logs through (SetLogger). It is also the top-level logger type.
type LoggerEntry interface {
	WithField(key string, value any) LoggerEntry
	WithFields(fields Fields) LoggerEntry
	WithError(err error) LoggerEntry
	Debug(args ...any)
	Info(args ...any)
	Warn(args ...any)
	Error(args ...any)
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}
