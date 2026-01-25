// Package fail2ban defines common data structures and types.
// This package provides core types used throughout the fail2ban integration,
// including ban records, configuration structures, and logging interfaces.
package fail2ban

import (
	"time"
)

// BanRecord represents a single ban entry with jail, IP, ban time, and remaining duration.
type BanRecord struct {
	Jail      string
	IP        string
	BannedAt  time.Time
	Remaining string
}

// Fields represents a map of structured log fields (decoupled from logrus)
type Fields map[string]interface{}

// LoggerEntry represents a structured logging entry that can be chained
type LoggerEntry interface {
	WithField(key string, value interface{}) LoggerEntry
	WithFields(fields Fields) LoggerEntry
	WithError(err error) LoggerEntry
	Debug(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// LoggerInterface defines the top-level logging interface (decoupled from logrus).
// It embeds LoggerEntry since both interfaces share the same method signatures.
type LoggerInterface interface {
	LoggerEntry
}

// LogCollectionConfig configures log line collection behavior
type LogCollectionConfig struct {
	Jail        string
	IP          string
	MaxLines    int
	MaxFileSize int64
}
