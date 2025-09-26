// Package fail2ban defines common data structures and types.
// This package provides core types used throughout the fail2ban integration,
// including ban records, configuration structures, and logging interfaces.
package fail2ban

import (
	"time"

	"github.com/sirupsen/logrus"
)

// BanRecord represents a single ban entry with jail, IP, ban time, and remaining duration.
type BanRecord struct {
	Jail      string
	IP        string
	BannedAt  time.Time
	Remaining string
}

// LoggerInterface defines the logging interface we need
type LoggerInterface interface {
	WithField(key string, value interface{}) *logrus.Entry
	WithFields(fields logrus.Fields) *logrus.Entry
	WithError(err error) *logrus.Entry
	Debug(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// LogCollectionConfig configures log line collection behavior
type LogCollectionConfig struct {
	Jail        string
	IP          string
	MaxLines    int
	MaxFileSize int64
}
