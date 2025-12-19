package fail2ban

import "github.com/sirupsen/logrus"

// logrusAdapter wraps logrus to implement our decoupled LoggerInterface
type logrusAdapter struct {
	entry *logrus.Entry
}

// logrusEntryAdapter wraps logrus.Entry to implement LoggerEntry
type logrusEntryAdapter struct {
	entry *logrus.Entry
}

// Ensure logrusAdapter implements LoggerInterface
var _ LoggerInterface = (*logrusAdapter)(nil)

// Ensure logrusEntryAdapter implements LoggerEntry
var _ LoggerEntry = (*logrusEntryAdapter)(nil)

// NewLogrusAdapter creates a logger adapter from a logrus logger
func NewLogrusAdapter(logger *logrus.Logger) LoggerInterface {
	if logger == nil {
		logger = logrus.StandardLogger()
	}
	return &logrusAdapter{entry: logrus.NewEntry(logger)}
}

// WithField implements LoggerInterface
func (l *logrusAdapter) WithField(key string, value interface{}) LoggerEntry {
	return &logrusEntryAdapter{entry: l.entry.WithField(key, value)}
}

// WithFields implements LoggerInterface
func (l *logrusAdapter) WithFields(fields Fields) LoggerEntry {
	return &logrusEntryAdapter{entry: l.entry.WithFields(logrus.Fields(fields))}
}

// WithError implements LoggerInterface
func (l *logrusAdapter) WithError(err error) LoggerEntry {
	return &logrusEntryAdapter{entry: l.entry.WithError(err)}
}

// Debug implements LoggerInterface
func (l *logrusAdapter) Debug(args ...interface{}) {
	l.entry.Debug(args...)
}

// Info implements LoggerInterface
func (l *logrusAdapter) Info(args ...interface{}) {
	l.entry.Info(args...)
}

// Warn implements LoggerInterface
func (l *logrusAdapter) Warn(args ...interface{}) {
	l.entry.Warn(args...)
}

// Error implements LoggerInterface
func (l *logrusAdapter) Error(args ...interface{}) {
	l.entry.Error(args...)
}

// Debugf implements LoggerInterface
func (l *logrusAdapter) Debugf(format string, args ...interface{}) {
	l.entry.Debugf(format, args...)
}

// Infof implements LoggerInterface
func (l *logrusAdapter) Infof(format string, args ...interface{}) {
	l.entry.Infof(format, args...)
}

// Warnf implements LoggerInterface
func (l *logrusAdapter) Warnf(format string, args ...interface{}) {
	l.entry.Warnf(format, args...)
}

// Errorf implements LoggerInterface
func (l *logrusAdapter) Errorf(format string, args ...interface{}) {
	l.entry.Errorf(format, args...)
}

// LoggerEntry implementation for logrusEntryAdapter

// WithField implements LoggerEntry
func (e *logrusEntryAdapter) WithField(key string, value interface{}) LoggerEntry {
	return &logrusEntryAdapter{entry: e.entry.WithField(key, value)}
}

// WithFields implements LoggerEntry
func (e *logrusEntryAdapter) WithFields(fields Fields) LoggerEntry {
	return &logrusEntryAdapter{entry: e.entry.WithFields(logrus.Fields(fields))}
}

// WithError implements LoggerEntry
func (e *logrusEntryAdapter) WithError(err error) LoggerEntry {
	return &logrusEntryAdapter{entry: e.entry.WithError(err)}
}

// Debug implements LoggerEntry
func (e *logrusEntryAdapter) Debug(args ...interface{}) {
	e.entry.Debug(args...)
}

// Info implements LoggerEntry
func (e *logrusEntryAdapter) Info(args ...interface{}) {
	e.entry.Info(args...)
}

// Warn implements LoggerEntry
func (e *logrusEntryAdapter) Warn(args ...interface{}) {
	e.entry.Warn(args...)
}

// Error implements LoggerEntry
func (e *logrusEntryAdapter) Error(args ...interface{}) {
	e.entry.Error(args...)
}

// Debugf implements LoggerEntry
func (e *logrusEntryAdapter) Debugf(format string, args ...interface{}) {
	e.entry.Debugf(format, args...)
}

// Infof implements LoggerEntry
func (e *logrusEntryAdapter) Infof(format string, args ...interface{}) {
	e.entry.Infof(format, args...)
}

// Warnf implements LoggerEntry
func (e *logrusEntryAdapter) Warnf(format string, args ...interface{}) {
	e.entry.Warnf(format, args...)
}

// Errorf implements LoggerEntry
func (e *logrusEntryAdapter) Errorf(format string, args ...interface{}) {
	e.entry.Errorf(format, args...)
}
