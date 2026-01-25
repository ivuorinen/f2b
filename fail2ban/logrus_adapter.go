package fail2ban

import "github.com/sirupsen/logrus"

// loggerCore provides common logging methods that delegate to a logrus.Entry.
// This type is embedded in both logrusAdapter and logrusEntryAdapter to
// eliminate duplicate method implementations.
type loggerCore struct {
	entry *logrus.Entry
}

// Debug logs a debug-level message.
func (c *loggerCore) Debug(args ...interface{}) { c.entry.Debug(args...) }

// Info logs an info-level message.
func (c *loggerCore) Info(args ...interface{}) { c.entry.Info(args...) }

// Warn logs a warning-level message.
func (c *loggerCore) Warn(args ...interface{}) { c.entry.Warn(args...) }

// Error logs an error-level message.
func (c *loggerCore) Error(args ...interface{}) { c.entry.Error(args...) }

// Debugf logs a formatted debug-level message.
func (c *loggerCore) Debugf(format string, args ...interface{}) { c.entry.Debugf(format, args...) }

// Infof logs a formatted info-level message.
func (c *loggerCore) Infof(format string, args ...interface{}) { c.entry.Infof(format, args...) }

// Warnf logs a formatted warning-level message.
func (c *loggerCore) Warnf(format string, args ...interface{}) { c.entry.Warnf(format, args...) }

// Errorf logs a formatted error-level message.
func (c *loggerCore) Errorf(format string, args ...interface{}) { c.entry.Errorf(format, args...) }

// logrusAdapter wraps logrus to implement our decoupled LoggerInterface.
// It embeds loggerCore to provide the 8 standard logging methods.
type logrusAdapter struct {
	loggerCore // embeds Debug, Info, Warn, Error, Debugf, Infof, Warnf, Errorf
}

// logrusEntryAdapter wraps logrus.Entry to implement LoggerEntry.
// It embeds loggerCore to provide the 8 standard logging methods.
type logrusEntryAdapter struct {
	loggerCore // embeds Debug, Info, Warn, Error, Debugf, Infof, Warnf, Errorf
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
	return &logrusAdapter{loggerCore: loggerCore{entry: logrus.NewEntry(logger)}}
}

// WithField implements LoggerInterface
func (l *logrusAdapter) WithField(key string, value interface{}) LoggerEntry {
	return &logrusEntryAdapter{loggerCore: loggerCore{entry: l.entry.WithField(key, value)}}
}

// WithFields implements LoggerInterface
func (l *logrusAdapter) WithFields(fields Fields) LoggerEntry {
	return &logrusEntryAdapter{loggerCore: loggerCore{entry: l.entry.WithFields(logrus.Fields(fields))}}
}

// WithError implements LoggerInterface
func (l *logrusAdapter) WithError(err error) LoggerEntry {
	return &logrusEntryAdapter{loggerCore: loggerCore{entry: l.entry.WithError(err)}}
}

// LoggerEntry implementation for logrusEntryAdapter

// WithField implements LoggerEntry
func (e *logrusEntryAdapter) WithField(key string, value interface{}) LoggerEntry {
	return &logrusEntryAdapter{loggerCore: loggerCore{entry: e.entry.WithField(key, value)}}
}

// WithFields implements LoggerEntry
func (e *logrusEntryAdapter) WithFields(fields Fields) LoggerEntry {
	return &logrusEntryAdapter{loggerCore: loggerCore{entry: e.entry.WithFields(logrus.Fields(fields))}}
}

// WithError implements LoggerEntry
func (e *logrusEntryAdapter) WithError(err error) LoggerEntry {
	return &logrusEntryAdapter{loggerCore: loggerCore{entry: e.entry.WithError(err)}}
}
