// Package fail2ban provides a log/slog-backed implementation of LoggerInterface.
// It replaces the former logrus adapter so f2b depends only on the standard
// library for logging while keeping the fluent WithField/WithError/Warnf API the
// rest of the codebase already uses.
package fail2ban

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// syncWriter is a concurrency-safe, swappable io.Writer. slog binds a writer at
// handler-construction time; wrapping it lets SetOutput redirect output
// afterward (needed for --log-file redirection and test output capture).
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func (s *syncWriter) set(w io.Writer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.w = w
}

func (s *syncWriter) get() io.Writer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w
}

// SlogFormat selects the handler a SlogLogger writes through.
type SlogFormat int

const (
	// SlogText emits human-readable key=value lines (the default).
	SlogText SlogFormat = iota
	// SlogJSON emits one JSON object per line for structured consumers, using
	// the same key names logrus produced (timestamp/message, lowercase level).
	SlogJSON
)

// SlogLogger adapts log/slog to LoggerInterface. Entries produced by With* share
// the root's level and output, so SetLevel/SetOutput affect the whole tree.
type SlogLogger struct {
	logger *slog.Logger
	level  *slog.LevelVar
	out    *syncWriter
}

// logrusCompatKeys renames slog's default JSON keys to the ones logrus emitted
// (timestamp/message) and lowercases the level, so structured-log consumers see
// an unchanged schema after the logrus->slog swap.
func logrusCompatKeys(_ []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.TimeKey:
		a.Key = "timestamp"
	case slog.MessageKey:
		a.Key = "message"
	case slog.LevelKey:
		if lv, ok := a.Value.Any().(slog.Level); ok {
			a.Value = slog.StringValue(strings.ToLower(lv.String()))
		}
	}
	return a
}

// NewSlogLogger builds a SlogLogger writing to os.Stderr at info level.
func NewSlogLogger(format SlogFormat) *SlogLogger {
	out := &syncWriter{w: os.Stderr}
	level := new(slog.LevelVar) // info by default
	opts := &slog.HandlerOptions{Level: level}

	var h slog.Handler
	if format == SlogJSON {
		opts.ReplaceAttr = logrusCompatKeys
		h = slog.NewJSONHandler(out, opts)
	} else {
		h = slog.NewTextHandler(out, opts)
	}
	return &SlogLogger{logger: slog.New(h), level: level, out: out}
}

func (l *SlogLogger) derive(sl *slog.Logger) *SlogLogger {
	return &SlogLogger{logger: sl, level: l.level, out: l.out}
}

// WithField returns an entry with an added structured field.
func (l *SlogLogger) WithField(key string, value any) LoggerEntry {
	return l.derive(l.logger.With(key, value))
}

// WithFields returns an entry with the given structured fields added.
func (l *SlogLogger) WithFields(fields Fields) LoggerEntry {
	args := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return l.derive(l.logger.With(args...))
}

// WithError attaches the error's message under the "error" field. slog's JSON
// handler would render a bare error value as "{}", so the string is stored.
func (l *SlogLogger) WithError(err error) LoggerEntry {
	if err == nil {
		return l
	}
	return l.derive(l.logger.With("error", err.Error()))
}

func (l *SlogLogger) write(level slog.Level, args ...any) {
	l.logger.Log(context.Background(), level, fmt.Sprint(args...))
}

func (l *SlogLogger) writef(level slog.Level, format string, args ...any) {
	l.logger.Log(context.Background(), level, fmt.Sprintf(format, args...))
}

// Debug logs at debug level.
func (l *SlogLogger) Debug(args ...any) { l.write(slog.LevelDebug, args...) }

// Info logs at info level.
func (l *SlogLogger) Info(args ...any) { l.write(slog.LevelInfo, args...) }

// Warn logs at warn level.
func (l *SlogLogger) Warn(args ...any) { l.write(slog.LevelWarn, args...) }

// Error logs at error level.
func (l *SlogLogger) Error(args ...any) { l.write(slog.LevelError, args...) }

// Debugf logs a formatted message at debug level.
func (l *SlogLogger) Debugf(format string, args ...any) { l.writef(slog.LevelDebug, format, args...) }

// Infof logs a formatted message at info level.
func (l *SlogLogger) Infof(format string, args ...any) { l.writef(slog.LevelInfo, format, args...) }

// Warnf logs a formatted message at warn level.
func (l *SlogLogger) Warnf(format string, args ...any) { l.writef(slog.LevelWarn, format, args...) }

// Errorf logs a formatted message at error level.
func (l *SlogLogger) Errorf(format string, args ...any) { l.writef(slog.LevelError, format, args...) }

// SetOutput redirects log output (e.g. to a --log-file or a test buffer).
func (l *SlogLogger) SetOutput(w io.Writer) { l.out.set(w) }

// Output returns the current log destination.
func (l *SlogLogger) Output() io.Writer { return l.out.get() }

// SetLevel sets the minimum level that will be emitted.
func (l *SlogLogger) SetLevel(level slog.Level) { l.level.Set(level) }

// GetLevel returns the current minimum level.
func (l *SlogLogger) GetLevel() slog.Level { return l.level.Level() }

var (
	_ LoggerInterface = (*SlogLogger)(nil)
	_ LoggerEntry     = (*SlogLogger)(nil)
)
