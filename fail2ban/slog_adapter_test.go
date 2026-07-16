package fail2ban

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestLogger builds a SlogLogger writing to buf at the given format and level.
func newTestLogger(buf *bytes.Buffer, format SlogFormat, level slog.Level) *SlogLogger {
	l := NewSlogLogger(format)
	l.SetOutput(buf)
	l.SetLevel(level)
	return l
}

func TestSlogAdapter_ImplementsInterface(t *testing.T) {
	// Compile-time proof that the concrete adapter satisfies LoggerInterface;
	// exercising it keeps the test failing-capable rather than tautological.
	var buf bytes.Buffer
	iface := newTestLogger(&buf, SlogText, slog.LevelInfo)
	var _ LoggerInterface = iface
	iface.WithField("k", "v").Info("implements interface")
	assert.Contains(t, buf.String(), "implements interface")
}

func TestSlogAdapter_WithField(t *testing.T) {
	var buf bytes.Buffer
	adapter := newTestLogger(&buf, SlogJSON, slog.LevelInfo)

	adapter.WithField("test", "value").Info("test message")

	output := buf.String()
	assert.Contains(t, output, "test")
	assert.Contains(t, output, "value")
	assert.Contains(t, output, "test message")
}

func TestSlogAdapter_WithFields(t *testing.T) {
	var buf bytes.Buffer
	adapter := newTestLogger(&buf, SlogJSON, slog.LevelInfo)

	adapter.WithFields(Fields{
		"field1": "value1",
		"field2": 42,
	}).Info("multi-field message")

	output := buf.String()
	assert.Contains(t, output, "field1")
	assert.Contains(t, output, "value1")
	assert.Contains(t, output, "field2")
	assert.Contains(t, output, "42")
}

func TestSlogAdapter_WithError(t *testing.T) {
	var buf bytes.Buffer
	adapter := newTestLogger(&buf, SlogJSON, slog.LevelError)

	adapter.WithError(errors.New("test error")).Error("error occurred")

	output := buf.String()
	assert.Contains(t, output, "test error")
	assert.Contains(t, output, "error occurred")
}

func TestSlogAdapter_Chaining(t *testing.T) {
	var buf bytes.Buffer
	adapter := newTestLogger(&buf, SlogJSON, slog.LevelInfo)

	adapter.
		WithField("field1", "value1").
		WithField("field2", "value2").
		WithError(errors.New("chain error")).
		Info("chained message")

	output := buf.String()
	assert.Contains(t, output, "field1")
	assert.Contains(t, output, "field2")
	assert.Contains(t, output, "chain error")
	assert.Contains(t, output, "chained message")
}

func TestSlogAdapter_LogLevels(t *testing.T) {
	tests := []struct {
		name     string
		logLevel slog.Level
		logFunc  func(LoggerInterface)
		expected bool
	}{
		{"debug_enabled", slog.LevelDebug, func(l LoggerInterface) { l.Debug("debug message") }, true},
		{"info_enabled", slog.LevelInfo, func(l LoggerInterface) { l.Info("info message") }, true},
		{"warn_enabled", slog.LevelWarn, func(l LoggerInterface) { l.Warn("warn message") }, true},
		{"error_enabled", slog.LevelError, func(l LoggerInterface) { l.Error("error message") }, true},
		{"debug_disabled_at_info_level", slog.LevelInfo, func(l LoggerInterface) { l.Debug("debug message") }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			adapter := newTestLogger(&buf, SlogText, tt.logLevel)
			tt.logFunc(adapter)

			output := buf.String()
			if tt.expected {
				assert.NotEmpty(t, output, "Expected log output")
			} else {
				assert.Empty(t, output, "Expected no log output")
			}
		})
	}
}

func TestSlogAdapter_FormattedLogs(t *testing.T) {
	tests := []struct {
		name     string
		logFunc  func(LoggerInterface)
		expected string
	}{
		{"debugf", func(l LoggerInterface) { l.Debugf("formatted %s %d", "test", 42) }, "formatted test 42"},
		{"infof", func(l LoggerInterface) { l.Infof("info %s", "test") }, "info test"},
		{"warnf", func(l LoggerInterface) { l.Warnf("warn %d", 123) }, "warn 123"},
		{"errorf", func(l LoggerInterface) { l.Errorf("error %v", "failed") }, "error failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			adapter := newTestLogger(&buf, SlogText, slog.LevelDebug)
			tt.logFunc(adapter)

			assert.Contains(t, buf.String(), tt.expected)
		})
	}
}

func TestSlogEntryAdapter_Chaining(t *testing.T) {
	var buf bytes.Buffer
	adapter := newTestLogger(&buf, SlogJSON, slog.LevelInfo)

	entry := adapter.WithField("initial", "value")
	entry.
		WithField("chained1", "val1").
		WithField("chained2", "val2").
		Info("entry chain test")

	output := buf.String()
	assert.Contains(t, output, "initial")
	assert.Contains(t, output, "chained1")
	assert.Contains(t, output, "chained2")
	assert.Contains(t, output, "entry chain test")
}

func TestSlogAdapter_JSONOutput(t *testing.T) {
	var buf bytes.Buffer
	adapter := newTestLogger(&buf, SlogJSON, slog.LevelInfo)

	adapter.WithFields(Fields{
		"service": "f2b",
		"version": "1.0.0",
	}).Info("structured log")

	// Verify valid JSON output with the logrus-compatible key names.
	var logEntry map[string]any
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err, "Output should be valid JSON")

	assert.Equal(t, "f2b", logEntry["service"])
	assert.Equal(t, "1.0.0", logEntry["version"])
	assert.Contains(t, logEntry["message"], "structured log")
}

func TestSlogEntryAdapter_FormattedLogs(t *testing.T) {
	var buf bytes.Buffer
	adapter := newTestLogger(&buf, SlogText, slog.LevelDebug)
	entry := adapter.WithField("context", "test")

	entry.Debugf("debug %s", "formatted")
	assert.Contains(t, buf.String(), "debug formatted")

	buf.Reset()
	entry.Infof("info %d", 42)
	assert.Contains(t, buf.String(), "info 42")

	buf.Reset()
	entry.Warnf("warn %v", true)
	assert.Contains(t, buf.String(), "warn true")

	buf.Reset()
	entry.Errorf("error %s", "test")
	assert.Contains(t, buf.String(), "error test")
}

func TestSlogAdapter_MultipleAdapters(t *testing.T) {
	// Test that multiple adapters can coexist without cross-talk.
	var buf1, buf2 bytes.Buffer
	adapter1 := newTestLogger(&buf1, SlogText, slog.LevelInfo)
	adapter2 := newTestLogger(&buf2, SlogText, slog.LevelInfo)

	adapter1.Info("message 1")
	adapter2.Info("message 2")

	assert.Contains(t, buf1.String(), "message 1")
	assert.NotContains(t, buf1.String(), "message 2")

	assert.Contains(t, buf2.String(), "message 2")
	assert.NotContains(t, buf2.String(), "message 1")
}
