package fail2ban

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogrusAdapter_ImplementsInterface(_ *testing.T) {
	logger := logrus.New()
	adapter := NewLogrusAdapter(logger)

	// Should implement LoggerInterface
	var _ = adapter
}

func TestLogrusAdapter_WithField(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	adapter := NewLogrusAdapter(logger)
	entry := adapter.WithField("test", "value")

	// Should return LoggerEntry
	var _ = entry

	entry.Info("test message")

	output := buf.String()
	assert.Contains(t, output, "test")
	assert.Contains(t, output, "value")
	assert.Contains(t, output, "test message")
}

func TestLogrusAdapter_WithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	adapter := NewLogrusAdapter(logger)

	fields := Fields{
		"field1": "value1",
		"field2": 42,
	}
	entry := adapter.WithFields(fields)

	entry.Info("multi-field message")

	output := buf.String()
	assert.Contains(t, output, "field1")
	assert.Contains(t, output, "value1")
	assert.Contains(t, output, "field2")
	assert.Contains(t, output, "42")
}

func TestLogrusAdapter_WithError(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.ErrorLevel)

	adapter := NewLogrusAdapter(logger)
	testErr := errors.New("test error")
	entry := adapter.WithError(testErr)

	entry.Error("error occurred")

	output := buf.String()
	assert.Contains(t, output, "test error")
	assert.Contains(t, output, "error occurred")
}

func TestLogrusAdapter_Chaining(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	adapter := NewLogrusAdapter(logger)

	// Test method chaining
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

func TestLogrusAdapter_LogLevels(t *testing.T) {
	tests := []struct {
		name     string
		logLevel logrus.Level
		logFunc  func(LoggerInterface)
		expected bool
	}{
		{
			name:     "debug_enabled",
			logLevel: logrus.DebugLevel,
			logFunc:  func(l LoggerInterface) { l.Debug("debug message") },
			expected: true,
		},
		{
			name:     "info_enabled",
			logLevel: logrus.InfoLevel,
			logFunc:  func(l LoggerInterface) { l.Info("info message") },
			expected: true,
		},
		{
			name:     "warn_enabled",
			logLevel: logrus.WarnLevel,
			logFunc:  func(l LoggerInterface) { l.Warn("warn message") },
			expected: true,
		},
		{
			name:     "error_enabled",
			logLevel: logrus.ErrorLevel,
			logFunc:  func(l LoggerInterface) { l.Error("error message") },
			expected: true,
		},
		{
			name:     "debug_disabled_at_info_level",
			logLevel: logrus.InfoLevel,
			logFunc:  func(l LoggerInterface) { l.Debug("debug message") },
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := logrus.New()
			logger.SetOutput(&buf)
			logger.SetLevel(tt.logLevel)

			adapter := NewLogrusAdapter(logger)
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

func TestLogrusAdapter_FormattedLogs(t *testing.T) {
	tests := []struct {
		name     string
		logFunc  func(LoggerInterface)
		expected string
	}{
		{
			name:     "debugf",
			logFunc:  func(l LoggerInterface) { l.Debugf("formatted %s %d", "test", 42) },
			expected: "formatted test 42",
		},
		{
			name:     "infof",
			logFunc:  func(l LoggerInterface) { l.Infof("info %s", "test") },
			expected: "info test",
		},
		{
			name:     "warnf",
			logFunc:  func(l LoggerInterface) { l.Warnf("warn %d", 123) },
			expected: "warn 123",
		},
		{
			name:     "errorf",
			logFunc:  func(l LoggerInterface) { l.Errorf("error %v", "failed") },
			expected: "error failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := logrus.New()
			logger.SetOutput(&buf)
			logger.SetLevel(logrus.DebugLevel)

			adapter := NewLogrusAdapter(logger)
			tt.logFunc(adapter)

			output := buf.String()
			assert.Contains(t, output, tt.expected)
		})
	}
}

func TestLogrusEntryAdapter_Chaining(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	adapter := NewLogrusAdapter(logger)

	// Test entry-level chaining
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

func TestLogrusAdapter_JSONOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	adapter := NewLogrusAdapter(logger)
	adapter.WithFields(Fields{
		"service": "f2b",
		"version": "1.0.0",
	}).Info("structured log")

	// Verify valid JSON output
	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err, "Output should be valid JSON")

	assert.Equal(t, "f2b", logEntry["service"])
	assert.Equal(t, "1.0.0", logEntry["version"])
	assert.Contains(t, logEntry["msg"], "structured log")
}

func TestLogrusEntryAdapter_FormattedLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.DebugLevel)

	adapter := NewLogrusAdapter(logger)
	entry := adapter.WithField("context", "test")

	// Test formatted log methods on entry
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

func TestLogrusAdapter_MultipleAdapters(t *testing.T) {
	// Test that multiple adapters can coexist
	logger1 := logrus.New()
	logger2 := logrus.New()

	var buf1, buf2 bytes.Buffer
	logger1.SetOutput(&buf1)
	logger2.SetOutput(&buf2)

	adapter1 := NewLogrusAdapter(logger1)
	adapter2 := NewLogrusAdapter(logger2)

	adapter1.Info("message 1")
	adapter2.Info("message 2")

	assert.Contains(t, buf1.String(), "message 1")
	assert.NotContains(t, buf1.String(), "message 2")

	assert.Contains(t, buf2.String(), "message 2")
	assert.NotContains(t, buf2.String(), "message 1")
}
