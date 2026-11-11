package fail2ban_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
)

// Fixtures for the tests in package fail2ban_test. They live in that package
// because gobco cannot instrument a package whose external tests use helpers
// declared in its internal tests.

// captureLog routes the package logger, at level, to a buffer for the test.
// Code outside package fail2ban cannot read the logger in place, so cleanup
// restores the package default (a text logger on stderr) instead.
func captureLog(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	l := fail2ban.NewSlogLogger(fail2ban.SlogText)
	l.SetOutput(&buf)
	l.SetLevel(level)
	fail2ban.SetLogger(l)
	t.Cleanup(func() { fail2ban.SetLogger(fail2ban.NewSlogLogger(fail2ban.SlogText)) })
	return &buf
}
