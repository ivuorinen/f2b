package fail2ban

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReconfigureSwitchesFormatAndKeepsTheOutput pins what --format json relies
// on: later records are JSON, carry the new fields and reach the same writer.
func TestReconfigureSwitchesFormatAndKeepsTheOutput(t *testing.T) {
	var out bytes.Buffer
	logger := NewSlogLogger(SlogText)
	logger.SetOutput(&out)

	logger.Reconfigure(SlogJSON, "command", "f2b ban")
	logger.Info("started")

	var record map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &record))
	assert.Equal(t, "f2b ban", record["command"])
	assert.Same(t, &out, logger.Output())
}

func TestWithErrorIgnoresANilError(t *testing.T) {
	logger := NewSlogLogger(SlogText)

	assert.Same(t, logger, logger.WithError(nil))
}
