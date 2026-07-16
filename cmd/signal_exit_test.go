package cmd

import "testing"

// Pins the 128+n signal exit-code convention surfaced via SignalExitCode.
func TestSignalExitCode(t *testing.T) {
	t.Cleanup(func() { interruptCode.Store(0) })

	interruptCode.Store(0)
	if got := SignalExitCode(); got != 0 {
		t.Fatalf("SignalExitCode() = %d before any signal, want 0", got)
	}
	for _, want := range []int32{130, 143} { // SIGINT, SIGTERM
		interruptCode.Store(want)
		if got := SignalExitCode(); got != int(want) {
			t.Errorf("SignalExitCode() = %d, want %d", got, want)
		}
	}
}
