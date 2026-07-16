package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
)

func TestMain(m *testing.M) {
	// Set up mock environment for all tests
	_, cleanup := fail2ban.SetupMockEnvironment(&testingT{})
	defer cleanup()

	// Run tests
	code := m.Run()

	os.Exit(code)
}

// testingT implements TestingInterface for TestMain
type testingT struct{}

func (t *testingT) Helper() {}
func (t *testingT) Fatalf(format string, args ...any) {
	fmt.Printf("TestMain setup fatal: "+format+"\n", args...)
}
func (t *testingT) Skipf(format string, args ...any) {
	fmt.Printf("TestMain setup skip: "+format+"\n", args...)
}
func (t *testingT) TempDir() string { return os.TempDir() }

// NOTE: the former shouldSkipClientInit helper and its tests
// (TestClientInitializationLogic, TestMainFunction, TestArgumentParsing,
// TestEdgeCases, TestMainIntegration, TestMainFunctionLogic, and the two
// benchmarks) were removed: main.go performs no argument-based client-init
// skip. It uses cmd.NewLazyClient(), so the client is built lazily on first
// use and no-client commands simply never touch it. The real lazy-construction
// behavior is covered by cmd/lazy_client_test.go (TestNewLazyClientDefersConstruction,
// TestLazyClientCachesConstructionError, TestLazyClientResolvesAndDelegates).
