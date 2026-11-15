// Package fail2bantest provides test doubles for package fail2ban: MockClient
// (fail2ban.Client), MockRunner (fail2ban.Runner) and MockSudoChecker
// (fail2ban.SudoChecker), plus helpers that install them as fail2ban's global
// runner and sudo checker.
//
// Only test code imports this package, so neither it nor the testing package
// reaches the f2b binary.
//
// MockRunner validates every command and its arguments with fail2ban's
// validators before it returns a response, sudo-keyed responses included, as
// OSRunner validates before it runs anything.
//
// MockClient reuses fail2ban's jail selection and log filtering, and validates
// with fail2ban's validators, as RealClient does: ban and unban targets and
// jails, log jail and IP filters, and log line limits. It does not validate
// the address given to BannedInWithContext or the filter name and log path
// given to TestFilterWithContext; test those against RealClient over a
// MockRunner.
package fail2bantest
