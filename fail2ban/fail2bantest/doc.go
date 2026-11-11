// Package fail2bantest provides test doubles for package fail2ban: MockClient
// (fail2ban.Client), MockRunner (fail2ban.Runner) and MockSudoChecker
// (fail2ban.SudoChecker), plus helpers that install them as fail2ban's global
// runner and sudo checker.
//
// Only test code imports this package, so neither it nor the testing package
// reaches the f2b binary. MockClient and MockRunner reuse fail2ban's own jail
// selection, log filtering and input validation, so a test passing against a
// double does not depend on behavior the real client lacks.
package fail2bantest
