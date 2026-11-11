# Architecture Profile

Generated: 2026-11-09

## Detected Patterns

### Layered / N-Tier — High confidence

Evidence:

- Import graph from `go list -f '{{.Imports}}'`: `.` imports `cmd` and `fail2ban`; `cmd` imports `constants`,
  `fail2ban` and cobra; `fail2ban` imports `constants`; `constants` imports no internal package.
- No package imports a package above it, and there is no cycle.
- `cmd/` holds the CLI surface (Cobra commands, output, config). `fail2ban/` holds system access (runner, parsing,
  log reading, path policy).

### Hexagonal / Ports & Adapters — Medium confidence

Evidence:

- `fail2ban/interfaces.go` declares `Client`, `Runner` and `SudoChecker`.
- `RealClient`, `OSRunner` and `RealSudoChecker` implement them against the host; `MockClient`, `MockRunner` and
  `MockSudoChecker` in the test-only `fail2ban/fail2bantest` package implement them against test state.
- `cmd` constructors take the port (`BanCmd(client, config)`), and `cmd/lazy_client.go` is a deferring adapter.
- There is no `ports/` or `adapters/` directory and no driving/driven split by package: ports and adapters share
  `fail2ban`.

## Detected Combination

Custom hybrid: Layered, with Ports & Adapters at the system boundary.

## Inferred Structural Rules

- Dependencies point only downward: `main` → `cmd` → `fail2ban` → `constants`.
- `constants` imports no internal package.
- `cmd` reaches fail2ban and the host only through an injected interface.
- Every external or privileged command goes through a `Runner`, which validates before executing.
- `fail2ban` owns path and input validation policy; `cmd` calls it and keeps no copy.
- Commands take configuration through the injected `*Config`, not through package globals.

## Ambiguities & Contradictions

- `ServiceCmd` takes no client and executes through the process-global runner
  (`fail2ban.RunnerCombinedOutputWithSudoContext`), bypassing the injected port every other command uses.
- `runJailOperation` reads the package-global `cfg` although its command was built with an injected `*Config`.
- `lazyClient.resolve` also reads the global `cfg`; that one is deliberate, so flags are parsed before the client
  is built.
- Test doubles live in the production `fail2ban` package (open finding `arch-08222af7`).
