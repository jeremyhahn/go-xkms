- **`pkg/ssh/console`'s host-key TOFU path no longer swallows a
  `known_hosts.Emit` failure.** `buildHostKeyCallback`'s first-contact
  confirmer builds a `known_hosts.Pin` for the freshly accepted host key and
  calls `known_hosts.Emit` to render it before mirroring it into every
  `DialRequest.KnownHostsExtraFiles` entry; an `Emit` error was previously
  checked only well enough to skip the mirror loop (`if line, eerr :=
  known_hosts.Emit(pin); eerr == nil { ... }`), leaving the failure
  unreported. The trust decision is unaffected either way — `HostKeyConfirm`
  already accepted the key before `Emit` is called, and mirroring into
  `KnownHostsExtraFiles` is documented as best-effort (matching
  `AppendMissing`'s existing treatment right below it) — so the fix logs the
  failure with `slog.Warn` rather than propagating it, the same convention
  #701 batch 2 established for an `AppendMissing` failure in this exact
  block. The inline closure is also extracted into a named
  `firstContactConfirmer` function so the Emit-failure branch is directly
  unit-testable without a live SSH handshake. Separately, `pkg/ssh/local`'s
  `DialAgent` returned an inline `errors.New("no agent socket configured")`
  for an empty `sockPath`, violating the project's typed-errors rule; it now
  wraps a new `local.ErrNoAgentSocket` sentinel inside the existing
  `*AgentUnavailableError`, matching the `ErrXxx` sentinel convention already
  used by `pkg/ssh/agent`. Files: `pkg/ssh/console/console.go`,
  `pkg/ssh/local/errors.go`, `pkg/ssh/local/agent.go`, plus
  `pkg/ssh/console/console_known_hosts_test.go` and
  `pkg/ssh/local/agent_test.go` (go-xkms#854).
