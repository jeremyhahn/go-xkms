# Lint gates

Status: current. Last verified: 2026-09-21.

What CI's Lint job (`.github/workflows/ci.yml`) enforces on every push and
pull request, in order, and the Make target behind each step so a developer
runs the identical check locally before pushing.

## Gates

| Order | Gate | Make target | What it enforces |
|-------|------|-------------|-------------------|
| 1 | gofmt | `make fmt-check` | Every `.go` file in every module is `gofmt -s` formatted. Path-based, so one run reaches all four modules. |
| 2 | go vet | `make vet` | `go vet` passes for every module in `LINT_MODULES` (`.`, `sdk/go`, `xkey`, `web/desktop`), each under its own build tags (`LINT_TAGS_xkey` for `xkey`; untagged elsewhere). Go tooling does not cross a module boundary, so this loops rather than running `go vet ./...` once from the root. |
| 3 | golangci-lint | `make lint` | The pinned `golangci-lint` version (`GOLANGCI_LINT_VERSION` in `ci.yml`) against `.golangci.yml`, over the same `LINT_MODULES` × tags matrix as `go vet`. CI requires the exact pinned version (`.github/scripts/require-tool.sh`) rather than falling back to an install, so a version drift fails loudly instead of scanning with an unknown tool. |
| 4 | secure-analyzer selftest | `make secure-analyzer-selftest` | Proves the next gate can still find a known violation and stays silent on its compliant counterpart, before that gate's own result is trusted. See below. |
| 5 | secure-analyzer | `make secure-analyzer` | go-qrdb's `pkg/secure/analyzer` rules (raw `memguard` imports, `ssh.ParsePrivateKey`, sensitive-named `string`/`[]byte` struct fields) over every module under every declared tag combination. See below. |

`make ci-gate` (the `ci-gate` job) is the umbrella that all of the above,
plus the other jobs (`test`, `security`, `build`, `race`, ...), must pass
before a PR is mergeable — this page covers the Lint job's steps only.

## The secure-analyzer gate (go-xkms#549)

### What it enforces

go-qrdb's `pkg/secure/analyzer` (`pkg/secure/analyzer/analyzer.go`,
vendored as a dependency, not code in this repository) is a `go vet` plugin
enforcing three rules on sensitive-material handling:

1. No `import "github.com/awnumar/memguard"` outside `pkg/secure` /
   `sdk/go/secure` (in go-qrdb) — absolute, no scope.
2. No `ssh.ParsePrivateKey` — absolute, no scope. Use
   `ssh.ParsePrivateKeyWithPassphrase` on `*secure.Buffer`-backed bytes.
3. No struct field named `Passphrase`, `Password`, `PIN`, `Secret`,
   `PrivateKey`, `KeyMaterial` or `RecoveryShare` typed `string` or
   `[]byte` — scoped by four structural clauses in go-qrdb's
   `pkg/secure/analyzer/scope.go` (generated files, codec-tagged transport
   fields, command-line flag targets, `_test.go` files). Read that file
   before assuming a rule-3 finding is a false positive.

The analyzer enforces these rules only where its own `go vet -vettool=...`
invocation runs. Nothing in go-qrdb reaches into this repository — each
downstream consumer wires its own sweep, which is what `make
secure-analyzer` is.

### How the sweep works

`scripts/secure-analyzer.sh` builds the analyzer's singlechecker from the
pinned `go-qrdb` dependency (`go build ...
github.com/jeremyhahn/go-qrdb/pkg/secure/analyzer/cmd/secure-analyzer`) to
an absolute path, then runs it as `go vet -vettool=<tool>` over every module
the Makefile's `SECURE_ANALYZER_RUNGS` names, each under its own build tags.
The root module gets two rungs — untagged (matching `make vet`) and under
`TEST_TAGS` (matching what `make test` actually compiles) — because a
single tag combination only answers for the files it compiles; `sdk/go` and
`web/desktop` build untagged, and `xkey` uses `LINT_TAGS_xkey`, the widest
combination already declared for its own `vet`/`lint`. `go vet ./...` does
not cross a module boundary, so the sweep loops per module rather than
running once from the root — the same reason `make vet` and `make lint`
loop.

Every rung also checks `go list`'s package count before trusting the
result: a tag combination that matches zero packages would otherwise let
`go vet` report a silent, vacuous "clean" for a rung that looked at
nothing.

### The allowlist

`scripts/secure-analyzer-allowlist.txt` is the exemption list — not a
baseline. Every entry is `<repo-relative path>:<line><TAB><reason>`, matched
against a diagnostic's exact file and line; the sweep script fails on any
finding not in this file, and separately fails on any allowlist entry that
matched **nothing** across the whole sweep (a stale exemption), so an entry
cannot silently outlive the code it was written for. The file's own header
documents three classes:

- **A go-truststrap-forced signature** (rule 1): a small number of sites
  where an upstream function (`p256proto.{NewStaticKey,EncodeStaticKey,
  DecodeStaticKey}` in go-truststrap v0.4.0-alpha) takes a
  `*memguard.LockedBuffer` directly, and `secure.Buffer` has no accessor to
  produce one. Tracked upstream as `jeremyhahn/go-truststrap#60`.
- **A rule-2 narrowing filed on go-qrdb**: sites in `pkg/ssh/keys` that
  already parse only `*secure.Buffer`/`*secure.Secret`-backed bytes, where
  `ssh.ParsePrivateKey` is called only to detect an unencrypted key before
  falling back to `ParsePrivateKeyWithPassphrase` (which cannot parse an
  unencrypted key at all). The fix belongs in the rule's own detection, not
  in this package.
- **Pre-existing rule-3 findings**: sensitive-named fields that predate this
  gate, reported for triage rather than converted without review, because
  every one needs an API change (the field's type) reaching its
  construction sites, some of them across a module boundary. See the
  allowlist file for the full, current list with the struct each belongs
  to.

### Running it locally

```sh
make secure-analyzer-selftest   # proves the gate still blocks a known violation
make secure-analyzer            # the real sweep
```

Both exit non-zero on failure. A new finding not covered by one of the
three allowlist classes above must be fixed, not silenced — adding a
fourth reason to the allowlist without one of those three labels is not
how this gate is meant to be extended; ask before adding a new class.
