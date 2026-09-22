# Lint gates

Status: current. Last verified: 2026-09-22.

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
baseline. Every entry is
`<repo-relative path><TAB><rule><TAB><symbol><TAB><reason>`: `<rule>` is `1`,
`2` or `3`, and `<symbol>` is the finding's own stable text — the forbidden
import path for rule 1, the call expression's source text for rule 2
(e.g. `ssh.ParsePrivateKey(buf.Bytes())`), or `<Struct>.<Field>` for rule 3
(e.g. `PKCS11Config.PIN`). The sweep matches a diagnostic's path + rule +
symbol against those first three fields, VERBATIM — not a glob — and fails
on any finding that doesn't match, and separately on any allowlist entry
that matched **nothing** across the whole sweep (a stale exemption), so an
entry cannot silently outlive the code it was written for.

This is the second key scheme (go-xkms#607). The first keyed on
`<path>:<line>`, and an edit anywhere above an exempted line silently
invalidated the entry by shifting the line number, with no signal beyond a
red Lint job on `main` days later — it broke twice within a week before
being replaced. Rule 2 and rule 3's symbols aren't present in the
diagnostic message (rule 2's message is the same fixed string for every
call site; rule 3's never names the struct), so `scripts/secure-analyzer.sh`
reads them back out of the source at the diagnostic's own `file:line:col`
using `scripts/secure-analyzer-symbol`, a small `go/ast`-based helper built
alongside the analyzer itself. One consequence: multiple call sites in the
same file with textually identical call expressions collapse onto the same
rule-2 key — correct when, as in `pkg/ssh/keys/signer.go`, they really are
the same shape for the same reason.

The file's own header documents three classes:

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

## Accepted residue: stdlib copies no exported API can wipe

The secure-analyzer gate enforces protected-memory handling at the source
level — imports, parse calls, struct fields. It cannot reach a second copy
of a secret that a standard-library package holds in a field of its own,
unexported type. That is a distinct, narrower class of exception, ruled on
separately (owner ruling 2026-09-21, go-xkms#133): the residue is accepted
and documented in place rather than reached with `unsafe` pointer
arithmetic over another package's private layout. `unsafe` layout pokes are
declined here for the same reason a stale allowlist entry is refused above
— a wipe reading the wrong offsets on a toolchain bump does not fail, it
silently stops wiping.

Accepted, each pinned by a regression test so a future stdlib release that
adds a zeroization route is caught by that test failing rather than by
manual audit:

- **`rsa.PrivateKey.Precomputed`** — `crypto/rsa` caches bigmod-form copies
  of the modulus and the primes in unexported fields of
  `rsa.PrecomputedValues`. `zeroizeParsedPrivateKey`
  (`pkg/backend/software/zeroize.go`) clears `D`, `Primes[]`, and every
  *exported* `Precomputed` field it can reach; the unexported cache is out
  of reach. go-xkms#133.
- **`ecdh.PrivateKey`'s X25519/NIST scalar** — lives in an unexported field
  with no zeroization method; `Bytes()` returns a copy, so wiping what it
  returns wipes the copy, not the key. Pinned by
  `TestZeroizeParsedPrivateKey_ECDHIsNotWipeable`
  (`pkg/backend/software/zeroize_test.go`) — the test documents the
  accepted residue, not a bug to fix. go-xkms#133.
- **`hmac.New`'s ipad/opad blocks** — `crypto/hmac` copies the key into its
  own heap-backed internal state, with no exported route to clear it.
  Hand-rolling HMAC to keep the key wipeable is exactly what "never
  hand-roll crypto" forbids, so this copy is accepted the same way; xkey's
  `oath` package documents the identical residue at its own call site
  (`xkey/pkg/oath/generator.go`). go-xkms#134, go-xkms#41.
- Every stdlib parse path this policy covers materializes a **second**
  representation of the bytes it decoded, independent of the source the
  caller can zeroize — `x509.ParsePKCS8PrivateKey` (`zeroizeParsedPrivateKey`'s
  one caller) is the current instance; the same reasoning applies to any
  future parse call that hands back a stdlib type holding its own
  unexported copy.

What mitigates it, in every case above: the second copy's lifetime is
bounded by the process — never persisted, never exported over any
transport — the caller zeroizes every field an exported API reaches, and no
current code path keeps a parsed key value alive longer than the operation
that needs it. A long-lived parsed private key is the shape that would turn
a bounded residue into a real exposure; none of the call sites named here
do that.
