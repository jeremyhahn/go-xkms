# Lint gates

> **Status: REFERENCE** · Last verified: 2026-10-16
> Scope: the lint and static-analysis gates CI's Lint and Static Analysis jobs run, and the Make target behind each.

This page lists what CI's Lint and Static Analysis jobs
(`.github/workflows/ci.yml`) enforce on every push and pull request, in
order. Each step names its Make target, so a developer can run the same
check locally before pushing. Both jobs run their steps in the toolchain
image built from `build/docker/devcontainer/Dockerfile`, through
`scripts/in-toolchain-image.sh`. Every tool version is pinned in
`scripts/tool-pins.sh`. `make docker-run CMD='make lint'` runs a step in
the same image locally.

## Gates

### Lint job

| Order | Gate | Make target | What it enforces |
|-------|------|-------------|-------------------|
| 1 | gofmt | `make fmt-check` | Every `.go` file in every module is `gofmt -s` formatted. Path-based, so one run reaches all four modules. |
| 2 | go vet | `make vet` | `go vet` passes for every module in `LINT_MODULES` (`.`, `sdk/go`, `xkey`, `web/desktop`; `Makefile:3792`), each under its own build tags: `LINT_TAGS_xkey` for `xkey`, `VET_BUILD_TAGS` for `web/desktop`, and `LINT_TAGS_root` (`TEST_TAGS`, comma-joined) plus `VET_BUILD_TAGS` for `.` and `sdk/go`. Two more passes vet the root module under `LINT_TAGS_root_backends` and `LINT_TAGS_root_raft` (`Makefile:3873`). Go tooling does not cross a module boundary, so this loops rather than running `go vet ./...` once from the root. |
| 3 | actionlint | `make lint` (`make actionlint`) | Every workflow in `.github/workflows/` passes actionlint at `ACTIONLINT_VERSION` (Makefile): syntax, expressions, runner labels, and every `run:` script through shellcheck when it is installed. A missing or different actionlint is replaced by the pin (`make install-actionlint`); a pin that cannot be installed fails the target. The installed version must match the pin exactly. The target fails at once when `.github/actionlint.yaml` is missing: it lists the self-hosted runner labels the workflows request (`qwen`), and must name exactly those. `make install-trivy` builds Trivy at `TRIVY_VERSION` with `go install`, stamping the version as Trivy's release build does; no install script is piped into a shell. A missing Trivy, or one that does not report the pin, is replaced by the pin, and an install that does not report the pin fails the target. `.github/scripts/make-gates-test.sh` proves this gate, and `make trivy`/`make trivy-image`, fail closed with the tool absent (go-xkms#1434). |
| 4 | golangci-lint | `make lint` | The pinned `golangci-lint` version (`GOLANGCI_VERSION` in `scripts/tool-pins.sh`, installed in the toolchain image) against `.golangci.yml`, over the same `LINT_MODULES` × tags matrix as `go vet`. |
| 5 | xkey skill reference | `make -C xkey check-skill-reference` | Fails when the xkey skill's generated CLI reference is stale, or `SKILL.md` cites a command or flag that does not exist (`xkey/Makefile:1048`). |
| 6 | internal literals | `make check-public-literals` | No lab-network address, fleet host name or owner workstation path in any tracked file, reported as `path:line` without the line's text (go-xkms#1030). |

Between gates 2 and 3 the job also runs the CI scripts' own self-tests
(`.github/scripts/disk-usage-test.sh`, `require-tool-test.sh`,
`make-gates-test.sh`, `apt-deps-test.sh`) and `make test-buildgates`. The
latter checks that every job in `ci.yml` appears in the CI Gate tagged `pr`
or `full`, and that a `full` job carries the full-tier `if:`.

### Static Analysis job

| Order | Gate | Make target | What it enforces |
|-------|------|-------------|-------------------|
| 1 | integration compile gate | `make vet-integration` | Every `test/integration` suite compiles, one `go vet` per distinct `//go:build` tag combination (go-xkms#650). |
| 2 | secure-analyzer selftest | `make secure-analyzer-selftest` | Proves the next gate can still find a known violation and stays silent on its compliant counterpart, before that gate's own result is trusted. See below. |
| 3 | secure-analyzer | `make secure-analyzer` | go-qrdb's `pkg/secure/analyzer` rules (raw `memguard` imports, `ssh.ParsePrivateKey`, sensitive-named `string`/`[]byte` struct fields, string conversions of protected bytes, unwiped copy-outs) over every module under every declared tag combination. See below. |

The `ci-gate` job (CI Gate) is the umbrella that all of the above, plus the
other jobs (`test`, `security`, `build`, `race`, ...), must pass before a PR
is mergeable. It is a job, not a Make target. This page covers the Lint and
Static Analysis jobs only.

## The secure-analyzer gate (go-xkms#549)

### What it enforces

go-qrdb's `pkg/secure/analyzer` (`pkg/secure/analyzer/analyzer.go`,
a module dependency, not code in this repository) is a `go vet` plugin
enforcing five rules on sensitive-material handling (`securecheck`, rules 1-3,
and `securecopy`, rules 4-5, as pinned at go-qrdb v0.47.0-alpha). The
numbers are this repository's: `rule_for` in `scripts/secure-analyzer-key.sh`
(lines 45-54) maps each analyzer message to one, verbatim, and fails on any
message it does not know.

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
4. `string(...)` of protected bytes, which can never be wiped.
5. A copy of protected bytes into ordinary memory that is never wiped,
   returned or consumed. The analyzer follows the copy: a function that
   returns one makes every caller answerable for it, across packages, so a
   copy must end in a `secure.Wipe`, a `return`, or a consumer such as
   `secure.NewBufferFromBytes` in the function that holds it.

Rules 4-5 have no key to allowlist (`process_diagnostics` fails them on
sight, `scripts/secure-analyzer-key.sh:126`): the fix is in the code. See
"Handling a secret without tripping the gate" below.

There is no rule for an unborrowed read any more. Earlier go-qrdb releases
reported a `secure.Buffer.Bytes()` read with no borrow held, and a malformed
`//secure:unborrowed` directive that exempted one. From v0.47.0-alpha
`secure.Buffer` is backed by go-enclave and its only reads are `WithBytes`
and `secure.CopyOut`: it has no method that returns its bytes outside a
borrow, so the compiler rejects what that rule caught, and the analyzer
dropped the rule and the directive with it
(`scripts/secure-analyzer-key.sh:37-41`).

The selftest's bad fixture plants one violation per rule
(`test/lint/secure/_fixtures/bad/bad.go`: rule 4 at line 59, rule 5 at line
68) and `expect_hit` (`scripts/secure-analyzer-selftest.sh:84-91`) fails
unless each rule is reported exactly once; the clean fixture beside it must
produce no diagnostic at all.

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
`2` or `3` (rules 4-5 are never allowlisted), and `<symbol>` is the finding's own stable text — the forbidden
import path for rule 1, the call expression's source text for rule 2
(e.g. `ssh.ParsePrivateKey(pem)`), or `<Struct>.<Field>` for rule 3
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
the same shape for the same reason. (`signer.go` now parses in one helper,
`parseSealedPEM` (`pkg/ssh/keys/signer.go:144`), so its entry names a single
call; `pkg/ssh/keys/parse.go:63` has an entry of its own.)

The file's own header documents two classes. Rule 1 has none: no file in
this repository imports `memguard` any more, now that the bootstrap P-256
static key is encoded and decoded through a go-enclave buffer rather than a
`*memguard.LockedBuffer` (`decodeP256StaticKey`,
`pkg/server/bootstrap_suite.go:168-192`), so the four go-truststrap#60 entries were removed
when they went stale.

- **A rule-2 narrowing filed on go-qrdb**: sites in `pkg/ssh/keys` that
  already parse only `*secure.Buffer`/`*secure.Secret`-backed bytes, where
  `ssh.ParsePrivateKey` is called only to detect an unencrypted key before
  falling back to `ParsePrivateKeyWithPassphrase` (which cannot parse an
  unencrypted key at all). The fix belongs in the rule's own detection, not
  in this package.
- **Pre-existing rule-3 findings**: sensitive-named fields that predate this
  gate, reported for triage rather than converted without review, because
  every one needs an API change (the field's type) reaching its
  construction sites, some of them across a module boundary. The class is
  currently empty: the allowlist's only entries are the two rule-2 sites
  above (`scripts/secure-analyzer-allowlist.txt:71-72`), and its rule-3
  section keeps only the header that governs any entry added back.

### Handling a secret without tripping the gate

- **Reading a protected value.** Borrow it with `WithBytes` and keep the
  work inside the callback, or take a caller-owned copy with `secure.CopyOut`
  and `defer secure.Wipe(copy)` in the same function. An accessor that
  returns such a copy (`Secret()`, `Password()`, `PrivateKey()`,
  `Password.Bytes()`) hands the wipe to its caller.
- **`types.Password`.** `String()` returns `types.PasswordRedacted` on every
  implementation, so formatting or logging a Password cannot leak it. `Bytes()`
  is a caller-owned copy to wipe. `WithBytes` lends the secret and also carries
  the "unreadable" signal (`RequiredPassword` returns `ErrPasswordRequired`,
  an unsealable `PlatformPassword` `ErrPlatformPasswordUnavailable`), which
  TPM session setup uses to fail closed.
- **A secret in a record.** `types.SecretBytes` is wipeable heap text for a
  value with a short, local life (a token response, a request field); its
  owner calls `Wipe`. `types.SecretText` is protected memory for a record that
  crosses functions (a backup archive, a sync delta, a pairing message); its
  owner calls `Destroy`, copies of the value share one buffer, and the record
  must not be compared with `reflect.DeepEqual`. Both encode to exactly the
  bytes a `string` field would, so stored records and archives are unchanged.
- **Where an API demands a string** (`url.Values`, a process environment, a
  JWS parser, the Wails-bound `StaticPassword.Password`) convert from a
  caller-owned copy at that one call site, and say so in a comment. A
  conversion of a copy is not a finding; `string(view)` inside `WithBytes` is.
- **Ciphertext is not secret.** `WrapAESKW`, `WrapAESKWP` and `WrapRSAAES`
  compute their final round straight into an ordinary slice, so their callers
  inherit no obligation.

### Running it locally

```sh
make secure-analyzer-selftest   # proves the gate still blocks a known violation
make secure-analyzer            # the real sweep
```

Both exit non-zero on failure. A new finding not covered by one of the
two allowlist classes above must be fixed, not silenced — adding a
third reason to the allowlist without one of those two labels is not
how this gate is meant to be extended; ask before adding a new class.

## Accepted residue: stdlib copies no exported API can wipe

The secure-analyzer gate enforces protected-memory handling at the source
level — imports, parse calls, struct fields. It cannot reach a second copy
of a secret that a standard-library package holds in a field of its own,
unexported type. That is a distinct, narrower class of exception: the residue is accepted
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
  (`pkg/backend/software/zeroize.go:74`) clears `D`, `Primes[]`, and every
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
