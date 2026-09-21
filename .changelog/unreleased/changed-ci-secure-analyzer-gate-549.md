- **The Lint job now enforces go-qrdb's `pkg/secure` analyzer rules on this
  repository instead of assuming them (#549).** `pkg/secure/analyzer` is a
  complete, unit-tested `go vet` plugin banning raw `memguard` imports outside
  `pkg/secure`, `ssh.ParsePrivateKey`, and sensitive-named struct fields typed
  `string`/`[]byte` — but an analyzer enforces nothing where its own make
  target does not run, and nothing in go-qrdb reaches into this repository, so
  compliance here was unmeasured. `make secure-analyzer` builds the analyzer
  from the pinned go-qrdb dependency and sweeps it, as `go vet -vettool=...`,
  over every module in this tree (`.`, `sdk/go`, `xkey`, `web/desktop`) under
  every build-tag combination that module's own vet/lint/test targets already
  declare; `make secure-analyzer-selftest` proves the gate can still find a
  known violation and stays silent on its compliant counterpart
  (`test/lint/secure/_fixtures`) before either result is trusted. Both run in
  CI's Lint job, after golangci-lint.

  Triage found six raw `memguard` imports and four `ssh.ParsePrivateKey`
  calls. One `memguard` import (`cmd/xkmsctl/bootstrap_noise.go`) and two
  `memguard.WipeBytes` calls (`cmd/xkmsctl/bootstrap_p256.go`,
  `pkg/server/bootstrap_suite.go`) were fixable in place and are now
  `secure.Buffer`/`secure.Wipe` from `sdk/go/secure`. The remainder needed an
  explicit, reasoned exemption in `scripts/secure-analyzer-allowlist.txt`
  rather than a code change, because the reported line asks for something the
  code cannot currently supply:

  - Five raw `memguard` imports (`cmd/xkmsctl/bootstrap_p256.go` and its test,
    `pkg/server/bootstrap_suite.go` and its test, `pkg/trust/bootstrap/suite_test.go`)
    exist because go-truststrap v0.4.0-alpha's `p256proto.{NewStaticKey,
    EncodeStaticKey,DecodeStaticKey}` take a `*memguard.LockedBuffer`
    directly, and `secure.Buffer` deliberately exposes no accessor to produce
    one. Filed upstream as **jeremyhahn/go-truststrap#60**.
  - Four `ssh.ParsePrivateKey` calls in `pkg/ssh/keys/{parse.go,signer.go}`
    already operate on `*secure.Buffer`/`*secure.Secret`-backed bytes; the
    call exists only to distinguish an unencrypted key from
    `*ssh.PassphraseMissingError` before falling back to
    `ParsePrivateKeyWithPassphrase`, which cannot parse an unencrypted key at
    all. The narrowing this needs is in the rule's own detection, not in this
    package — tracked as a rule-2 narrowing on go-qrdb.

  The sweep also surfaced 31 pre-existing rule-3 findings (sensitive-named
  fields predating this gate, across `pkg/crypto/rand`, `pkg/luks`,
  `pkg/fido2`, `pkg/backend/mocks`, `pkg/backup`, `pkg/factor/fido2`,
  `pkg/pivcert`, `examples/symmetric-encryption`, `pkg/auth`,
  `pkg/pkcs11/module`, `pkg/trust/clusterca`, `pkg/acme/client`,
  `sdk/go/piv_signer.go`, and thirteen sites under `xkey/`). None is fixable
  without changing an exported field's type across its call sites, so each is
  listed in the allowlist as a named, pre-existing finding pending design
  review rather than converted or silently dropped. Every allowlist entry —
  all three classes — is matched by exact `file:line` and fails the sweep as
  stale the moment it stops matching anything, so an exemption cannot outlive
  the code it was written for. Files: `Makefile`, `scripts/secure-analyzer.sh`,
  `scripts/secure-analyzer-selftest.sh`, `scripts/secure-analyzer-allowlist.txt`,
  `test/lint/secure/_fixtures/{bad,clean}`, `.github/workflows/ci.yml`,
  `cmd/xkmsctl/bootstrap_noise.go`, `cmd/xkmsctl/bootstrap_p256.go`,
  `pkg/server/bootstrap_suite.go`, `docs/development/lint-gates.md`. Verified
  by `make secure-analyzer` and `make secure-analyzer-selftest`, both exit 0.
