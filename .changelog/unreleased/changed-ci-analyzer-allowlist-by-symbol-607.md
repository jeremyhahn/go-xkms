- **`scripts/secure-analyzer-allowlist.txt` now keys each exemption by path +
  rule + the finding's own symbol, not by `path:line`** (#607, #549). A
  `path:line` key breaks on any edit that shifts the exempted line — it broke
  Lint on `main` twice in one week (`fido2.go` 208→207 after #181,
  `mock_extended.go` after #154) — with no signal beyond a red job days
  later. The symbol is the forbidden import path for rule 1, the call
  expression's own source text for rule 2, or `<Struct>.<Field>` for rule 3;
  rule 2 and rule 3's symbols aren't in the diagnostic message, so
  `scripts/secure-analyzer.sh` reads them back out of the source at the
  diagnostic's `file:line:col` via a new `go/ast`-based helper,
  `scripts/secure-analyzer-symbol`. The matching and staleness-check logic
  moved into a shared, sourced `scripts/secure-analyzer-key.sh` so
  `scripts/secure-analyzer-selftest.sh` can exercise the real gate against a
  throwaway fixture: its new case proves an entry survives a line shift and
  that the stale check still catches a genuinely removed finding. All 38
  existing entries are rewritten to the new key form (they collapse to 36
  `path+rule+symbol` keys — three identical `ssh.ParsePrivateKey(buf.Bytes())`
  call sites in `pkg/ssh/keys/signer.go` now share one entry).
  `docs/development/lint-gates.md` documents the new format.
  `make secure-analyzer` and `make secure-analyzer-selftest` both verified
  green.
