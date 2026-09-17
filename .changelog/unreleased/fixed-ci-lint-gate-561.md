- **`CI / Lint` is green again, which unblocks every other job in the pipeline.**
  The gate was failing on `main` itself, and because `test`,
  `nested-module-test`, `security`, `build-raft` and `race` all declare
  `needs: [lint, ...]`, a red Lint SKIPPED them — and a skipped job is not a
  passing one, so `CI Gate` failed and every open pull request was refused at
  merge with "not all required status checks successful". Two independent
  causes, both fixed here. Thirteen test files had no trailing newline (#561,
  #562); twelve are the ones `gofmt` has always flagged, and
  `pkg/pkcs11/module/module_keygen_quantum_test.go` is flagged only by Go
  1.27's `gofmt`, which indents a multi-value return of composite literals
  differently — so it appears the moment CI moves to 1.27. And four
  golangci-lint findings (#563) sat behind the formatting failure, invisible
  until it was fixed: `registry.Close()` discarded on two error paths in
  `pkg/escrow/factory.go` (its aggregated per-agent close failures are now
  joined into the returned error), gRPC's deprecated `SecurityVersion` in
  `peercred_transport.go` (removed; nothing read it), and the uncalled
  `resolveExportBackend` in `pkg/api/rest/handlers.go` (deleted — the export
  path asserts `backend.ExportBackend` inline, exactly as the dead helper did).
