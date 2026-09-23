- **`xkmsctl migrate` is removed — BREAKING.** `cmd/xkmsctl/migrate.go`,
  `pkg/migration/` and its SDK re-export `sdk/go/migration/` are deleted in
  full, along with their Makefile targets (`test-migration`,
  `coverage-migration`) and every doc mention (`docs/README.md`'s
  migration-record row, `docs/ROADMAP.md`, `docs/crypto-backends/
  engineering.md`, `docs/certificate-authority/engineering.md`,
  `docs/acme-issuance/engineering.md`). `pkg/migration`'s plan/filter/
  batch-execute/verify engine drove two `types.KeyProvider` backends
  directly (`migration.NewMigrator(source, dest)`), an in-process
  capability the SDK `Client` never exposed and that `xkmsctl migrate` only
  ever reached by constructing local backends outside the canonical
  `ClientFactory` seam — the same deprecated pattern `tls get` used. There
  is no client-based replacement: an **exportable** key moves between
  backends one at a time through `xkmsctl key copy` (server-side `CopyKey`,
  already wired through `ClientFactory`); a **non-exportable** key (PKCS#11,
  TPM2, and other hardware-bound backends that refuse `ExportKeyTo`) could
  never move between backend registrations and still cannot.
