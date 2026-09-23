- **Fixed six Makefile per-package targets that pointed at nonexistent
  packages.** `test-backup`/`coverage-backup`/`bench-backup` targeted
  `./pkg/adapters/backup/...`, which does not exist, instead of
  `./pkg/backup/...`. The same audit, run by matching every `test-*`,
  `coverage-*`, and `bench-*` per-package target's path against `go list`
  in each module, found five more: `test-auth`/`coverage-auth` and
  `test-audit`/`coverage-audit` targeted the removed `./pkg/adapters/auth/...`
  and `./pkg/adapters/audit/...` and now target `./pkg/auth/...` and
  `./pkg/audit/...`; `coverage-memory-storage` and a `bench-storage` line
  targeted `./pkg/storage/memory/...`, a subdirectory that no longer exists
  now that `NewMemoryBackend` is a two-line wrapper directly in `pkg/storage`,
  and now target `./pkg/storage`. `test-authz`/`coverage-authz`,
  `test-rbac`/`coverage-rbac`, and `test-user`/`coverage-user` targeted
  `./pkg/adapters/authz/...`, `./pkg/adapters/rbac/...`, and `./pkg/user/...`;
  none exist — authz is merged into `pkg/auth/authorize.go` (covered by
  `test-auth`), and RBAC and the user/identity model are owned by go-qrdb
  and have no local package to test, so these six targets are deleted rather
  than repointed. Files: `Makefile`. Fixes go-xkms#663.
