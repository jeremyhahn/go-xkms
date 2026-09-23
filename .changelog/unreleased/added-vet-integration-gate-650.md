- **Added a compile-only CI gate (`make vet-integration`) that type-checks
  every suite under `test/integration/` before it can rot silently.**
  `go vet ./...` from the root never reaches a file behind an `integration`
  (or other suite) build tag, because that tag is never set — the reason
  #636/#638 broke `sdk/go` and `acme-tpm` unnoticed, and the `tpm2/idevid`
  and `tpm2/tpm_operations` suites drifted roughly 200 references behind
  `pkg/tpm2/store`'s current API before an agent tripped over it.
  `scripts/vet-integration.sh` discovers every distinct `//go:build` tag
  combination declared under `test/integration/` and runs one
  `go vet -tags "..."` per combination, deliberately never as one tag
  union: several suites are mutually exclusive within the same package
  (`integration && grpc` beside `integration && !grpc`, `pkcs11` beside
  `!pkcs11`), and unioning every tag would compile both halves of a pair
  together and fail on a conflict no real build configuration produces.
  Wired into CI's Lint job alongside `make vet`. Ported
  `test/integration/tpm2/idevid` and `test/integration/tpm2/tpm_operations`
  to the current `pkg/tpm2`/`pkg/tpm2/store` API (`store.NewPassword` now
  returns `(types.Password, error)`; `store.KeyAttributes`,
  `store.TPMAttributes` and the `store.KEY_TYPE_*`/`store.STORE_*`
  constants moved to `pkg/types`) so the new gate starts clean. Resolves
  go-xkms#650.