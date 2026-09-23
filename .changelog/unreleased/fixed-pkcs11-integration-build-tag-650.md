- **Fixed three `test/integration/pkcs11` suites that could not actually
  compile under the plain `integration` tag they declared.**
  `integration_test.go`, `pkcs11_integration_test.go` and
  `pkcs11_cert_integration_test.go` unconditionally imported
  `pkg/backend/pkcs11`, whose files are all gated behind `//go:build
  pkcs11` (a cgo package), but their own build constraint was
  `//go:build integration` alone. This was invisible everywhere the suite
  had ever actually been built, because `make integration-test`'s
  `INTEGRATION_TEST_FLAGS` always bundles `pkcs11` alongside `integration`
  — it surfaced only once `make vet-integration` (go-xkms#650) vetted
  `integration` on its own, matching each file's own declared constraint.
  Their `//go:build` (and legacy `// +build`) lines now read `integration
  && pkcs11`, matching the sibling
  `pkcs11_nitrokey_hsm_integration_test.go`, which already declared it
  correctly.