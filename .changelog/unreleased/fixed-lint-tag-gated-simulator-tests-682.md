- **`make lint`/`make vet` now cover every file the root module's and
  `sdk/go`'s own tests build, closing a gap where `golangci-lint` and `go
  vet` ran untagged and never saw code behind `tpm_simulator`, `codec_cbor`,
  `codec_json` or `codec_msgpack`.** The root module went from 0 findings
  untagged to 107 under `TEST_TAGS`, all in `*_simulator_test.go` and other
  tag-gated test files `unused`/`ineffassign`/`staticcheck` had never
  reached (go-xkms#682). `LINT_MODULES`'s root and `sdk/go` entries now lint
  under `LINT_TAGS_root`, `TEST_TAGS` comma-joined for golangci-lint/go
  vet's `-tags` flag -- the same tags `test-sdk-go` already builds its
  tests with -- while `xkey` keeps `LINT_TAGS_xkey` and `web/desktop`, which
  has no test target, stays untagged; `SECURE_ANALYZER_RUNGS`'s root rung
  now reuses `LINT_TAGS_root` instead of recomputing the same comma-join.
  Every finding is fixed, not suppressed: the deprecated
  `(*ecdsa.PublicKey).X`/`.Y` field reads and `elliptic.Curve.IsOnCurve`
  calls in `pkg/tpm2`'s simulator tests are replaced with the existing
  `pkg/crypto/ecpoint` helper (`ecpoint.PublicKey`, already used by
  production code in `pkg/tpm2/eccpub.go`) or `(*ecdsa.PublicKey).ECDH()`,
  both of which still reject an off-curve point -- the on-curve assertions
  keep checking what they checked before. `QF1008` embedded-selector,
  `SA4006`/`ineffassign` unchecked-error and `unused` dead-helper findings
  in `pkg/acme/server/handlers`, `pkg/acme/admin` and
  `pkg/acme/storage/objstore` are fixed at the source: unchecked
  `crypto.GenerateKey`/`Sign` errors now go through `require.NoError`, and
  test helpers nothing called are deleted rather than kept. No `nolint`
  suppressions were added. Files: `Makefile`, `pkg/tpm2/crypto_ops_simulator_test.go`,
  `pkg/tpm2/algorithm_agility_simulator_test.go`,
  `pkg/tpm2/sign_none_hash_simulator_test.go`,
  `pkg/tpm2/attestation_certify_simulator_test.go`,
  `pkg/acme/server/handlers/tpm_coverage_test.go`,
  `pkg/acme/server/handlers/coverage_90_final_test.go`,
  `pkg/acme/server/handlers/coverage_90_target_test.go`,
  `pkg/acme/server/handlers/coverage_boost_simple_test.go`,
  `pkg/acme/server/handlers/compliance_attestation_test.go`,
  `pkg/acme/server/handlers/tpm_test_helpers_test.go`,
  `pkg/acme/admin/tenant_handlers_coverage_test.go`,
  `pkg/acme/admin/test_helpers_test.go`,
  `pkg/acme/storage/objstore/tenant_aware_factory_test.go`.
