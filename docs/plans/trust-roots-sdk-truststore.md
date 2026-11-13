# Plan: trust-roots, xkey uses sdk/go/truststore only (epic #1545)

Row: trust-roots (docs/SPEC.md:136).

## Objective

xkey is an sdk/go client. Every xkey file that imports
`github.com/jeremyhahn/go-xkms/pkg/attestation/truststore` switches to
`github.com/jeremyhahn/go-xkms/sdk/go/truststore`. The SDK package gains the
re-exports the xkey files need. Package name and qualifier stay `truststore`,
so only the import line changes.

## Files (36, all tests)

- xkey/cmd/xkey/cmd (11): trust_test.go, datadir_adoption_test.go,
  trust_fetch_test.go, auth_tls_test.go, trust_bootstrap_purpose_test.go,
  device_listen_collaborators_test.go, backup_sources_test.go,
  sync_trust_quarantine_test.go, trust_os_cov704c_test.go, tpm_ek_test.go,
  backup_device_test.go
- xkey/pkg/gui/services (18): coverage_phase6, final_coverage_push3,
  surgical_final_b, final_coverage3, tpm_coverage_phase6,
  phone_storage_trust_coverage, tpm_coverage_phase3, tpm_coverage_phase2,
  tpm_coverage_phase5, secure_browser_service, phone_pair_attestation,
  trust_service, surgical_coverage_c, trust_service_truststrap_integration,
  tpm_coverage_phase4, final_coverage_push5, tpm_service, final_push_coverage
  (all `_test.go`)
- xkey/pkg/attestation (2): trust_test.go, device_realchain_test.go
- xkey/pkg/backup/service_test.go, xkey/pkg/pairing/bridge_sync_test.go,
  xkey/pkg/sync/service_test.go
- xkey/test/integration/trust_cli_test.go,
  xkey/test/integration/truststrap/trust_service_test.go

## Symbols used

Already in sdk/go/truststore: AddCertificateOptions, BootstrapImportOptions,
CertPurpose, ErrCertificateExists, ErrCertificateNotFound, FileStore,
FileStoreConfig, Fingerprint, ImportResult, NewFileStore, ParsePurpose,
Purpose* constants, TrustStore.

Missing, added as re-exports: CertMetadata, OSCertStore (types);
ClassifyCertificate (func); ErrInvalidCertificate, ErrPermissionDenied,
ErrRemoveFailed (errors).

## Slices

1. test(sdk): sdk/go/truststore/truststore_test.go asserts each new alias is
   the pkg type (compile-time assignment) and each var is the pkg value, plus
   one ClassifyCertificate call.
2. feat(sdk): the re-exports in sdk/go/truststore/truststore.go.
3. refactor(xkey): import switch, one commit per directory group
   (cmd, pkg/gui/services, pkg/attestation+backup+pairing+sync, test/integration).

## Out of scope

pkg/attestation/truststore itself, go.mod/go.sum, CI enforcement of the
import ban for xkey test files (ci.yml), other pkg/* imports in xkey.
