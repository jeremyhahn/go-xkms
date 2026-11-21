# xkey-sdk-only: pkg/attestation/truststore through sdk/go/truststore

Row: xkey-sdk-only (docs/SPEC.md:180), epic #2084.

## Objective

xkey reaches go-xkms only through sdk/go. This slice removes every direct
import of `github.com/jeremyhahn/go-xkms/pkg/attestation/truststore` from
xkey; the files import `github.com/jeremyhahn/go-xkms/sdk/go/truststore`
instead, with the same `truststore` qualifier.

## Re-exports sdk/go/truststore lacks

| Symbol | Kind | Defined in pkg/attestation/truststore |
|---|---|---|
| CertMetadata | type | file.go |
| OSCertStore | type | os_linux.go, os_stub.go |
| ClassifyCertificate | func | classify.go |
| ErrInvalidCertificate | error | errors.go |
| ErrPermissionDenied | error | errors.go |
| ErrRemoveFailed | error | errors.go |

## Files that switch the import (36, all tests)

- xkey/cmd/xkey/cmd: auth_tls_test.go, backup_device_test.go,
  backup_sources_test.go, datadir_adoption_test.go,
  device_listen_collaborators_test.go, sync_trust_quarantine_test.go,
  tpm_ek_test.go, trust_bootstrap_purpose_test.go, trust_fetch_test.go,
  trust_os_cov704c_test.go, trust_test.go
- xkey/pkg/gui/services: coverage_phase6_test.go, final_coverage3_test.go,
  final_coverage_push3_test.go, final_coverage_push5_test.go,
  final_push_coverage_test.go, phone_pair_attestation_test.go,
  phone_storage_trust_coverage_test.go, secure_browser_service_test.go,
  surgical_coverage_c_test.go, surgical_final_b_test.go,
  tpm_coverage_phase2_test.go, tpm_coverage_phase3_test.go,
  tpm_coverage_phase4_test.go, tpm_coverage_phase5_test.go,
  tpm_coverage_phase6_test.go, tpm_service_test.go, trust_service_test.go,
  trust_service_truststrap_integration_test.go
- xkey/pkg (other): attestation/trust_test.go,
  attestation/device_realchain_test.go, backup/service_test.go,
  pairing/bridge_sync_test.go, sync/service_test.go
- xkey/test/integration: trust_cli_test.go, truststrap/trust_service_test.go

## Slices

1. test: sdk/go/truststore/reexport_test.go asserts each new alias is the
   pkg symbol.
2. feat: the six re-exports in sdk/go/truststore/truststore.go.
3. refactor: switch imports, one commit per directory group above.

## Out of scope

Other go-xkms/pkg imports in xkey; pkg/attestation/truststore itself;
go.mod/go.sum.
