# Lane fd2575e: F5 fold, merge #2074 into #2061 (CA m2575)

- Merges: #2074 (6cedc3a2610f, row/1846-test-audit-fido2) into row/2575-fold-test-audit (979c7943e89c); modify/delete files take the delete unless #2061 added a case no remaining test covers.
- Checks: go vet + go test -cover (codec_cbor codec_json codec_msgpack) on ./pkg/acme/... ./pkg/ca/... ./pkg/fido2/..., coverage next to main d55b1b73c7; make lint.

## Results

- Merge #2074: the 32 conflicts were content conflicts, not modify/delete (both audits removed different tests from the same files; #2074 deletes no file). First resolution: #2061's side minus the 52 functions #2074 also removed. coverage_boost5_test.go stays deleted (#2061 removed it).
- Coverage check after that merge: handlers 89.5% (main 90.6%), pkg/ca 91.2% (main 91.7%). The lost blocks were in the EAB paths (external_account_binding.go, new_account.go), new_order, order_finalize, service.go and most pkg/ca targets: the two audits had each removed a different twin.
- Follow-up commit: restored #2061's version of the 15 trimmed files (the 52 tests). #2074's other removals stay (pkg/fido2, coverage_boost18 and the files that merged cleanly).
- go vet (no tags and the codec tags) on ./pkg/acme/... ./pkg/ca/... ./pkg/fido2/...: pass.
- go test -cover, fold vs main: handlers 90.6 / 90.6, pkg/ca 91.7 / 91.7, pkg/fido2 92.0 / 92.0, fido2/authenticator 91.0 / 91.0, keybackend 89.7 / 89.7, uhid 95.9 / 95.9, virtualdevice 93.1 / 93.1, ca/checkpoint 99.7 / 99.7. Packages this merge doesn't touch are within run-to-run noise (e.g. dns-01/providers 93.3 / 94.0, client/service 72.7 / 72.8, enroll-01 92.7-93.3).
- Known failure, not caused by this merge: pkg/acme/client TestDeviceAttestDICE* (5 tests) also fail on main d55b1b73c7 and on 979c7943e89c.
- make lint: pass (0 issues in every module and tag set).
