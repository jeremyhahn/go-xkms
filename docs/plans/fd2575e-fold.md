# Lane fd2575e: F5 fold, merge #2074 into #2061 (CA m2575)

- Merges: #2074 (6cedc3a2610f, row/1846-test-audit-fido2) into row/2575-fold-test-audit (979c7943e89c); modify/delete files take the delete unless #2061 added a case no remaining test covers.
- Checks: go vet + go test -cover (codec_cbor codec_json codec_msgpack) on ./pkg/acme/... ./pkg/ca/... ./pkg/fido2/..., coverage next to main d55b1b73c7; make lint.
- Results to follow.
