# #2084 fold: #2108 (truststore slice) into #2107 (oidc slice)

- Merge: `git merge --no-ff` of row/2084-xkey-sdk-truststore 08e694e1a8 into row/2084-xkey-sdk-oidc; resolve the four predicted import-block conflicts in xkey/pkg/gui/services by keeping both sdk/go/oidc and sdk/go/truststore.
- Checks: xkey `go build ./...` + unit tests of the packages both heads changed, `go vet` of the integration-tagged packages, sdk/go build + `./oidc/ ./truststore/` tests, root `make lint`.
- Results below.

## Results

- Merge: four import-block conflicts in xkey/pkg/gui/services test files, all resolved to sdk/go/oidc + sdk/go/truststore; no conflict markers, no pkg/oidc or pkg/attestation/truststore import left in them.
- xkey `go build ./...`: pass.
- xkey `go test -count=1 -tags "codec_cbor codec_json codec_msgpack"` cmd/xkey/cmd, pkg/gui/services, pkg/oidc/aws, pkg/attestation, pkg/backup, pkg/pairing, pkg/sync: all ok.
- xkey `go vet -tags "integration linux codec_cbor codec_json codec_msgpack"` test/integration, test/integration/truststrap: pass.
- sdk/go `go build ./...`: pass; `go test -count=1 ./oidc/ ./truststore/` (incl. both reexport tests): ok.
- Root `make lint`: pass (0 issues in every module and tag set; actionlint pass).
