# #2084 fold: #2108 (truststore slice) into #2107 (oidc slice)

- Merge: `git merge --no-ff` of row/2084-xkey-sdk-truststore 08e694e1a8 into row/2084-xkey-sdk-oidc; resolve the four predicted import-block conflicts in xkey/pkg/gui/services by keeping both sdk/go/oidc and sdk/go/truststore.
- Checks: xkey `go build ./...` + unit tests of the packages both heads changed, `go vet` of the integration-tagged packages, sdk/go build + `./oidc/ ./truststore/` tests, root `make lint`.
- Results to follow.
