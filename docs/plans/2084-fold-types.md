# 2084 fold: #2117 (pkg/types slice) into #2107

- Merge row/2084-xkey-sdk-only 041ba6056a into row/2084-xkey-sdk-oidc, keeping both import swaps (fipstest -> sdk/go/xkmstest, pkg/types -> sdk/go names).
- Checks: xkey go build/vet (plus integration-tag vet of ./test/...), xkey unit tests of the conflicted packages, sdk/go build + xkmstest test, root make lint.
- Results to follow.

## Results

- Merge: 14 test-file import conflicts resolved to the sdk/go names (bootstrap, pairingproto, truststore, oidc, fido2/authenticator, xkmstest); no go.mod/go.sum conflict.
- xkey go build ./...: pass.
- xkey go vet ./...: pass.
- xkey go vet (integration linux codec tags) ./test/...: pass.
- xkey go test (codec tags) e2eprobe, xkey/cmd, attestation/..., gui/services, pairing, phone: pass.
- sdk/go go build ./... and go test ./xkmstest/: pass.
- make lint (root): pass, 0 issues in every module and tag set.
