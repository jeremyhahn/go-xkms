# 2084 fold: #2117 (pkg/types slice) into #2107

- Merge row/2084-xkey-sdk-only 041ba6056a into row/2084-xkey-sdk-oidc, keeping both import swaps (fipstest -> sdk/go/xkmstest, pkg/types -> sdk/go names).
- Checks: xkey go build/vet (plus integration-tag vet of ./test/...), xkey unit tests of the conflicted packages, sdk/go build + xkmstest test, root make lint.
- Results to follow.
