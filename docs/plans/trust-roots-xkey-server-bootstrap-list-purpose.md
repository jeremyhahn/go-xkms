# trust-roots: xkey trust bootstrap against xkmsd, and trust list --purpose

Row: trust-roots (docs/SPEC.md:136), epic #1545, lane strotf (slice 6).

## Gap

- With an xkmsd endpoint configured, `xkey trust bootstrap` still files the
  fetched CA bundle in the local FileStore, which the server never reads; the
  next `xkey trust list` (served by xkmsd) does not show it.
- `xkey trust list` has no `--purpose` filter, though the server's
  `TrustRootListRequest{Purpose}` takes one.

## Change

- bootstrap, server mode: fetch from the bootstrap listener as today, then
  `TrustRootImport` with purpose bootstrap-ca and source `platform:<host>`
  (from `truststore.BootstrapImportOptions`); no local store is opened.
  Without an endpoint it behaves as before.
- list `--purpose <p>`: validated with `truststore.ParsePurpose` before any
  call (refusal wraps `ErrTrustListFailed`); server mode sends it as the
  request field; local mode matches certificate metadata (general when
  metadata is missing).

## Tests (trust_xkmsd_test.go)

- TestTrustBootstrapXKMSd_ImportsToServer
- TestTrustBootstrapXKMSd_ReportsSkipped
- TestTrustListXKMSd_PurposeFilter
- TestTrustList_PurposeFilterLocal
- TestTrustList_BadPurpose

## Checks

- Trust tests with -race, xkey build + vet, sdk/go build, make lint.

## Results

- Trust tests (-race, codec tags, ./cmd/xkey/cmd/): pass; the five new tests failed on the base first.
- xkey go build ./... and go vet ./cmd/xkey/cmd/...: pass.
- sdk/go go build ./...: pass.
- make lint: pass (0 issues in every module and tag set).
- Note: xkmsd test sockets overflow the unix path limit under the lanecache TMPDIR; the runs used a short /tmp symlink to that same directory.
