# Trust roots: xkey trust classify against xkmsd (row 1545, slice 4)

## Gap

SPEC.md:136: against a server, xkey uses the server's trust-root store
through the sdk/go TrustRootService verbs. `xkey trust list`, `show`, `add`
and `remove` already do (slices 2 and 3). `xkey trust classify` still writes
the local FileStore when an xkmsd endpoint is configured, so a root an
operator quarantines stays unquarantined on the server.

## Rule in server mode (`resolveXKMSdURL() != ""`)

- The fingerprint is trimmed and lowercased and `--purpose` is parsed as
  today; an empty or invalid purpose is refused with
  `ErrTrustClassifyFailed` before any call.
- `--purpose synced` calls `TrustRootQuarantine`; the success line prints the
  purpose the server returned. A server error is wrapped as
  `ErrTrustClassifyFailed` with "TrustRootQuarantine:".
- Any other valid purpose is refused with `ErrTrustClassifyFailed`: xkmsd
  reclassifies a root only to synced; to change a purpose, remove the root
  and add it again with `--purpose`. No call, no local write.
- No fallback to the local store. Without an endpoint, classify is unchanged.

## Tests (xkey/cmd/xkey/cmd/trust_xkmsd_test.go)

- `TestTrustClassifyXKMSd_QuarantinesServerRoot`
- `TestTrustClassifyXKMSd_RefusesOtherPurpose`
- `TestTrustClassifyXKMSd_UnknownFingerprint`
- `TestTrustClassifyXKMSd_BadPurpose`

## Checks

- `go test -count=1 -race -tags "codec_cbor codec_json codec_msgpack" -run Trust ./cmd/xkey/cmd/` in xkey
- xkey `go build ./...` and `go vet` of ./cmd/xkey/cmd/...
- sdk/go `go build ./...`
- `make lint` at the root

Results (2026-11-12, on the feat and docs commits):

- Trust tests with -race (xkey ./cmd/xkey/cmd/): pass; the three server-mode
  tests other than BadPurpose failed on the base as expected.
- xkey build and vet: pass.
- sdk/go build: pass.
- make lint: pass (0 issues in every module and tag set).

## Later slices

`trust install`, `trust uninstall`, `trust bootstrap` and a `--purpose`
filter on `trust list` in server mode.
