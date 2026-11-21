# trust-roots: xkey trust add and remove against the server store

Row: trust-roots (docs/SPEC.md:136), epic #1545. Lane strotc.

## Gap

SPEC.md:136 says that against a server xkey uses the server's trust-root
store through the sdk/go TrustRootService verbs. `xkey trust list` and
`xkey trust show` already do (lane strotb). `xkey trust add` and
`xkey trust remove` still open only the local FileStore in server mode, so a
root added with xkey never reaches the server and a served root cannot be
removed.

## Change

- `xkey trust add` in server mode (`resolveXKMSdURL() != ""`): read the PEM
  file and parse `--purpose` locally, then call `TrustRootImport` with the
  PEM, purpose and source. Added 0 and Skipped 0 is `ErrTrustNoCertificates`.
  Errors are tagged `TrustRootImport:` and wrapped in `ErrTrustAddFailed`.
- `xkey trust remove` in server mode: call `TrustRootRemove` with the
  fingerprint. Errors are tagged `TrustRootRemove:` and wrapped in
  `ErrTrustRemoveFailed`.
- Neither touches the local store in server mode; no fallback. Without an
  endpoint both work as before.

## Tests (xkey/cmd/xkey/cmd/trust_xkmsd_test.go)

- TestTrustAddXKMSd_ImportsToServer
- TestTrustAddXKMSd_SkipsExisting
- TestTrustAddXKMSd_BadPurpose
- TestTrustRemoveXKMSd_RemovesServerRoot
- TestTrustAddXKMSd_NotConfigured

## Checks

- trust tests with -race (codec tags)
- whole xkey cmd package with -race
- xkey build and vet
- sdk/go build
- make lint

## Later slices

classify, install, uninstall and a `--purpose` flag on list.

## Results

- trust tests (-race, codec tags, -run Trust): pass, the five new and strotb's three included.
- whole xkey cmd package (-race): one run failed on TestExtensionServe_ReopensAnExistingPassphraseBarrier
  and TestExtensionServeCmd_BarrierMode_IPCConnectivity (extension_serve_test.go:507, timed out waiting
  for IPC socket, under 1-3 s storage syncs); both pass when rerun alone. Not trust code.
- xkey go build ./... and go vet ./cmd/xkey/cmd/: pass.
- sdk/go go build ./...: pass.
- make lint: pass, 0 issues.
