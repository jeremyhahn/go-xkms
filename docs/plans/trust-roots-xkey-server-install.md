# trust-roots: xkey trust install and uninstall against xkmsd (row 1545, slice 5, lane strote)

## Gap

SPEC.md:136: against a server, xkey uses the server's trust-root store through
the sdk/go TrustRootService verbs. `list`, `show`, `add`, `remove` and
`classify` do (strotb, strotc, strotd). `xkey trust install` and
`trust uninstall` still look the root up in the local FileStore and write its
system-installed flag, so against a server they fail with "certificate not
found" for every server root.

## Server-mode rule (`resolveXKMSdURL() != ""`)

- install: fetch the root with `TrustRootGet`, decode the first CERTIFICATE
  block of its PEM, check that its fingerprint is the requested one, install it
  in the OS trust store under `xkey-<fp[:16]>`; no local store is opened and no
  local system-installed flag is written.
- uninstall: remove the OS trust store entry under the same label; neither the
  server nor the local store is read, so a root the server dropped can still be
  cleaned up.
- The label is built by one helper `osTrustLabel` used by all four paths.

## Tests (trust_xkmsd_test.go)

- TestTrustInstallXKMSd_InstallsServerRoot
- TestTrustInstallXKMSd_UnknownFingerprint
- TestTrustInstallXKMSd_OSStoreFails
- TestTrustUninstallXKMSd_RemovesOSEntry
- TestTrustUninstallXKMSd_RootGoneFromServer

## Checks

- Trust tests with -race and the codec tags in xkey/cmd/xkey/cmd
- xkey build and vet
- sdk/go build
- make lint

Results to follow.

## Next slice

Bootstrap and `list --purpose` in server mode: lane strotf, on this branch.
