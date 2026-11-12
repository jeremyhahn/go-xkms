# Trust roots: xkey trust list and show against the server's store

Row: trust-roots (docs/SPEC.md:136), epic #1545.

## Gap

SPEC.md:136: against a server, xkey uses the server's trust-root store through
the sdk/go TrustRootService verbs. Today `xkey trust list` and `xkey trust show`
always open the local FileStore (`openTrustStore()`), even when an xkmsd
endpoint is configured.

## Slice

1. Test commit: `xkey/cmd/xkey/cmd/trust_xkmsd_test.go`
   - `TestTrustListXKMSd_ShowsServerRoots`: server store holds one root
     (CN "strotb server root"); list shows it, a local-only root does not.
   - `TestTrustShowXKMSd_ByFingerprint`: show by fingerprint prints the
     fingerprint and subject.
   - `TestTrustListXKMSd_NotConfigured`: no store wired; list errors and
     writes no local-store output.
2. sdk/go/truststore: aliases `DAOStore = truststore.DAOStore` and
   `NewDAOStore = truststore.NewDAOStore` (xkey may import sdk/go only).
3. xkey: in server mode (`resolveXKMSdURL() != ""`) runTrustList calls
   `TrustRootList` (with `--purpose`) and runTrustShow calls `TrustRootGet`
   through `connectXKMSdClient`; output to `cmd.OutOrStdout()`; server errors
   are returned wrapped, never a fallback to the local store.

Out of scope: trust add/import/remove and other subcommands; pkg/ server side;
SPEC and ROADMAP text.

## Checks

- xkey go test -race (Trust tests), xkey build + vet, sdk/go build + truststore
  tests, make lint.

## Results

- xkey `go test -race -run 'TrustListXKMSd|TrustShowXKMSd|Trust' ./cmd/xkey/cmd/`: pass.
- xkey `go build ./...` + `go vet ./cmd/xkey/cmd/...`: pass.
- sdk/go `go build ./...` + `go test -race ./truststore/...`: pass.
- `make lint`: pass (0 issues on every module and tag set).

Note: `xkey trust list` has no `--purpose` flag, so the server call sends an
empty Purpose (all roots); a purpose filter is a later slice.
