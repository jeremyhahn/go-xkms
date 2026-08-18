# Share Custody Client — Engineering Contract

> **Status: NORMATIVE** · Feature: `share-custody` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

## Exported surface

The client is CLI plus local storage; the contract it speaks is
`transport.ShareService`, documented in
[`../../../docs/share-custody/engineering.md`](../../../docs/share-custody/engineering.md):

```go
type ShareService interface {
	SubmitShare(ctx, req *SubmitShareRequest) (*SubmitShareResponse, error)
	ListShares(ctx) (*ListSharesResponse, error)
	GetShare(ctx, serverURL, groupID string, shareIndex int) (*ShareInfo, error)
	DeleteShare(ctx, serverURL, groupID string, shareIndex int) error
	GetShareCollectionStatus(ctx, groupID string) (*ShareCollectionStatus, error)
}
```

Phone-held custody is `xkey/pkg/pairing/protocol_sharing.go` +
`bridge_sharing.go`, with policy in `sharing_policy.go`.

## CLI contract — `xkey/cmd/xkey/cmd/share.go`

| Verb | Flags |
|---|---|
| `share list` | — |
| `share receive` | `--server` (xkmsd URL, e.g. `grpc://host:9090`) |
| `share import` | `--file` (JSON file containing the share) |
| `share export` | `--server`, `--group-id`, `--share-index` (**1-based**), `--file` (output path) |
| `share unseal` | `--server`, `--group-id`, `--share-index` |
| `share delete` | `--server`, `--group-id`, `--share-index` |

**`--share-index` is 1-based here**, per the flag's own help
(`"1-based share index within the group"`). The server-side `xkmsctl share`
surface takes the index within the group as well; when scripting across both,
check the base rather than assuming they match.

## Invariants

- **A share is identified by `{serverURL, groupID, shareIndex}`.** Every verb
  that names a specific share requires all three. Do not add a convenience form
  that drops `--server`.
- **`unseal` submits one share; it does not unseal.** The server accumulates
  toward the quorum. A successful submit below threshold is success.
- **Submission is idempotent per index, not additive.** Submitting the same
  index twice does not advance the quorum.
- **`export` writes share material to a file** outside xkey's protection. It is
  deliberate, and it is the operation to be careful with.
- **`delete` is local and final.** No server call reissues a share.
- **Nothing here reconstructs a secret.** Reconstruction is server-side.
- **Concurrency.** Different custodians submitting simultaneously is the normal
  case and is safe; the accumulator is server-side state.

## Error semantics

Surfaced from the server side
([`../../../docs/share-custody/engineering.md`](../../../docs/share-custody/engineering.md)):
invalid share, share belongs to another group or server, duplicate index,
expired quorum, group not found.

**Below threshold is not an error.** A client that treats an incomplete quorum
as failure will report a working collection as broken, and may resubmit an index
that has already counted.

**Fail closed:** an invalid or foreign share never advances a quorum.

## Configuration

`--server` accepts the xkmsd URL in the form the transport expects — the flag's
example is `grpc://host:9090`. A custodian serving several deployments will have
several, and they are not interchangeable.

Phone custody adds `sharing_policy.go` on the pairing side.

## Persistence

Shares are held in xkey's local storage, keyed by the three-part identity.
Protection is xkey's storage protection — the same choice that applies to
credentials.

`export` produces a JSON file; `import` consumes one. That pair is the transfer
and backup path, and the only one.

## Test strategy

- **Server side** — `go-xkms/pkg/sharestore` suites,
  `pkg/api/rest/handlers_share_test.go`,
  `pkg/api/rest/handlers_barrier_shamir_test.go`.
- **Client side** — `xkey/cmd/xkey/cmd/share*.go` paths.
- **Phone custody** — `xkey/pkg/pairing` sharing suites.

The cases worth explicit tests: a share submitted to the wrong server, a
duplicate index, and an expired quorum. All three fail quietly if untested.

## Observability

Share submissions are audited **server-side** — see
[`../../../docs/audit-log/engineering.md`](../../../docs/audit-log/engineering.md)
— and those are among the highest-value records in the system: who participated
in opening a barrier, and when. The client's own useful signal is `share list`:
what this device holds, for which servers.
