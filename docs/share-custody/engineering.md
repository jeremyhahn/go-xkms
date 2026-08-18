# Share Custody — Engineering Contract

> **Status: NORMATIVE** · Feature: `share-custody` · Repo: `go-xkms` · Last verified: 2026-08-19

## Exported surface

### Share store — `pkg/sharestore`

```go
type ShareEntry struct { … }   // sharestore.go:72
type ShareStore interface { … } // sharestore.go:110

func NewBackendShareStore(backend storage.Backend, prefix string) (ShareStore, error)
func NewMemoryShareStore() ShareStore
```

Entries are keyed by `{serverURL, groupID, shareIndex}`. The memory store is for
tests; the backend store persists through `pkg/storage`.

### Client contracts — `sdk/go/transport`

```go
type CustodianGroupService interface {
	CreateCustodianGroup(ctx, req *CreateCustodianGroupRequest) (*CreateCustodianGroupResponse, error)
	GetCustodianGroup(ctx, groupID string) (*GetCustodianGroupResponse, error)
	ListCustodianGroups(ctx) (*ListCustodianGroupsResponse, error)
	DeleteCustodianGroup(ctx, groupID string) error
	AddCustodianMember(ctx, req *AddCustodianMemberRequest) (*AddCustodianMemberResponse, error)
	RemoveCustodianMember(ctx, req *RemoveCustodianMemberRequest) error
	DistributeShares(ctx, req *DistributeSharesRequest) (*DistributeSharesResponse, error)
}

type ShareService interface {
	SubmitShare(ctx, req *SubmitShareRequest) (*SubmitShareResponse, error)
	ListShares(ctx) (*ListSharesResponse, error)
	GetShare(ctx, serverURL, groupID string, shareIndex int) (*ShareInfo, error)
	DeleteShare(ctx, serverURL, groupID string, shareIndex int) error
	GetShareCollectionStatus(ctx, groupID string) (*ShareCollectionStatus, error)
}
```

`ShareService` methods take `serverURL`, `groupID` and `shareIndex` positionally
— the three-part identity, enforced in the signature.

The Shamir types themselves (`ShamirConfig`, `ShamirInitResult`,
`QuorumProgress`, `DefaultQuorumTTL`) are go-qrdb's, aliased in
`pkg/seal/strategy.go`.

## Invariants

- **A share is identified by `{serverURL, groupID, shareIndex}`**, never by
  index alone. A custodian serving two deployments holds index 1 twice.
- **Distribution happens once.** No API returns a share afterwards; there is no
  resend.
- **Submission is accumulative.** Each `SubmitShare` advances a server-side
  quorum session; the barrier opens when M distinct valid shares have arrived.
- **Quorum sessions expire** (`DefaultQuorumTTL`). A partially collected quorum
  is not a permanently open door.
- **Duplicate submissions do not count twice.** M *distinct* indices are
  required.
- **`threshold` and `total` are fixed at group creation.** Changing M or N means
  a new split, which means a barrier rekey.
- **Deleting a group does not invalidate distributed shares.** Only a rekey
  does.
- **Concurrency.** Concurrent submissions from different custodians are the
  normal case and are safe; the quorum accumulator is server-side state.

## Error semantics

Typed errors. What a caller must distinguish:

| Condition | Meaning |
|---|---|
| share rejected — wrong group | the share belongs to another group or server |
| share rejected — invalid | corrupt or truncated share bytes |
| duplicate index | already submitted; does not advance the quorum |
| quorum expired | the collection window elapsed; start again |
| below threshold | fewer than M have arrived — not an error, a state |
| group not found | wrong group ID, or it was deleted |

**Fail closed:** an invalid or foreign share never advances the quorum, and a
barrier never unseals below M. "Below threshold" is reported as progress, not as
failure — a client that treats it as an error will report a working collection
as broken.

## Configuration

Group-level, at creation: `--threshold` (M), `--total` (N), `--purpose`,
`--tenant-id`, optional `--id`.

Member-level: `--user-id`, `--username`, and `--method` (`encrypted` or
`manual`, default `encrypted`). `encrypted` delivers to the member's key;
`manual` means the operator moves the share out of band.

Store-level: `NewBackendShareStore(backend, prefix)` — the prefix namespaces a
holder's shares within a shared backend.

## Persistence

- **Server side** — custodian groups, membership and quorum sessions persist
  through go-qrdb.
- **Holder side** — `pkg/sharestore` over `pkg/storage`, or the memory store in
  tests. On the desktop this is xkey's custody client.

A submitted share is consumed into a quorum session; it is not stored
server-side for reuse.

## Test strategy

- **Unit** — `pkg/sharestore/sharestore_test.go`, `sharestore_gaps_test.go`.
- **Transport** — `pkg/api/rest/handlers_share_test.go`,
  `handlers_custodian_test.go`; `pkg/api/mcp/handlers_share_test.go`.
- **Barrier integration** — `pkg/api/rest/handlers_barrier_shamir_test.go`,
  `pkg/api/grpc/service_barrier_shamir_test.go`.
- **Authorization** — `pkg/api/rest/server_barrier_authz_test.go`.
- **End to end** — `test/integration/bootstrap`,
  `pkg/api/rest/init_ceremony_e2e_test.go`.

The cases worth having explicit tests for, because they are the ones that fail
quietly: a share submitted to the wrong group, a duplicate index, and an expired
quorum.

## Observability

Share submissions and quorum progress are audited through `pkg/audit` — these
are among the highest-value audit records in the system, because they record who
participated in opening a barrier and when. `GetShareCollectionStatus` returns
`QuorumProgress` so an operator can watch a collection without polling the
barrier itself.
