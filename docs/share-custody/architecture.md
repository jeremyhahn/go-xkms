# Share Custody — Architecture

> **Status: NORMATIVE** · Feature: `share-custody` · Repo: `go-xkms` · Last verified: 2026-08-19

## The problem

A barrier protected by a single credential has a single point of failure and a
single point of compromise. Shamir splitting fixes both — M-of-N shares, no one
holder can unseal, no one loss is fatal — but it creates an operational problem
it does not solve: someone has to organise the holders, deliver each share to
the right person, and collect enough of them back when the barrier needs
opening.

That organisation is custody, and it is what this feature covers: **custodian
groups**, **share delivery**, and **share collection**.

## Shape chosen: groups own the threshold, the store holds one holder's shares

Two halves, deliberately separate:

**Custodian groups** — the coordination side. A group has a threshold (M), a
total (N), a purpose, an optional tenant, and members. Creating a group and
adding members is administrative; `distribute` is the act that turns the split
into delivered shares.

**The share store** (`pkg/sharestore`) — one holder's view. `ShareStore` holds
`ShareEntry` values keyed by originating server, group and index, so a single
custodian who serves several deployments keeps them apart:

```go
type ShareEntry struct { … }   // server URL, group, index, purpose, bytes
type ShareStore interface { … }
func NewBackendShareStore(backend storage.Backend, prefix string) (ShareStore, error)
func NewMemoryShareStore() ShareStore
```

The three-part key — `{serverURL, groupID, shareIndex}` — appears in the REST
paths too, and that is not incidental: a custodian holding shares for two
servers must never submit one to the other.

Rejected alternatives:

- **Implementing Shamir here.** Rejected: the GF(256) primitive is
  go-quicraft's, and the barrier and custody model are go-qrdb's. go-xkms
  supplies the client and the group surface.
- **A single global share list.** Rejected — see the three-part key.
- **Delivering shares over the same channel that stores them.** The delivery
  method is explicit (`encrypted` or `manual`) precisely so it can be a
  different channel.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| Shamir splitting primitive (GF(256)) | go-quicraft | **go-quicraft** |
| Barrier, seal registry, Shamir custody model | `go-qrdb/sdk/go` | **go-qrdb** |
| Custodian group surface | `pkg/api/rest/handlers_custodian.go`, `transport.CustodianGroupService` | go-xkms |
| Share store | `pkg/sharestore` | go-xkms |
| Share surface | `pkg/api/rest/handlers_share.go`, `pkg/api/mcp/handlers_share.go`, `transport.ShareService` | go-xkms |
| CLI | `cmd/xkmsctl/custodian.go`, `cmd/xkmsctl/share.go` | go-xkms |
| Desktop custodian client | `xkey share …` | go-xkms (xkey surface) |

The barrier operations these shares unseal are
[`../sealing-and-barrier/`](../sealing-and-barrier/architecture.md); the
ceremony that first hands them out is
[`../init-ceremony/`](../init-ceremony/architecture.md).

## Data flow

```
set up:
  custodian create --name … --threshold 3 --total 5 [--tenant-id …]
  custodian add-member --group-id … --user-id … --method encrypted|manual
  custodian distribute --group-id …
      → shares split M-of-N and delivered per member's method

hold:
  each custodian's ShareStore keeps {serverURL, groupID, shareIndex} → share

unseal:
  custodian submits:  share submit --group-id … --share-index … --data|--file
      → server accumulates toward the quorum
  operator watches:   share status --group-id …
      → QuorumProgress: how many of M have arrived
  at M:  the barrier unseals
```

Collection is **accumulative and stateful on the server** — each `submit` adds
to a quorum session rather than requiring all M at once. That is what lets
custodians in different time zones unseal a barrier without a conference call.
Quorum sessions have a TTL (`DefaultQuorumTTL`, re-exported from go-quicraft via
go-qrdb): a half-collected quorum does not sit open forever.

## Trust boundaries

- **M is the security parameter and N is the availability parameter.** M-1
  colluding holders learn nothing; N-M can be lost without consequence. Choosing
  M=N maximises security and guarantees an outage on the first lost share.
- **A share is bound to its origin.** The `{serverURL, groupID, shareIndex}` key
  exists so a custodian serving several deployments cannot cross them.
- **Delivery method is part of the model, not a detail.** `encrypted` delivers
  to the member's key; `manual` means the operator moves it out of band. The
  wrong choice here is how shares end up in a chat log.
- **A submitted share is spent into a quorum session.** The server accumulates;
  it does not store the share for reuse.
- **Shares are emitted once.** No endpoint returns a share after distribution —
  there is no "resend my share".
- **Deleting a custodian group does not un-distribute its shares.** They exist
  in the holders' stores until the barrier is rekeyed.

## What this feature deliberately does not do

- **It does not implement Shamir**, own the barrier, or own the custody model.
- **It does not choose M and N for you**, and there is no default that is right
  for every deployment.
- **It does not deliver shares over a channel it controls** for the `manual`
  method — that is the point of the method.
- **It does not recover a lost share.** Below M reachable holders, the barrier
  needs its recovery keys, and if those do not exist the root key is gone.
