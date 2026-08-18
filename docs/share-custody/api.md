# Share Custody — API

> **Status: NORMATIVE** · Feature: `share-custody` · Repo: `go-xkms` · Last verified: 2026-08-19

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

Both groups are `RouteAuthSession` and conditionally registered — custodian
routes on `hasCustodian`, share routes on `hasShares`. Where the subsystem is
not configured the routes do not exist.

## Custodian groups

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC | MCP | Embedded (`CustodianGroupService.`) |
|---|---|---|---|---|---|
| Create group | `POST /api/v1/custodian/groups/` | `CreateCustodianGroup` | same as REST | **MISSING — docs/13** | `CreateCustodianGroup` |
| List groups | `GET /api/v1/custodian/groups/` | `ListCustodianGroups` | same as REST | **MISSING — docs/13** | `ListCustodianGroups` |
| Get group | `GET /api/v1/custodian/groups/{id}` | `GetCustodianGroup` | same as REST | **MISSING — docs/13** | `GetCustodianGroup` |
| Delete group | `DELETE /api/v1/custodian/groups/{id}` | `DeleteCustodianGroup` | same as REST | **MISSING — docs/13** | `DeleteCustodianGroup` |
| Add member | `POST /api/v1/custodian/groups/{id}/members` | `AddCustodianMember` | same as REST | **MISSING — docs/13** | `AddCustodianMember` |
| Remove member | `DELETE /api/v1/custodian/groups/{id}/members/{userID}` | `RemoveCustodianMember` | same as REST | **MISSING — docs/13** | `RemoveCustodianMember` |
| Distribute shares | `POST /api/v1/custodian/groups/{id}/distribute` | `DistributeShares` | same as REST | **MISSING — docs/13** | `DistributeShares` |

## Shares

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded (`ShareService.`) |
|---|---|---|---|---|---|
| Submit share | `POST /api/v1/shares/submit` | `SubmitShare` | same as REST | `xkms.submitShare` | `SubmitShare` |
| List held shares | `GET /api/v1/shares/` | `ListShares` | same as REST | `xkms.listShares` | `ListShares` |
| Get a share | `GET /api/v1/shares/{serverURL}/{groupID}/{shareIndex}` | `GetShare` | same as REST | `xkms.getShare` | `GetShare` |
| Delete a share | `DELETE /api/v1/shares/{serverURL}/{groupID}/{shareIndex}` | `DeleteShare` | same as REST | `xkms.deleteShare` | `DeleteShare` |
| Collection status | `GET /api/v1/shares/status/{groupID}` | `GetShareCollectionStatus` | same as REST | `xkms.getShareCollectionStatus` | `GetShareCollectionStatus` |

Note the asymmetry: the **share** half is on MCP, the **custodian** half is not.
That is a coherent line — reading and submitting a share you hold is a custodian
activity, while creating groups and distributing splits is administration — but
it is recorded as seven gaps rather than presented as a design statement,
because nothing in the code says it was one.

## The three-part share identity is in the path

```
/api/v1/shares/{serverURL}/{groupID}/{shareIndex}
```

Not `/shares/{index}`. A custodian serving several deployments holds the same
index more than once, and the path makes crossing them impossible rather than
merely discouraged. The `ShareService` Go signatures carry the same three
parameters positionally.

## Barrier operations these feed

Shares are collected here and consumed by the barrier — see
[`../sealing-and-barrier/api.md`](../sealing-and-barrier/api.md):
`BarrierInitializeShamir`, `BarrierUnsealShare` (one share, accumulating),
`BarrierUnsealShares` (all at once).

`POST /api/v1/barrier/shamir/unseal-share` carries its own permission,
`barrier:unseal-share`, distinct from `seal:unseal` — a custodian can contribute
a share without holding the authority to unseal outright.

## Request and response schemas

`pkg/api/transport/types_custodian.go` and `types.go`:
`CreateCustodianGroupRequest`/`Response`, `AddCustodianMemberRequest`/`Response`,
`RemoveCustodianMemberRequest`, `DistributeSharesRequest`/`Response`,
`SubmitShareRequest`/`Response`, `ShareInfo`, `ShareCollectionStatus`.

Shamir types (`ShamirConfig`, `ShamirInitResult`, `QuorumProgress`) are
go-qrdb's.

**A share's bytes appear in exactly one response — the distribution response —
and never again.** `GetShare` returns `ShareInfo` (metadata for a share the
caller holds), not a re-issue.

## Status and error mapping

| Condition | REST | gRPC / Unix | MCP |
|---|---|---|---|
| success | 200 | `OK` | `result` |
| below threshold (progress) | **200** | `OK` | `result` |
| share invalid or corrupt | 400 | `InvalidArgument` | JSON-RPC `-32602` |
| share belongs to another group or server | 400 | `InvalidArgument` | error object |
| duplicate index already submitted | 409 | `AlreadyExists` | error object |
| quorum session expired | 410 | `FailedPrecondition` | error object |
| group not found | 404 | `NotFound` | error object |
| custody subsystem not configured | route absent (404) | `Unimplemented` | error object |

**Below threshold is 200.** A client that treats an incomplete quorum as a
failure will report a healthy collection as broken and may retry a share that
has already counted.

## Pagination

`ListCustodianGroups` and `ListShares` are bounded by the deployment's group and
share counts and are returned whole.

## Versioning and deprecation

`/api/v1/custodian/*` and `/api/v1/shares/*`; gRPC package `xkmsv1`. Nothing
deprecated.

The stable contract is the three-part share identity. Changing it would break
every held share's addressability, which is worse than an API break — holders
would still have valid shares they could no longer submit.
