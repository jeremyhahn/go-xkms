# Share Custody Client — API

> **Status: NORMATIVE** · Feature: `share-custody` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

Transport shapes:
[`../../../docs/key-management/api.md`](../../../docs/key-management/api.md).

## A client of an existing surface

`xkey share` speaks the same `ShareService` API as everything else. The full
capability matrix, schemas and error mapping are in
[`../../../docs/share-custody/api.md`](../../../docs/share-custody/api.md); the
essentials:

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded (`ShareService.`) |
|---|---|---|---|---|---|
| Submit share | `POST /api/v1/shares/submit` | `SubmitShare` | same as REST | `xkms.submitShare` | `SubmitShare` |
| List held shares | `GET /api/v1/shares/` | `ListShares` | same as REST | `xkms.listShares` | `ListShares` |
| Get a share | `GET /api/v1/shares/{serverURL}/{groupID}/{shareIndex}` | `GetShare` | same as REST | `xkms.getShare` | `GetShare` |
| Delete a share | `DELETE /api/v1/shares/{serverURL}/{groupID}/{shareIndex}` | `DeleteShare` | same as REST | `xkms.deleteShare` | `DeleteShare` |
| Collection status | `GET /api/v1/shares/status/{groupID}` | `GetShareCollectionStatus` | same as REST | `xkms.getShareCollectionStatus` | `GetShareCollectionStatus` |

The barrier operation a submitted share feeds is
`POST /api/v1/barrier/shamir/unseal-share` (`BarrierUnsealShare`), which carries
its own permission — `barrier:unseal-share`, distinct from `seal:unseal`. A
custodian can contribute without holding the authority to unseal outright.

## The three-part identity is in the path

```
/api/v1/shares/{serverURL}/{groupID}/{shareIndex}
```

Not `/shares/{index}`. That shape is why the CLI requires `--server` on every
share-specific verb, and why a custodian serving several deployments cannot
cross them.

## Local storage and phone custody

Held shares live in xkey's own storage, keyed by the same three-part identity.
There is no local API surface — the CLI is the interface.

Phone-held custody travels the pairing channel:
`xkey/pkg/pairing/protocol_sharing.go` and `bridge_sharing.go`, over the Noise
session described in [`../phone-hsm/api.md`](../phone-hsm/api.md). Policy is
`sharing_policy.go`.

## Below threshold is 200

A submission that leaves the quorum incomplete returns **success**. A client
that treats it as an error will report a healthy collection as broken and may
resubmit an index that has already counted — which does not advance anything.

## Error mapping

| Condition | REST |
|---|---|
| submitted, below threshold | **200** |
| share invalid or corrupt | 400 |
| share belongs to another group or server | 400 |
| duplicate index already submitted | 409 |
| quorum session expired | 410 |
| group not found | 404 |

## Versioning

The stable contract is the three-part share identity. Changing it would leave
holders with valid shares they could no longer address — worse than an ordinary
API break.

Note for anyone scripting across both CLIs: `xkey share --share-index` is
documented as 1-based; confirm the base on the `xkmsctl` side rather than
assuming they match.
