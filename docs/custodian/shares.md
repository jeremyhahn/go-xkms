# Share Collection Plane

Custodian groups say *who* holds a Shamir share. The share collection plane
tracks *which shares have come back*. A custodian who has been handed a share
submits it toward a group's quorum; operators then inspect collection progress
and, when a submission was wrong, remove it.

Share state is owned by the embedded go-qrdb node. `XKMSService`
(`pkg/xkms/servicer_share.go`) is a passthrough to the node's share client —
xkms stores no share state of its own.

## Share identity

A share is addressed by a triple:

| Field | Meaning |
|-------|---------|
| `server_url` | The xkms server the share was issued by |
| `group_id` | The custodian group the share belongs to |
| `share_index` | The 1-based index within the group |

All three are required to reach a single share. The index matters: two shares
of the same group from the same server differ only by index, and they are
addressed independently.

## Share material is write-only

Share bytes go **in** through submit and are read only by the barrier's unseal
quorum. No read path returns them:

- REST, QUIC and MCP strip `share_data` before writing a response.
- The gRPC `ShareInfo` message has no share-data field at all.
- `xkmsctl share get` prints metadata only.

A response carrying share material would hand any reader quorum input
directly, so this is enforced at every transport rather than relied upon from
the storage layer.

## Operations

| Operation | Purpose | Authorization |
|-----------|---------|---------------|
| Submit | Return a received share toward a group's quorum | `barrier:unseal-share` |
| List | Enumerate shares visible to the caller | `ceremony:status` |
| Get | Read one share's metadata | `ceremony:status` |
| Delete | Remove one share (lowers the collected count) | `barrier:unseal-share` |
| Collection status | Report threshold progress for a group | `ceremony:status` |

Reads are ceremony status; writes move quorum material and therefore carry the
barrier's unseal-share action.

## Transport surface

Every transport implements all five operations.

| Transport | Addressing |
|-----------|-----------|
| REST | `POST /api/v1/shares/submit`, `GET /api/v1/shares`, `GET\|DELETE /api/v1/shares/{serverURL}/{groupID}/{shareIndex}`, `GET /api/v1/shares/status/{groupID}` |
| QUIC | Same paths as REST |
| gRPC / Unix | `SubmitShare`, `ListShares`, `GetShare`, `DeleteShare`, `GetShareCollectionStatus` |
| MCP | `xkms.submitShare`, `xkms.listShares`, `xkms.getShare`, `xkms.deleteShare`, `xkms.getShareCollectionStatus` |
| Embedded | Direct `XKMSService` calls |

### Escaping the server URL

The server URL is itself a URL, so over REST and QUIC it is escaped into a
single path segment (`https%3A%2F%2Fhost%3A8443`). Both servers therefore
split the **raw** path and unescape each segment afterwards; splitting the
decoded path would tear the scheme and host into extra segments and the
request would 404.

## CLI

```
xkmsctl share submit --group-id g1 --share-index 2 --file share.bin
xkmsctl share list
xkmsctl share get    --server-url https://xkms:8443 --group-id g1 --share-index 2
xkmsctl share delete --server-url https://xkms:8443 --group-id g1 --share-index 2
xkmsctl share status --group-id g1
```

`submit` takes share bytes from `--file` (raw) or `--data` (base64); passing
both is an error.

## Cross-References

- [Custodian Groups](README.md) — who holds which share
- [Barrier Encryption Architecture](../seal/README.md) — Shamir sharing of the barrier root key
- [Key Share Persistence](../sharestore/README.md) — the client-side custodian vault
