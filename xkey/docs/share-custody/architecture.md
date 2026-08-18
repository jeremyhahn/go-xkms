# Share Custody Client — Architecture

> **Status: NORMATIVE** · Feature: `share-custody` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

## The problem

A custodian holds one piece of a barrier's root key. They need to receive it,
keep it somewhere it will survive, and submit it when a barrier needs opening —
possibly for several deployments, possibly years apart.

Doing that with a file in a home directory works until it does not: the file is
unlabelled, its origin is forgotten, and nothing stops it being submitted to the
wrong server.

## Shape chosen: a desktop client over the server-side share store

`xkey share` is the custodian's side of the custody model documented in
[`../../../docs/share-custody/architecture.md`](../../../docs/share-custody/architecture.md).
It does not implement Shamir, does not own the custody model, and does not split
anything — go-quicraft owns the GF(256) primitive and go-qrdb owns the barrier
and custody model. xkey is the holder's interface to them.

The identity of a share is the same three-part key used everywhere else:
`{serverURL, groupID, shareIndex}`. Every `xkey share` verb that names a
specific share takes all three, which is what makes holding shares for two
deployments safe rather than merely careful.

Rejected alternatives:

- **A file per share, managed by hand.** Rejected — that is the problem
  statement.
- **Implementing splitting or reconstruction in xkey.** Rejected by the
  ownership boundary and by good sense: reconstruction happens server-side as
  shares accumulate toward the quorum.
- **A single share list without server scoping.** Rejected: index 2 exists for
  every deployment a custodian serves.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| Shamir primitive | go-quicraft | **go-quicraft** |
| Barrier, custody model, quorum accumulation | go-qrdb | **go-qrdb** |
| Server-side share store and API | `go-xkms/pkg/sharestore`, `pkg/api/rest/handlers_share.go` | go-xkms |
| Custodian CLI | `xkey/cmd/xkey/cmd/share.go` | go-xkms (xkey surface) |
| Local holding | xkey's own storage | go-xkms (xkey surface) |
| Phone-held shares | `xkey/pkg/pairing/protocol_sharing.go`, `bridge_sharing.go` | go-xkms (xkey surface) |

Capability row: **"Shamir share custody client (SO/custodian workflows)"** —
`xkey share list|receive|import|export|unseal|delete`.

## Data flow

```
receive:  xkey share receive --server grpc://kms.example.com:9090
            → the share is delivered and stored locally

import:   xkey share import --file alice.share.json
            → a share delivered out of band is taken in

hold:     xkey share list
            → what this custodian holds, per {server, group, index}

submit:   xkey share unseal --server … --group-id … --share-index …
            → the share goes to that server's quorum accumulator
            → the barrier opens when M distinct shares have arrived

export:   xkey share export --server … --group-id … --share-index … --file out.json
delete:   xkey share delete --server … --group-id … --share-index …
```

`unseal` is the verb that matters: it does not unseal anything by itself. It
contributes one share toward a quorum that the server accumulates. Custodians do
not need to be online at the same time.

## Trust boundaries

- **A share is a fraction of a root key.** Held material, at rest, on a desktop
  — its protection is xkey's storage protection.
- **The three-part identity prevents cross-submission.** A share for one server
  cannot be submitted to another by mistake, because every verb names the
  server.
- **`export` produces the share as a file.** That is a deliberate escape hatch
  for backup and transfer, and it is also the one operation that puts share
  material somewhere xkey does not control.
- **`delete` is final on this device.** Nothing reissues a share; see the server
  side.
- **Sharing to a phone moves custody**, with the phone's protections and the
  phone's loss modes.

## What this feature deliberately does not do

- **It does not split, reconstruct, or unseal.** Reconstruction is server-side
  as the quorum fills.
- **It does not organise custodian groups** — that is the operator's
  `xkmsctl custodian` surface.
- **It does not reissue a lost share.** Nothing can.
