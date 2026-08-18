# Share Custody Client — User Guide

> **Status: NORMATIVE** · Feature: `share-custody` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

## You are a custodian

Someone gave you one piece of a key. On its own it reveals nothing. Together
with enough of the others it opens a barrier. This is how you hold it and how
you use it.

The operator's side — creating the group, deciding how many pieces there are —
is [`../../../docs/share-custody/user.md`](../../../docs/share-custody/user.md).

## Receiving your share

If it was delivered to you through the system:

```
xkey share receive --server grpc://kms.example.com:9090
```

If it was handed to you as a file:

```
xkey share import --file alice.share.json
```

Then check:

```
xkey share list -o json
```

## Contributing to an unseal

```
xkey share unseal --server grpc://kms.example.com:9090 --group-id grp-1 --share-index 2
```

**This submits your share. It does not unseal the barrier.** The server collects
shares until it has enough; yours is one of them.

You do not need to be on a call with the other custodians. Everyone submits when
they can, and the barrier opens when the threshold is reached. A response saying
the quorum is still below threshold means your part worked.

There is a time limit — if a collection stalls long enough, it resets and
everyone submits again.

## Backing it up

```
xkey share export --server grpc://kms.example.com:9090 \
    --group-id grp-1 --share-index 2 --file alice.share.json
```

This writes your share to a plain file. Treat that file the way you would treat a
private key: it is a real piece of the key, and it is now outside xkey's
protection.

Then put it somewhere that will still exist and still be findable in a year —
and somewhere different from where the other custodians keep theirs. The whole
point of a threshold is that the pieces are separated.

## Holding shares for more than one system

Every command takes `--server` because you will eventually hold index 2 for two
different deployments. Naming the server every time is what makes submitting one
to the other impossible rather than just unlikely.

```
xkey share list -o json     # shows which server each share belongs to
```

## If you script this

`xkey share --share-index` is documented as **1-based**. If you are also
scripting `xkmsctl share`, check the base there rather than assuming they match.

## Removing a share

```
xkey share delete --server grpc://kms.example.com:9090 --group-id grp-1 --share-index 2
```

Gone from this device. **Nothing reissues it** — not the operator, not the
server. If you delete it and have no export, your piece is lost. That is
survivable if enough other custodians remain; below the threshold it is not.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| "below threshold" | your submission counted; not enough others yet | nothing — chase the other custodians |
| share rejected as invalid | the file is corrupt or truncated | re-import from a good copy |
| share rejected — wrong group | wrong `--server` or `--group-id` | `xkey share list` shows what you hold |
| "already submitted" | that index has already counted | your part is done; a different holder is needed |
| quorum expired | the collection window elapsed | everyone submits again |
| your share stopped working | the barrier was rekeyed | you need the new share |
| you deleted it and have no export | it cannot be reissued | tell the operator; below threshold this is serious |

## Where to go next

- What the shares open: [`../../../docs/sealing-and-barrier/user.md`](../../../docs/sealing-and-barrier/user.md)
- Where your share came from: [`../../../docs/init-ceremony/user.md`](../../../docs/init-ceremony/user.md)
- The operator's view: [`../../../docs/share-custody/user.md`](../../../docs/share-custody/user.md)
