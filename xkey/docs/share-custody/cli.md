# Share Custody Client — CLI

> **Status: NORMATIVE** · Feature: `share-custody` · Module: `go-xkms/xkey` · Last verified: 2026-09-25

Binary: `xkey`, group `share` (`xkey/cmd/xkey/cmd/share.go`). The operator's
side — creating groups and distributing shares — is `xkmsctl custodian`, in
[`../../../docs/share-custody/cli.md`](../../../docs/share-custody/cli.md).

Persistent flag on the whole group, inherited by every subcommand below:
`--tls-ca` (PEM CA bundle used to verify the xkmsd server; empty uses the
default trust chain).

## `xkey share list`

No flags. What this device holds, per server, group and index. Start here.

```
xkey share list -o json
```

## `xkey share receive`

| Flag | Type | Purpose |
|---|---|---|
| `--server` | string | xkmsd server URL, e.g. `grpc://kms.example.com:9090` |

```
xkey share receive --server grpc://kms.example.com:9090
```

Collects a share delivered to you through the `encrypted` method.

## `xkey share import`

| Flag | Type | Purpose |
|---|---|---|
| `--file` | string | JSON file containing the share |

```
xkey share import --file alice.share.json
```

For shares delivered out of band (the `manual` method).

## `xkey share export`

| Flag | Type | Purpose |
|---|---|---|
| `--server` | string | the xkmsd server that issued the share |
| `--group-id` | string | custodian group |
| `--share-index` | int | **1-based** index within the group |
| `--file` | string | output path for the exported JSON |

```
xkey share export --server grpc://kms.example.com:9090 \
    --group-id grp-1 --share-index 2 --file alice.share.json
```

This is your backup and transfer path. It is also the one command that writes
share material to a plain file, so put the result somewhere you would put a key.

## `xkey share unseal`

| Flag | Type | Purpose |
|---|---|---|
| `--server` | string | server to submit to |
| `--group-id` | string | custodian group |
| `--share-index` | int | 1-based index |

```
xkey share unseal --server grpc://kms.example.com:9090 --group-id grp-1 --share-index 2
```

**This submits one share; it does not unseal the barrier.** The server
accumulates shares until M have arrived. You do not need to coordinate a time
with the other custodians — everyone submits when they can.

A "below threshold" response means it worked and the collection is not finished.

## `xkey share delete`

| Flag | Type | Purpose |
|---|---|---|
| `--server` | string | issuing server |
| `--group-id` | string | custodian group |
| `--share-index` | int | 1-based index |

```
xkey share delete --server grpc://kms.example.com:9090 --group-id grp-1 --share-index 2
```

Removes it from this device. Nothing reissues it.

## Why every verb wants `--server`

If you hold shares for two deployments, you hold index 2 twice. Naming the
server on every operation is what makes submitting one to the other impossible
rather than merely unlikely.

## Index bases differ between the two CLIs

`xkey share`'s `--share-index` is documented as **1-based**. When scripting
across `xkey share` and `xkmsctl share`, check the base rather than assuming
they agree.

## Exit codes

`0` on success — including a submission below threshold, which is progress
rather than failure. Non-zero for an invalid share, a share belonging to another
group or server, a duplicate index, or an expired quorum.

## Parity coverage

The `go-xkms` parity runner covers `xkmsctl`. Coverage here is the server-side
`pkg/sharestore` and handler suites plus the xkey CLI paths.
