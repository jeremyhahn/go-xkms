# Share Custody — CLI

> **Status: NORMATIVE** · Feature: `share-custody` · Repo: `go-xkms` · Last verified: 2026-08-19

Binary: `xkmsctl`. Two groups: **`custodian`** (organising the split, operator
side) and **`share`** (holding and submitting, custodian side). Sources:
`cmd/xkmsctl/custodian.go`, `cmd/xkmsctl/share.go`. Global flags:
[`../key-management/cli.md`](../key-management/cli.md).

The desktop equivalent is `xkey share list|receive|import|export|unseal|delete`.

## `xkmsctl custodian` — the operator side

### `custodian create`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--name` | string | — | **yes** |
| `--threshold` | int | `0` | **yes** — M, minimum shares to unseal |
| `--total` | int | `0` | **yes** — N, shares generated |
| `--purpose` | string | `""` | no |
| `--tenant-id` | string | `""` | no |
| `--id` | string | `""` | no — auto-generated when omitted |

```
xkmsctl custodian create --name "Production barrier" --threshold 3 --total 5 \
    --purpose "root key custody"
```

M is your security parameter, N your availability parameter. M-1 colluding
holders learn nothing; N-M shares can be lost without consequence. M=N is
maximum security and a guaranteed outage on the first lost share.

### `custodian list` / `show` / `delete`

| Verb | Flags |
|---|---|
| `custodian list` | `--tenant-id` (filter) |
| `custodian show` | `--id` (**required**) |
| `custodian delete` | `--id` (**required**) |

```
xkmsctl custodian list --tenant-id acme
xkmsctl custodian show --id grp-1 -o json
```

**Deleting a group does not un-distribute its shares.** They stay in the
holders' stores until the barrier is rekeyed.

### `custodian add-member` / `remove-member`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--group-id` | string | — | **yes** |
| `--user-id` | string | — | **yes** |
| `--username` | string | `""` | no — display name |
| `--method` | string | `encrypted` | no — `encrypted` or `manual` |

```
xkmsctl custodian add-member --group-id grp-1 --user-id alice \
    --username "Alice" --method encrypted
xkmsctl custodian remove-member --group-id grp-1 --user-id alice
```

`encrypted` delivers to the member's key. `manual` means **you** move the share
out of band. Choosing `manual` and then emailing it is how shares end up in
places you cannot retract them from.

### `custodian distribute`

```
xkmsctl custodian distribute --group-id grp-1
```

The moment the split becomes real. Each member receives their share by their
configured method. **This happens once** — no command reissues a share.

## `xkmsctl share` — the custodian side

### `share submit`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--group-id` | string | — | **yes** |
| `--share-index` | int | `0` | index within the group |
| `--data` | string | `""` | share bytes, base64 |
| `--file` | string | `""` | file containing raw share bytes |
| `--group-name` | string | `""` | no |
| `--server-url` | string | `""` | no — originating server |
| `--purpose` | string | `""` | no |

```
xkmsctl share submit --group-id grp-1 --share-index 2 --file alice.share
```

Submission is **accumulative**: each custodian submits independently and the
server counts toward M. Custodians do not need to be online together.

### `share status`

| Flag | Required |
|---|---|
| `--group-id` | **yes** |

```
xkmsctl share status --group-id grp-1 -o json
```

Reports quorum progress. "Below threshold" is a **state, not an error** — it
means the collection is working and not finished.

### `share list` / `get` / `delete`

`get` and `delete` take the full three-part identity:

| Flag | Required |
|---|---|
| `--server-url` | **yes** |
| `--group-id` | **yes** |
| `--share-index` | index within the group |

```
xkmsctl share list -o json
xkmsctl share get --server-url https://kms.example.com:8443 --group-id grp-1 --share-index 2
xkmsctl share delete --server-url https://kms.example.com:8443 --group-id grp-1 --share-index 2
```

The `--server-url` requirement is not bureaucracy: a custodian who serves two
deployments holds index 2 twice, and submitting one to the other must be
impossible.

## Exit codes

`0` on success. A share below threshold is reported as progress with exit `0`.
Non-zero for an invalid share, a foreign group, a duplicate index, or an expired
quorum.

## Parity coverage

**Defect: no `custodian` or `share` verb has a `CommandDefinition` in
`test/integration/api/commands/commands.go`**, despite all thirteen operations
having routes on REST, gRPC, QUIC and Unix, and the share half also on MCP.
