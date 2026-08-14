# Custodian Groups

A custodian group records *who* holds the Shamir shares of a barrier: an M-of-N
roster naming each share index, the user assigned to it, when the share was
assigned and whether it has been picked up. This is what FIPS 140-2/3 and PCI
DSS separation-of-duties reviews ask for — a named, auditable roster rather than
an anonymous quorum.

Custodian state is owned by the embedded go-qrdb node. `XKMSService`
(`pkg/xkms/servicer_custodian.go`) is a passthrough to the node's custodian
client — xkms performs no local persistence of its own. There is no custodian
storage package in this repository.

## Architecture

```
  CustodianGroup (3-of-5)
    |
    +-- Member 1 (share_index=1, received)
    +-- Member 2 (share_index=2, received)
    +-- Member 3 (share_index=3, pending)
    +-- Member 4 (share_index=4, pending)
    +-- Member 5 (share_index=5, pending)
```

## Types

The transport types are aliases of the go-qrdb SDK types
(`pkg/api/transport/types_custodian.go`), so a value crossing the xkms API is
the same value the node stores.

### CustodianGroupInfo

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Unique group identifier |
| `TenantID` | `string` | Tenant scope (empty, or the reserved `system` tenant, = system-level; see auth.IsCrossTenant) |
| `Name` | `string` | Human-readable group name |
| `Purpose` | `string` | What the group's shares protect |
| `Threshold` | `int` | M (minimum shares to reconstruct) |
| `Total` | `int` | N (total shares) |
| `Members` | `[]CustodianMemberInfo` | Group members |
| `CreatedAt` | `time.Time` | Group creation time |
| `UpdatedAt` | `time.Time` | Last modification time |

### CustodianMemberInfo

| Field | Type | Description |
|-------|------|-------------|
| `ShareIndex` | `int` | 1-based share index |
| `UserID` | `string` | User identifier |
| `Username` | `string` | Display name |
| `AssignedAt` | `time.Time` | When share was assigned |
| `ReceivedAt` | `*time.Time` | When share was picked up (nil = pending) |
| `Method` | `string` | Delivery method |

## Service API

`CustodianGroupServicer` (`pkg/xkms/servicer_custodian.go`) is the interface
every transport is served from:

| Method | Description |
|--------|-------------|
| `CreateCustodianGroup(ctx, req)` | Creates a group with threshold parameters |
| `GetCustodianGroup(ctx, groupID)` | Retrieves a group by ID |
| `ListCustodianGroups(ctx)` | Returns all registered groups |
| `DeleteCustodianGroup(ctx, groupID)` | Deletes a group by ID |
| `AddCustodianMember(ctx, req)` | Adds a member to a group |
| `RemoveCustodianMember(ctx, req)` | Removes a member from a group |
| `DistributeShares(ctx, req)` | Distributes Shamir shares to group members |

Every method fails with `ErrNotConfigured` (`pkg/xkms/errors.go`) when the
custodian client is absent, and the request-taking methods fail with
`ErrNilRequest` on a nil request. Domain errors — unknown group, duplicate
member, bad threshold — come back from the node.

## REST

The routes are registered inside the versioned `/api/v1` router
(`pkg/api/rest/server.go:629`), under `/custodian/groups`, and only when the
custodian handlers were built, which the `Config.CustodianEnabled` flag gates
(`pkg/api/rest/server.go:212` and `:475-476`; route table at `:971-982`).
`CustodianEnabled` is to be set only when the embedded qrdb node is available.
The full paths are therefore:

| Method | Path |
|--------|------|
| `POST` | `/api/v1/custodian/groups` |
| `GET` | `/api/v1/custodian/groups` |
| `GET` | `/api/v1/custodian/groups/{id}` |
| `DELETE` | `/api/v1/custodian/groups/{id}` |
| `POST` | `/api/v1/custodian/groups/{id}/members` |
| `DELETE` | `/api/v1/custodian/groups/{id}/members/{userID}` |
| `POST` | `/api/v1/custodian/groups/{id}/distribute` |

## CLI

`xkmsctl custodian` (`cmd/xkmsctl/custodian.go`). Every subcommand takes its
arguments as flags -- there are no positional arguments:

```bash
xkmsctl custodian create --name "Ops Team" --purpose "production barrier" --threshold 3 --total 5
xkmsctl custodian create --name "DR Group" --threshold 2 --total 3 --tenant-id acme --id dr-group
xkmsctl custodian list
xkmsctl custodian show --id <group-id>
xkmsctl custodian delete --id <group-id>
xkmsctl custodian add-member --group-id <group-id> --user-id <user-id> [--username alice] [--method encrypted]
xkmsctl custodian remove-member --group-id <group-id> --user-id <user-id>
xkmsctl custodian distribute --group-id <group-id>
```

| Subcommand | Flags | Required |
|------------|-------|----------|
| `create` | `--name`, `--purpose`, `--threshold`, `--total`, `--tenant-id`, `--id` | `--name`, `--threshold`, `--total` |
| `list` | `--tenant-id` | none |
| `show` | `--id` | `--id` |
| `delete` | `--id` | `--id` |
| `add-member` | `--group-id`, `--user-id`, `--username`, `--method` | `--group-id`, `--user-id` |
| `remove-member` | `--group-id`, `--user-id` | `--group-id`, `--user-id` |
| `distribute` | `--group-id` | `--group-id` |

`--method` defaults to `encrypted` (the other accepted value is `manual`);
`--id` on `create` is optional and the group ID is generated when it is
omitted. `create` rejects a threshold that is zero, negative, or greater than
`--total` before any request leaves the client.

`list --tenant-id` is registered as a flag but is not yet wired: the run
function calls `custodianList(cfg, printer)` without it
(`cmd/xkmsctl/custodian.go:94-99`), and `ListCustodianGroups` takes no filter
argument (`pkg/xkms/servicer_custodian.go:58`). `list` therefore always
returns every group the caller is authorized to see.

## Cross-References

- [Share Collection Plane](shares.md) -- submitting, inspecting, and removing returned shares
- [Barrier Encryption Architecture](../seal/README.md) -- Shamir secret sharing for barrier root keys
- [Key Share Persistence](../sharestore/README.md) -- storing received shares on client side
