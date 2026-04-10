# Custodian Groups

The `pkg/custodian` package provides M-of-N custodian group management for key ceremony participation and share distribution. Custodian groups track which users hold Shamir shares, when shares were assigned, and whether they have been received. This supports FIPS 140-2/3 and PCI DSS separation of duties requirements.

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

### CustodianGroup

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Unique group identifier |
| `TenantID` | `string` | Tenant scope (empty = system-level) |
| `Name` | `string` | Human-readable group name |
| `Purpose` | `string` | `"barrier"`, `"signing-key"`, or `"backup"` |
| `Threshold` | `int` | M (minimum shares to reconstruct) |
| `Total` | `int` | N (total shares) |
| `Members` | `[]CustodianMember` | Group members |

### CustodianMember

| Field | Type | Description |
|-------|------|-------------|
| `ShareIndex` | `int` | 1-based share index |
| `UserID` | `string` | User identifier |
| `Username` | `string` | Display name |
| `AssignedAt` | `time.Time` | When share was assigned |
| `ReceivedAt` | `*time.Time` | When share was picked up (nil = pending) |
| `Method` | `string` | Delivery method: `"fido2"`, `"pkcs11"`, `"manual"` |

## Service API

| Method | Description |
|--------|-------------|
| `NewService(store)` | Creates service backed by a `CustodianGroupStore` |
| `CreateGroup(ctx, id, tenantID, name, purpose, threshold, total)` | Creates and validates a new group |
| `GetGroup(ctx, id)` | Retrieves a group by ID |
| `DeleteGroup(ctx, id)` | Deletes a group |
| `AddMember(ctx, groupID, userID, username, method)` | Adds a member to a group |
| `RemoveMember(ctx, groupID, userID)` | Removes a member |
| `MarkShareReceived(ctx, groupID, userID)` | Marks a member's share as received |
| `ListGroups(ctx)` | Returns all groups |
| `ListGroupsByTenant(ctx, tenantID)` | Returns groups for a tenant |

## CustodianGroupStore Interface

| Method | Description |
|--------|-------------|
| `Create(ctx, group)` | Persists a new group |
| `Get(ctx, id)` | Retrieves group by ID |
| `Update(ctx, group)` | Updates an existing group |
| `Delete(ctx, id)` | Removes a group |
| `List(ctx)` | Returns all groups |
| `ListByTenant(ctx, tenantID)` | Groups by tenant |
| `ListByPurpose(ctx, purpose)` | Groups by purpose |

A `MemoryStore` implementation is provided for testing.

## Usage

```go
store := custodian.NewMemoryStore()
svc, _ := custodian.NewService(store)

group, _ := svc.CreateGroup(ctx, "grp-1", "", "Barrier Custodians",
    custodian.PurposeBarrier, 3, 5)

member, _ := svc.AddMember(ctx, "grp-1", "user-42", "alice", custodian.MethodFIDO2)
// member.ShareIndex == 1, member.ReceivedAt == nil

svc.MarkShareReceived(ctx, "grp-1", "user-42")
// member.ReceivedAt is now set
```

## Error Reference

| Error | Condition |
|-------|-----------|
| `ErrGroupNotFound` | Group ID not found |
| `ErrGroupAlreadyExists` | Duplicate group ID |
| `ErrGroupFull` | Group at maximum capacity |
| `ErrMemberNotFound` | User not in group |
| `ErrMemberAlreadyExists` | User already in group |
| `ErrInvalidThreshold` | Threshold < 2 or > total |
| `ErrShareAlreadyReceived` | Share already marked received |
| `ErrNilStore` | Nil store passed to `NewService` |

## Cross-References

- [Barrier Encryption Architecture](../seal/README.md) -- Shamir secret sharing for barrier root keys
- [Key Share Persistence](../sharestore/README.md) -- storing received shares on client side
