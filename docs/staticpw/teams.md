# Team Passwords

Team passwords enable group-based credential sharing with role-based access control. This document covers team creation, membership management, and shared password access.

## Concepts

A **team** is a group of users who can collectively access shared passwords. Teams have:
- **Owner**: Single user who can add/remove members and manage team passwords
- **Members**: List of user IDs with read-only access to team passwords
- **Passwords**: Shared credentials marked with `OwnerID = team_name` and `Shared = true`

## Team Management

### Create a Team

```go
import "github.com/jeremyhahn/go-xkms/pkg/staticpw"

teamStore, err := staticpw.NewDAOTeamStore(kvStore)

ctx := context.Background()
team := &staticpw.TeamEntity{
    Name:    "engineering",
    TenantID: "tenant-1",
    OwnerID: "alice@company.com",
}
err = teamStore.Create(ctx, team)
```

Team names must be unique within a tenant. The creation timestamp is set automatically.

### List Teams

```go
// All teams in the system
teams, err := teamStore.List(ctx)

// All teams for a specific tenant
teams, err := teamStore.ListByTenant(ctx, "tenant-1")
```

### Retrieve a Team

```go
team, err := teamStore.Get(ctx, "engineering")
```

### Update Team (Metadata)

```go
team, _ := teamStore.Get(ctx, "engineering")
// Update fields like OwnerID if ownership transfers
team.OwnerID = "bob@company.com"
err = teamStore.Update(ctx, team)
```

The ID and CreatedAt timestamps are preserved during updates.

### Delete a Team

```go
err = teamStore.Delete(ctx, "engineering")
```

Deleting a team does not delete associated passwords; they remain in the password store.

## Membership Management

### Add a Member

```go
err = teamStore.AddMember(ctx, "engineering", "charlie@company.com")
// Idempotent: adding an existing member is a no-op
```

Members are appended to the team's Members slice if not already present.

### Check Membership

```go
isMember := teamStore.IsMember(ctx, "engineering", "charlie@company.com")
if isMember {
    // User can access team passwords
}
```

Returns false if the team doesn't exist or the user is not a member.

### Remove a Member

```go
err = teamStore.RemoveMember(ctx, "engineering", "charlie@company.com")
// Idempotent: removing non-member is a no-op
```

### RBAC Model

| Role       | Create Team | Manage Members | Read Passwords | Write Passwords |
|------------|-------------|----------------|----------------|-----------------|
| Owner      | N/A         | Yes            | Yes            | Yes             |
| Member     | N/A         | No             | Yes            | No              |
| Non-Member | N/A         | No             | No             | No              |

## Team-Scoped Passwords

The `TeamScopedStore` wraps password and team stores to enforce team access rules:

```go
pwStore, _ := staticpw.NewDAOStore(kvStore)
teamStore, _ := staticpw.NewDAOTeamStore(kvStore)

scoped, err := staticpw.NewTeamScopedStore(pwStore, teamStore, "alice@company.com")
```

The third argument is the current user ID for permission checks.

### List Team Passwords

```go
passwords, err := scoped.ListTeamPasswords(ctx, "engineering")
// Returns passwords where OwnerID="engineering" and Shared=true
// User must be a member or owner
```

### Add Password to Team (Owner Only)

```go
password := &staticpw.StaticPassword{
    Name:     "database-prod",
    Username: "dbadmin",
    Password: "secret123",
    // ... other fields
}
err := scoped.AddTeamPassword(ctx, "engineering", password)
// Sets OwnerID="engineering", Shared=true
// Only team owner can perform this
```

### Get a Team Password

```go
password, err := scoped.GetTeamPassword(ctx, "engineering", "database-prod")
// User must be a member or owner
```

### Delete Password from Team (Owner Only)

```go
err := scoped.DeleteTeamPassword(ctx, "engineering", "database-prod")
// Only team owner can perform this
```

## Multi-Tenant Teams

Teams are tenant-scoped. Each team has a `TenantID` field:

```go
// List teams in a specific tenant
teams, err := teamStore.ListByTenant(ctx, "tenant-1")

// Create tenant-aware team
team := &staticpw.TeamEntity{
    Name:     "engineering",
    TenantID: "tenant-1",
    OwnerID:  "alice@company.com",
}
teamStore.Create(ctx, team)
```

The `TenantDAOFactory` provides per-tenant team stores:

```go
factory, _ := staticpw.NewTenantDAOFactory(systemKVStore, barrierRegistry)

// Get team store for tenant
teamStore, _ := factory.TeamStoreForTenant("tenant-1")
teams, _ := teamStore.List(ctx)  // Only teams in tenant-1
```

## REST API Endpoints

Team operations are exposed through REST handlers:

```
POST   /v1/teams                    Create team
GET    /v1/teams/{name}             Get team
GET    /v1/teams                    List teams
PATCH  /v1/teams/{name}             Update team
DELETE /v1/teams/{name}             Delete team

POST   /v1/teams/{name}/members     Add member
DELETE /v1/teams/{name}/members/{id} Remove member

GET    /v1/teams/{name}/passwords   List team passwords
POST   /v1/teams/{name}/passwords   Add password to team
GET    /v1/teams/{name}/passwords/{id} Get team password
DELETE /v1/teams/{name}/passwords/{id} Delete from team
```

## Error Handling

```go
team, err := teamStore.Get(ctx, "unknown")
if err == staticpw.ErrTeamNotFound {
    // Team doesn't exist
}

err = teamStore.Create(ctx, "", owner)
if err == staticpw.ErrTeamNameEmpty {
    // Name is required
}

err = scoped.AddTeamPassword(ctx, "engineering", pwd)
if err == staticpw.ErrNotTeamOwner {
    // Only owner can add passwords
}

err = scoped.ListTeamPasswords(ctx, "engineering")
if err == staticpw.ErrNotTeamMember {
    // User is not a member or owner
}
```

## Pagination

For systems with many teams:

```go
pageResult, err := teamStore.Page(ctx, dao.PageQuery{
    Page:     1,
    PageSize: 50,
})
```

## Security Considerations

1. **Owner isolation**: Only the team owner can modify team membership and add/remove passwords
2. **Member isolation**: Members can read but not modify team passwords
3. **Audit logging**: Log team creation, membership changes, and password access
4. **Barrier encryption**: All team data is encrypted with the tenant's DEK when using TenantDAOFactory
5. **Access revocation**: Removing a member immediately revokes their access to team passwords
