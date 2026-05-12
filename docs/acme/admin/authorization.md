# Admin API Authorization

The Admin API implements a Role-Based Access Control (RBAC) authorization model powered by QRDB IAM.

## Authorization Model

```
+------------------------------------------------------------------------------+
|                        RBAC Authorization Model                              |
+------------------------------------------------------------------------------+
|                                                                              |
|   Request                                                                    |
|      |                                                                       |
|      v                                                                       |
|   +----------------------------------------------------------------------+   |
|   |                    Authentication Layer                              |   |
|   |                    (JWT Token Validation)                            |   |
|   +----------------------------------------------------------------------+   |
|      |                                                                       |
|      | Extract: UserID, TenantID, Roles, Groups, Permissions                 |
|      v                                                                       |
|   +----------------------------------------------------------------------+   |
|   |                    RBAC Quick Check                                  |   |
|   |                    (Role Level Validation)                           |   |
|   |                                                                      |   |
|   |   super-admin (100) > admin (80) > endorser (60) >                   |   |
|   |   operator (40) > viewer (20)                                        |   |
|   +----------------------------------------------------------------------+   |
|      |                                                                       |
|      | If RBAC passes, continue to policy evaluation                         |
|      v                                                                       |
|   +----------------------------------------------------------------------+   |
|   |                    RBAC Policy Evaluation                            |   |
|   |                    (QRDB PolicyEngine)                               |   |
|   |                                                                      |   |
|   |   1. Build CheckRequest (subject, resource, action, context)         |   |
|   |   2. Evaluate deny policies first                                    |   |
|   |   3. Evaluate allow policies                                         |   |
|   |   4. Default deny if no match                                        |   |
|   +----------------------------------------------------------------------+   |
|      |                                                                       |
|      v                                                                       |
|   Allow / Deny                                                               |
|                                                                              |
+------------------------------------------------------------------------------+
```

## Role-Based Access Control (RBAC)

### Role Hierarchy

The Admin API defines five roles in a hierarchical structure. Higher-level roles inherit all permissions from lower levels.

```
+----------------+
|  super-admin   |  Level: 100
|  (Global)      |
+-------+--------+
        |
        v
+----------------+
|     admin      |  Level: 80
|   (Tenant)     |
+-------+--------+
        |
        v
+----------------+
|   endorser     |  Level: 60
|   (Device)     |
+-------+--------+
        |
        v
+----------------+
|   operator     |  Level: 40
|  (Read/Write)  |
+-------+--------+
        |
        v
+----------------+
|    viewer      |  Level: 20
|  (Read-Only)   |
+----------------+
```

### Role Definitions

#### Super-Admin (Level 100)

Global system administrator with unrestricted access.

| Capability | Description |
|------------|-------------|
| Manage Tenants | Create, update, delete tenants |
| Manage Root CA | Configure global root CA |
| System Config | Modify system-wide settings |
| Cross-Tenant Access | Access any tenant's resources |
| All Lower Permissions | Inherits all admin permissions |

```go
func (r Role) CanManageTenants() bool {
    return r == RoleSuperAdmin
}

func (r Role) CanManageRootCA() bool {
    return r == RoleSuperAdmin
}
```

#### Admin (Level 80)

Tenant-level administrator with full control within their tenant.

| Capability | Description |
|------------|-------------|
| Manage Tenant CA | Create intermediate CAs for tenant |
| Revoke Certificates | Revoke any certificate in tenant |
| Disable Accounts | Disable ACME accounts in tenant |
| Manage Policies | Create and modify RBAC policies |
| Manage EABs | Full EAB lifecycle management |
| All Lower Permissions | Inherits all endorser permissions |

```go
func (r Role) CanManageTenantCA() bool {
    return r == RoleSuperAdmin || r == RoleAdmin
}

func (r Role) CanRevokeAccess() bool {
    return r == RoleSuperAdmin || r == RoleAdmin
}
```

#### Endorser (Level 60)

Device provisioning administrator for TPM/attestation workflows.

| Capability | Description |
|------------|-------------|
| Create EAB | Create EAB tokens for device enrollment |
| Endorse-01 | Provision endorse-01 challenge EABs |
| Enroll-01 | Provision enroll-01 challenge EABs |
| All Lower Permissions | Inherits all operator permissions |

```go
func (r Role) CanCreateEAB() bool {
    return r == RoleSuperAdmin || r == RoleAdmin || r == RoleEndorser
}
```

#### Operator (Level 40)

Standard operator with read/write access but no destructive operations.

| Capability | Description |
|------------|-------------|
| Create Resources | Create accounts, orders |
| Update Resources | Modify non-destructive settings |
| View Resources | Read all tenant resources |
| No Destructive Ops | Cannot delete or revoke |

#### Viewer (Level 20)

Read-only access for monitoring and auditing.

| Capability | Description |
|------------|-------------|
| List Resources | List certificates, accounts, orders |
| View Details | Get individual resource details |
| View Statistics | Access CA status and stats |
| No Modifications | Cannot create, update, or delete |

### Permission Matrix

| Operation | super-admin | admin | endorser | operator | viewer |
|-----------|:-----------:|:-----:|:--------:|:--------:|:------:|
| **Tenant Operations** |||||
| List all tenants | X | - | - | - | - |
| Create tenant | X | - | - | - | - |
| Update tenant | X | X | - | - | - |
| Delete tenant | X | - | - | - | - |
| Update tenant status | X | - | - | - | - |
| **CA Operations** |||||
| Create root CA | X | X | - | - | - |
| Create intermediate CA | X | X | - | - | - |
| Update CA status | X | X | - | - | - |
| Set default CA | X | X | - | - | - |
| **Certificate Operations** |||||
| List certificates | X | X | X | X | X |
| Get certificate | X | X | X | X | X |
| Revoke certificate | X | X | - | - | - |
| **Account Operations** |||||
| List accounts | X | X | X | X | X |
| Get account | X | X | X | X | X |
| Disable account | X | X | - | - | - |
| **EAB Operations** |||||
| List EABs | X | X | X | - | - |
| Create EAB | X | X | X | - | - |
| Get EAB | X | X | X | - | - |
| Delete EAB | X | X | - | - | - |
| **Policy Operations** |||||
| List policies | X | X | - | - | - |
| Create policy | X | X | - | - | - |
| Update policy | X | X | - | - | - |
| Delete policy | X | X | - | - | - |
| **Status Operations** |||||
| Get CA status | X | X | X | X | X |
| Get CA statistics | X | X | X | X | X |

### RBAC Implementation

The RBAC middleware enforces role requirements:

```go
// RequireRole creates a middleware that requires a minimum role level
func RequireRole(minRole Role) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            role, ok := r.Context().Value(ContextKeyRole).(Role)
            if !ok {
                writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
                return
            }

            if role.Level() < minRole.Level() {
                writeError(w, http.StatusForbidden, "FORBIDDEN", "Insufficient privileges")
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

Usage in route registration:

```go
// Certificate revocation requires admin role
revokeRouter := adminRouter.PathPrefix("/certificates/{serial}/revoke").Subrouter()
revokeRouter.Use(RequireRole(RoleAdmin))
revokeRouter.HandleFunc("", h.RevokeCertificate).Methods("POST")

// Tenant deletion requires super-admin role
deleteRouter := tenantsRouter.PathPrefix("/{id}").Subrouter()
deleteRouter.Use(RequireRole(RoleSuperAdmin))
deleteRouter.HandleFunc("", h.DeleteTenant).Methods("DELETE")
```

## RBAC Policy Definitions

RBAC policies provide fine-grained access control using policies that evaluate attributes of the subject, resource, action, and environment.

### Policy Structure

Policies follow the QRDB IAM format:

```yaml
apiVersion: rbac.qrdb.io/v1
kind: Policy
metadata:
  name: policy-name
  tenant: tenant-id
  description: Policy description
  priority: 100
  labels:
    purpose: access-control
    managed: system
spec:
  subjects:
    roles: [admin, operator]
    groups: [engineering]
    authenticated: true
  rules:
    - name: rule-name
      effect: allow  # or deny
      priority: 100
      actions: [read, write, delete]
      resources:
        - acme/tenants/{tenant}/**
      when:
        - expression: "subject.role == 'admin'"
      unless:
        - expression: "context.ip starts_with '192.168.'"
```

### Policy Components

#### Subject Selector

Defines who the policy applies to:

```yaml
spec:
  subjects:
    # Match specific roles
    roles:
      - super-admin
      - admin

    # Match specific groups
    groups:
      - engineering
      - operations

    # Match any authenticated user
    authenticated: true
```

#### Rules

Define the access control logic:

```yaml
rules:
  - name: allow-read-own-tenant
    effect: allow
    priority: 100
    actions:
      - read
      - list
    resources:
      - acme/tenants/{tenant}/certificates/**
      - acme/tenants/{tenant}/accounts/**
    when:
      - expression: "subject.tenant_id == resource.tenant_id"
```

#### Conditions

Fine-grained conditions using expressions:

| Operator | Description | Example |
|----------|-------------|---------|
| `==` | Equals | `subject.role == 'admin'` |
| `!=` | Not equals | `subject.tenant_id != 'default'` |
| `in` | In list | `subject.role in ['admin', 'operator']` |
| `contains` | Contains | `subject.roles contains 'admin'` |
| `starts_with` | Prefix match | `resource.path starts_with '/admin'` |
| `ends_with` | Suffix match | `resource.path ends_with '/revoke'` |

### Default Policies

When a tenant is created, default policies are automatically provisioned:

#### Tenant Isolation Policy

Ensures users can only access resources within their own tenant:

```yaml
apiVersion: rbac.qrdb.io/v1
kind: Policy
metadata:
  name: tenant-isolation
  tenant: {tenant_id}
  description: Default tenant isolation policy
  priority: 9999
  labels:
    purpose: tenant-isolation
    managed: system
    immutable: "true"
spec:
  subjects:
    authenticated: true
  rules:
    - name: allow-own-tenant
      effect: allow
      priority: 100
      actions: ["*"]
      resources:
        - "{tenant_id}/**"

    - name: deny-cross-tenant
      effect: deny
      priority: 9999
      actions: ["*"]
      resources: ["*"]
      unless:
        - expression: "subject.tenant_id == '{tenant_id}'"
        - expression: "subject.roles contains 'super-admin'"
```

#### EAB Creation Policy

Controls who can create External Account Binding tokens:

```yaml
apiVersion: rbac.qrdb.io/v1
kind: Policy
metadata:
  name: eab-creation
  tenant: {tenant_id}
  description: Default EAB creation policy
  priority: 100
  labels:
    purpose: eab-creation
    managed: system
spec:
  subjects:
    roles:
      - super-admin
      - admin
      - endorser
  rules:
    - name: allow-eab-creation
      effect: allow
      priority: 100
      actions: [create, write]
      resources:
        - acme/tenants/{tenant_id}/eab/**

    - name: allow-eab-read
      effect: allow
      priority: 99
      actions: [read, list]
      resources:
        - acme/tenants/{tenant_id}/eab/**
```

#### Endorse-01 Policy

Allows endorsers to create endorse-01 EAB tokens:

```yaml
apiVersion: rbac.qrdb.io/v1
kind: Policy
metadata:
  name: endorse-01-access
  tenant: {tenant_id}
  description: Allows endorser to create endorse-01 EAB tokens
  priority: 150
  labels:
    purpose: endorse-01
    managed: system
spec:
  subjects:
    roles:
      - super-admin
      - admin
      - endorser
  rules:
    - name: allow-endorse01-eab
      effect: allow
      priority: 100
      actions: [create]
      resources:
        - acme/tenants/{tenant_id}/eab/endorse-01/**
```

### Custom Policies

Tenants can create custom policies for advanced access control scenarios.

#### Business Hours Restriction

Restrict sensitive operations to business hours:

```yaml
apiVersion: rbac.qrdb.io/v1
kind: Policy
metadata:
  name: business-hours-restriction
  tenant: acme-corp
  description: Restricts sensitive operations to business hours
  priority: 200
  labels:
    purpose: business-hours
    managed: user
spec:
  subjects:
    authenticated: true
  variables:
    start_hour: "9"
    end_hour: "17"
  rules:
    - name: allow-during-business-hours
      effect: allow
      priority: 100
      actions: [create, write, delete]
      resources:
        - acme/tenants/acme-corp/**
      when:
        - expression: "time.hour >= 9"
        - expression: "time.hour < 17"

    - name: deny-outside-business-hours
      effect: deny
      priority: 200
      actions: [create, write, delete]
      resources:
        - acme/tenants/acme-corp/**
```

#### Network Restriction

Restrict operations by IP range:

```yaml
apiVersion: rbac.qrdb.io/v1
kind: Policy
metadata:
  name: network-restriction
  tenant: acme-corp
  description: Restricts operations to allowed IP ranges
  priority: 300
  labels:
    purpose: network-restriction
    managed: user
spec:
  subjects:
    authenticated: true
  rules:
    - name: allow-from-internal
      effect: allow
      priority: 100
      actions: ["*"]
      resources:
        - acme/tenants/acme-corp/**
      when:
        - expression: "request.ip in ['10.0.0.0/8']"
        - expression: "request.ip in ['192.168.0.0/16']"

    - name: deny-from-external
      effect: deny
      priority: 300
      actions: ["*"]
      resources:
        - acme/tenants/acme-corp/**
```

### Policy Evaluation

The RBAC engine evaluates policies in order:

1. **Collect Applicable Policies**: Find policies matching subject roles/groups
2. **Sort by Priority**: Higher priority rules evaluated first
3. **Evaluate Deny Rules**: Any deny match results in immediate denial
4. **Evaluate Allow Rules**: First allow match grants access
5. **Default Deny**: If no rules match, access is denied

```go
// Authorization middleware evaluation
func (am *AuthorizationMiddleware) Authorize(action, resource string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := GetUserFromContext(r.Context())

            // Build IAM check request
            checkReq := &iam.CheckRequest{
                Subject: iam.Subject{
                    ID:            user.UserID,
                    TenantID:      user.TenantID,
                    Roles:         user.Roles,
                    Groups:        user.Groups,
                    Authenticated: true,
                    Attributes:    buildSubjectAttributes(user),
                },
                Resource: resource,
                Action:   action,
                Context:  buildRequestContext(r),
            }

            // Evaluate against all applicable policies
            response, err := am.policyEngine.Evaluate(r.Context(), checkReq)
            if err != nil {
                writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Authorization check failed")
                return
            }

            if !response.Allowed {
                writeError(w, http.StatusForbidden, "FORBIDDEN", response.Reason)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

## Tenant Isolation

### Isolation Mechanisms

1. **Key Prefix Separation**: All tenant data uses prefixed keys
2. **Context Propagation**: TenantID flows through all operations
3. **Policy Enforcement**: Default isolation policy prevents cross-tenant access
4. **API Scoping**: Most endpoints operate within tenant context

### Cross-Tenant Access

Only super-admins can access resources across tenants:

```go
func RequireTenant(getTenantID func(r *http.Request) string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := GetUserFromContext(r.Context())
            tenantID := getTenantID(r)

            // Super-admins can access any tenant
            if user.Role != RoleSuperAdmin && user.TenantID != tenantID {
                writeError(w, http.StatusForbidden, "FORBIDDEN", "Cannot access tenant")
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

## Resource Constants

The Admin API defines standard resource paths for policy targeting:

```go
const (
    ResourceTenants      = "acme/tenants"
    ResourceTenantCA     = "acme/tenants/{tenant}/ca"
    ResourceTenantEAB    = "acme/tenants/{tenant}/eab"
    ResourceCertificates = "acme/certificates"
    ResourceAccounts     = "acme/accounts"
    ResourceOrders       = "acme/orders"
    ResourceStatus       = "acme/status"
    ResourceStats        = "acme/stats"
    ResourcePolicies     = "acme/tenants/{tenant}/policies"
)
```

## Action Constants

Standard actions for authorization checks:

```go
const (
    ActionRead   = "read"
    ActionWrite  = "write"
    ActionDelete = "delete"
    ActionAdmin  = "admin"
    ActionList   = "list"
    ActionRevoke = "revoke"
    ActionCreate = "create"
    ActionUpdate = "update"
)
```

## Best Practices

### Role Assignment

1. **Minimum Privilege**: Assign the lowest role that meets requirements
2. **Role Separation**: Use different accounts for different functions
3. **Regular Audit**: Review role assignments periodically

### Policy Design

1. **Explicit Allow**: Define what is allowed, not what is denied
2. **High Priority Denies**: Use high-priority deny rules for security boundaries
3. **Descriptive Names**: Use clear, descriptive policy and rule names
4. **Documentation**: Document the purpose of each custom policy

### Security Considerations

1. **Immutable System Policies**: Never modify system-managed policies
2. **Test Policies**: Test policies in a non-production environment first
3. **Audit Logging**: Enable audit logging for all authorization decisions
4. **Regular Review**: Review and update policies as requirements change
