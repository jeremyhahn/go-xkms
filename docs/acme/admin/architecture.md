# Admin API Architecture

## System Overview

```
+------------------------------------------------------------------------------+
|                           go-xkms Admin API                            |
+------------------------------------------------------------------------------+
|                                                                              |
|  +------------------------------------------------------------------------+  |
|  |                          HTTP Layer                                    |  |
|  |                                                                        |  |
|  |  +------------------+  +------------------+  +------------------+       |  |
|  |  |  Admin Handlers  |  | Tenant Handlers  |  | Policy Handlers  |       |  |
|  |  |                  |  |                  |  |                  |       |  |
|  |  | /admin/*         |  | /api/v1/tenants  |  | /api/v1/tenants  |       |  |
|  |  | Certificates     |  | CRUD operations  |  | /{id}/policies   |       |  |
|  |  | Accounts         |  | CA management    |  | RBAC policies    |       |  |
|  |  | Orders           |  | EAB management   |  |                  |       |  |
|  |  | Status/Stats     |  |                  |  |                  |       |  |
|  |  +------------------+  +------------------+  +------------------+       |  |
|  +------------------------------------------------------------------------+  |
|                                    |                                         |
|                                    v                                         |
|  +------------------------------------------------------------------------+  |
|  |                      Middleware Layer                                  |  |
|  |                                                                        |  |
|  |  +------------------+  +------------------+  +------------------+       |  |
|  |  | AuthMiddleware   |  | AuthzMiddleware  |  | RequireRole      |       |  |
|  |  |                  |  |                  |  | RequireOperation |       |  |
|  |  | JWT validation   |  | RBAC evaluation  |  | RequireTenant    |       |  |
|  |  | Token parsing    |  | Policy engine    |  |                  |       |  |
|  |  | User context     |  | Access control   |  |                  |       |  |
|  |  +------------------+  +------------------+  +------------------+       |  |
|  +------------------------------------------------------------------------+  |
|                                    |                                         |
|                                    v                                         |
|  +------------------------------------------------------------------------+  |
|  |                       Service Layer                                    |  |
|  |                                                                        |  |
|  |  +------------------+  +------------------+  +------------------+       |  |
|  |  |  AdminService    |  | TenantService    |  | PolicyEngine     |       |  |
|  |  |                  |  |                  |  | (QRDB RBAC)      |       |  |
|  |  | Certificate ops  |  | Tenant CRUD      |  |                  |       |  |
|  |  | Account ops      |  | CA lifecycle     |  | Create/Get/      |       |  |
|  |  | Order ops        |  | EAB management   |  | Update/Delete    |       |  |
|  |  | Stats/Status     |  |                  |  | List/Evaluate    |       |  |
|  |  +------------------+  +------------------+  +------------------+       |  |
|  +------------------------------------------------------------------------+  |
|                                    |                                         |
|                                    v                                         |
|  +------------------------------------------------------------------------+  |
|  |                       Storage Layer                                    |  |
|  |                                                                        |  |
|  |  +------------------+  +------------------+  +------------------+       |  |
|  |  |   QRDB KV        |  |   CA Storage     |  |   go-xkms        |       |  |
|  |  |                  |  |   (go-objstore)  |  |                  |       |  |
|  |  | Accounts         |  |                  |  | Key storage      |       |  |
|  |  | Orders           |  | Certificates     |  | HSM/TPM          |       |  |
|  |  | EAB tokens       |  | CRL/OCSP         |  | Software keys    |       |  |
|  |  | Tenants          |  |                  |  |                  |       |  |
|  |  +------------------+  +------------------+  +------------------+       |  |
|  +------------------------------------------------------------------------+  |
|                                                                              |
+------------------------------------------------------------------------------+
```

## Components

### HTTP Layer

The HTTP layer handles incoming requests and routes them to appropriate handlers.

#### Admin Handlers (`handlers.go`)

Core certificate, account, and order management:

```go
type Handlers struct {
    service Service
    logger  *slog.Logger
}
```

Endpoints:
- `GET /admin/certificates` - List certificates
- `GET /admin/certificates/{serial}` - Get certificate
- `POST /admin/certificates/{serial}/revoke` - Revoke certificate
- `GET /admin/certificates/expiring` - List expiring certificates
- `GET /admin/accounts` - List accounts
- `GET /admin/accounts/{id}` - Get account
- `DELETE /admin/accounts/{id}` - Disable account
- `GET /admin/orders` - List orders
- `GET /admin/orders/{id}` - Get order
- `GET /admin/status` - CA status
- `GET /admin/stats` - CA statistics

#### Tenant Handlers (`tenant_handlers.go`)

Multi-tenant management and CA operations:

```go
type TenantHandlers struct {
    service TenantService
    logger  *slog.Logger
}
```

Endpoints:
- Tenant CRUD (`/api/v1/tenants`)
- Tenant CA management (`/api/v1/tenants/{id}/root-ca`, `/intermediate-cas`)
- EAB management (`/api/v1/tenants/{id}/eab`)
- Policy management (`/api/v1/tenants/{id}/policies`)

#### Policy Handlers (`policy_handlers.go`)

RBAC policy management delegating to QRDB IAM:

```go
type PolicyHandlers struct {
    policyEngine PolicyEngine
    logger       *slog.Logger
}
```

### Middleware Layer

#### Authentication Middleware (`auth.go`)

Validates JWT tokens from QRDB Auth and extracts user context:

```go
type AuthMiddleware struct {
    client qrdb.AuthClient
}

func (am *AuthMiddleware) Authenticate(next http.Handler) http.Handler
```

Authentication flow:

```
Request                  AuthMiddleware                  QRDB Auth
   |                          |                               |
   | 1. Bearer token          |                               |
   |------------------------->|                               |
   |                          |                               |
   |                          | 2. ValidateToken()            |
   |                          |------------------------------>|
   |                          |                               |
   |                          | 3. Token claims               |
   |                          |<------------------------------|
   |                          |                               |
   |                          | 4. Extract user info          |
   |                          |    - UserID, Username         |
   |                          |    - TenantID, Role           |
   |                          |    - Groups, Permissions      |
   |                          |                               |
   |                          | 5. Set context values         |
   |                          |    - ContextKeyUser           |
   |                          |    - ContextKeyRole           |
   |                          |    - ContextKeyTenantID       |
   |                          |                               |
   | 6. Authenticated request |                               |
   |<-------------------------|                               |
```

#### Authorization Middleware (`authorization.go`)

RBAC authorization using QRDB's PolicyEngine:

```go
type AuthorizationMiddleware struct {
    policyEngine PolicyEngine
}

func (am *AuthorizationMiddleware) Authorize(action, resource string) func(http.Handler) http.Handler
func (am *AuthorizationMiddleware) AuthorizeWithTenant(action, resourceTemplate string, getTenantID func(*http.Request) string) func(http.Handler) http.Handler
```

Authorization flow:

```
Request                  AuthzMiddleware                 PolicyEngine
   |                          |                               |
   | 1. Authenticated request |                               |
   |------------------------->|                               |
   |                          |                               |
   |                          | 2. Build CheckRequest         |
   |                          |    - Subject (user, roles)    |
   |                          |    - Resource (path)          |
   |                          |    - Action (read/write/etc)  |
   |                          |    - Context (IP, method)     |
   |                          |                               |
   |                          | 3. Evaluate()                 |
   |                          |------------------------------>|
   |                          |                               |
   |                          |    4. Check deny policies     |
   |                          |    5. Check allow policies    |
   |                          |    6. Default deny            |
   |                          |                               |
   |                          | 7. CheckResponse              |
   |                          |<------------------------------|
   |                          |                               |
   | 8. Allow/Deny            |                               |
   |<-------------------------|                               |
```

#### Role-Based Middleware

Simple RBAC enforcement for quick permission checks:

```go
func RequireRole(minRole Role) func(http.Handler) http.Handler
func RequireOperation(operation string) func(http.Handler) http.Handler
func RequireTenant(getTenantID func(r *http.Request) string) func(http.Handler) http.Handler
```

### Service Layer

#### Service Interface (`service_interface.go`)

Defines core admin operations:

```go
type Service interface {
    // Certificate operations
    ListCertificates(ctx context.Context, req ListCertificatesRequest) ([]*CertificateInfo, *Pagination, error)
    GetCertificate(ctx context.Context, serial string) (*CertificateInfo, error)
    RevokeCertificate(ctx context.Context, serial string, reason string) error
    ListExpiringCertificates(ctx context.Context, days int, page, perPage int) ([]*CertificateInfo, *Pagination, error)

    // Account operations
    ListAccounts(ctx context.Context, req ListAccountsRequest) ([]*AccountInfo, *Pagination, error)
    GetAccount(ctx context.Context, accountID uint64) (*AccountInfo, error)
    DisableAccount(ctx context.Context, accountID uint64) error

    // Order operations
    ListOrders(ctx context.Context, req ListOrdersRequest) ([]*OrderInfo, *Pagination, error)
    GetOrder(ctx context.Context, orderID uint64, accountID uint64) (*OrderInfo, error)

    // Status operations
    GetStatus(ctx context.Context) (*CAStatus, error)
    GetStats(ctx context.Context) (*CAStats, error)
}
```

#### Tenant Service Interface

Multi-tenant operations:

```go
type TenantService interface {
    // Tenant CRUD
    CreateTenant(ctx context.Context, req CreateTenantRequest) (*TenantInfo, error)
    GetTenant(ctx context.Context, tenantID string) (*TenantInfo, error)
    UpdateTenant(ctx context.Context, tenantID string, req UpdateTenantRequest) (*TenantInfo, error)
    DeleteTenant(ctx context.Context, tenantID string) error
    ListTenants(ctx context.Context, req ListTenantsRequest) ([]*TenantInfo, *Pagination, error)

    // Tenant CA operations
    CreateTenantRootCA(ctx context.Context, tenantID string, req CreateTenantRootCARequest) (*TenantRootCAInfo, error)
    CreateTenantIntermediateCA(ctx context.Context, tenantID string, req CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error)
    // ... more CA operations

    // EAB operations
    CreateTenantEAB(ctx context.Context, tenantID string, req CreateEABRequest) (*CreateEABResponse, error)
    GetTenantEAB(ctx context.Context, tenantID string, kid string) (*EABInfo, error)
    // ... more EAB operations

    // Policy operations (QRDB RBAC)
    CreateTenantPolicy(ctx context.Context, tenantID string, policy *iam.Policy) (*iam.Policy, error)
    GetTenantPolicy(ctx context.Context, tenantID string, name string) (*iam.Policy, error)
    // ... more policy operations
}
```

#### Policy Engine Interface (`types.go`)

Direct integration with QRDB RBAC:

```go
type PolicyEngine interface {
    CreatePolicy(ctx context.Context, tenantID string, policy *iam.Policy) error
    GetPolicy(ctx context.Context, tenantID, policyName string) (*iam.Policy, error)
    UpdatePolicy(ctx context.Context, tenantID string, policy *iam.Policy) error
    DeletePolicy(ctx context.Context, tenantID, policyName string) error
    ListPolicies(ctx context.Context, tenantID string, opts iam.ListOptions) ([]*iam.Policy, error)
    Evaluate(ctx context.Context, req *iam.CheckRequest) (*iam.CheckResponse, error)
}
```

### Storage Layer

#### Storage Integration

QRDB provides KV storage for:
- Account storage and indexing
- Order management
- EAB token storage
- Tenant management
- RBAC policy storage and evaluation

QRDB Auth provides:
- JWT token validation

#### Certificate Storage (go-objstore)

Certificates are stored using go-objstore backends:
- Local filesystem
- S3-compatible storage
- Cloud providers (AWS, GCP, Azure)

#### Key Storage (go-xkms)

Private keys managed by go-xkms:
- Software keystores
- HSM integration
- TPM storage
- PKCS#11 support

## Data Flow

### Certificate Revocation Flow

```
Admin UI              Admin API              CA Service              Storage
   |                      |                      |                      |
   | 1. POST /revoke      |                      |                      |
   |--------------------->|                      |                      |
   |                      |                      |                      |
   |                      | 2. Authenticate      |                      |
   |                      | 3. Authorize (admin) |                      |
   |                      |                      |                      |
   |                      | 4. RevokeCertificate |                      |
   |                      |--------------------->|                      |
   |                      |                      |                      |
   |                      |                      | 5. Update cert status|
   |                      |                      |--------------------->|
   |                      |                      |                      |
   |                      |                      | 6. Add to CRL        |
   |                      |                      |--------------------->|
   |                      |                      |                      |
   |                      |                      | 7. Update OCSP       |
   |                      |                      |--------------------->|
   |                      |                      |                      |
   |                      | 8. Success           |                      |
   |                      |<---------------------|                      |
   |                      |                      |                      |
   | 9. Response          |                      |                      |
   |<---------------------|                      |                      |
```

### Tenant Creation Flow

```
Platform Admin        Admin API              TenantService          QRDB
   |                      |                      |                      |
   | 1. POST /tenants     |                      |                      |
   |--------------------->|                      |                      |
   |                      |                      |                      |
   |                      | 2. Authenticate      |                      |
   |                      | 3. Authorize tenants:create (qrdb RBAC)     |
   |                      |                      |                      |
   |                      | 4. CreateTenant      |                      |
   |                      |--------------------->|                      |
   |                      |                      |                      |
   |                      |                      | 5. Store tenant      |
   |                      |                      |--------------------->|
   |                      |                      |                      |
   |                      |                      | 6. Create default    |
   |                      |                      |    isolation policy  |
   |                      |                      |--------------------->|
   |                      |                      |                      |
   |                      |                      | 7. Create EAB policy |
   |                      |                      |--------------------->|
   |                      |                      |                      |
   |                      | 8. TenantInfo        |                      |
   |                      |<---------------------|                      |
   |                      |                      |                      |
   | 9. Response          |                      |                      |
   |<---------------------|                      |                      |
```

## Security Architecture

### Authentication Security

| Component | Protection |
|-----------|------------|
| JWT Tokens | RS256/ES256 signed, validated by QRDB Auth |
| Token Expiration | Configurable TTL, automatic validation |
| Token Claims | UserID, TenantID, Roles, Permissions |
| Transport | TLS 1.3 required in production |

### Authorization Security

| Component | Protection |
|-----------|------------|
| RBAC | 5-level hierarchical roles |
| Policy Engine | QRDB RBAC policy engine |
| Tenant Isolation | Key prefix separation, policy enforcement |
| Default Deny | No access without explicit policy |

### Audit Trail

All admin operations are logged:
- Actor (user ID, username)
- Action (create, update, delete, revoke)
- Resource (certificate, account, tenant)
- Timestamp
- Success/failure status
- Client IP address

## Integration Points

### QRDB IAM

The Admin API integrates with QRDB IAM for authorization:
- RBAC policy storage and evaluation
- User and role management

Authentication is handled via QRDB Auth:
- JWT token validation
- Session management

### ACME Server

The Admin API shares storage with the ACME server for:
- Certificate data
- Account data
- Order data
- EAB tokens

### CA Service

The Admin API delegates to the CA service for:
- Certificate revocation
- CRL generation
- OCSP responses
- CA key operations

## Deployment Considerations

### High Availability

- Stateless Admin API handlers
- QRDB clustering for storage
- Load balancer with health checks
- Multiple CA replicas

### Scalability

- Horizontal scaling of Admin API
- QRDB automatic sharding
- Certificate storage via cloud object stores
- Connection pooling

### Monitoring

- Prometheus metrics endpoint
- Structured JSON logging
- Health check endpoints
- Audit log streaming
