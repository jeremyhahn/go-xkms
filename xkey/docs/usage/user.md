# User Management

> **Status: REFERENCE** · Last verified: 2026-10-13
> Pointer page for user accounts in xkmsd; superseded by [user-onboarding](../../../docs/user-onboarding/user.md) and [rbac](../../../docs/rbac/user.md). Where they disagree, the feature folders win.

go-xkms has no user package of its own. The user and identity model, role
assignment and certificate binding belong to go-qrdb and are reached through
its SDK; a certificate is bound to a user by its SPKI SHA-256 thumbprint. The
`pkg/user` Go API this page once described (`user.NewFileStore`,
`NewWebAuthnUserAdapter`, `NewUserRBACAdapter`, the session store) was
removed and is not documented here.

## CLI

`xkmsctl user` (`cmd/xkmsctl/user.go:128`) has these verbs:

| Verb | Defined at |
|------|------------|
| `register <username>` | `user.go:138` |
| `login <email>` | `user.go:315` |
| `list` | `user.go:476` |
| `get <username>` | `user.go:560` |
| `delete <username>` | `user.go:648` |
| `disable <username>` | `user.go:694` |
| `enable <username>` | `user.go:739` |
| `status` | `user.go:784` |
| `credentials <username>` | `user.go:850` |
| `update <username>` | `user.go:922` |
| `bind-cert <username>` | `user.go:1007` |

Flags and examples are in [cli/user.md](cli/user.md).

## REST API

Routes under `/api/v1/users` (`pkg/api/rest/routes.go:468-475`), each gated by
an `auth.ResourceUsers` permission:

| Endpoint | Method | Action |
|----------|--------|--------|
| `/api/v1/users` | POST | create |
| `/api/v1/users` | GET | list |
| `/api/v1/users/{username}` | GET | read |
| `/api/v1/users/{username}/credentials` | GET | read |
| `/api/v1/users/{username}/enable` | POST | enable |
| `/api/v1/users/{username}/disable` | POST | disable |
| `/api/v1/users/{username}/cert-bindings` | POST | update |
| `/api/v1/users/{username}` | DELETE | delete |

## Related Documentation

- [User onboarding](../../../docs/user-onboarding/architecture.md) - Enrollment and identity flow
- [WebAuthn](../../../docs/webauthn/user.md) - Passwordless authentication
- [RBAC](../../../docs/rbac/architecture.md) - Role-based access control
- [xkmsd Configuration](../../../docs/xkmsd-configuration/user.md) - API server configuration
