# MFA Policy Engine

The `pkg/auth/policy` package provides an operation-level MFA policy engine with hot-reload support. Policies map operations to required MFA levels aligned with NIST SP 800-63B authentication assurance levels.

## MFA Levels

| Level | Constant | NIST AAL | Factors |
|-------|----------|----------|---------|
| None | `MFANone` | AAL1 | Internal/system operations only |
| FIDO2 | `MFAFIDO2` | AAL2 | Possession (authenticator) + UV (PIN/biometric) |
| FIDO2+OATH | `MFAFIDO2OATH` | AAL3 | FIDO2 + OATH TOTP/HOTP (3FA) |

Levels are ordinal: `MFAFIDO2OATH > MFAFIDO2 > MFANone`. A higher level always satisfies a lower requirement.

## Engine API

| Method | Description |
|--------|-------------|
| `NewEngine(policy)` | Creates engine; nil policy uses `DefaultPolicy()` |
| `Check(op, provided)` | Returns nil if satisfied, `ErrInsufficientMFA` if not |
| `RequiredLevel(op)` | Returns the required level for an operation |
| `SetPolicy(policy)` | Hot-replaces the entire policy (concurrent-safe) |
| `AddOperationPolicy(op)` | Adds/replaces a single operation policy |
| `RemoveOperationPolicy(op)` | Removes a single operation policy |
| `ListPolicies()` | Returns a copy of all operation policies |

## Default Policy

`DefaultPolicy()` sets `MFAFIDO2` as the default and requires 3FA (`MFAFIDO2OATH`) for:

- `barrier_unseal` -- Unsealing the barrier
- `key_export` -- Exporting key material
- `tenant_create` -- Creating tenants
- `escrow_key` -- Escrowing keys externally
- `recover_key` -- Recovering escrowed keys

## Well-Known Operations

| Constant | Operation |
|----------|-----------|
| `OpBarrierUnseal` | `barrier_unseal` |
| `OpBarrierSeal` | `barrier_seal` |
| `OpKeyExport` | `key_export` |
| `OpKeyImport` | `key_import` |
| `OpKeyGenerate` | `key_generate` |
| `OpKeyDelete` | `key_delete` |
| `OpTenantCreate` | `tenant_create` |
| `OpTenantDelete` | `tenant_delete` |
| `OpUserCreate` | `user_create` |
| `OpUserDelete` | `user_delete` |
| `OpCustodianInvite` | `custodian_invite` |
| `OpShareProvide` | `share_provide` |
| `OpShareReceive` | `share_receive` |
| `OpEscrowKey` | `escrow_key` |
| `OpRecoverKey` | `recover_key` |
| `OpCertRequest` | `cert_request` |
| `OpLogin` | `login` |

## OperationPolicy

```go
type OperationPolicy struct {
    Operation     string   `json:"operation"`
    RequiredLevel MFALevel `json:"required_level"`
    Description   string   `json:"description,omitempty"`
    Enforced      bool     `json:"enforced"` // false = advisory only
}
```

When `Enforced` is `false`, `Check()` always returns nil regardless of the provided level. This allows deploying policies in advisory mode before enforcement.

## Usage

```go
engine := policy.NewEngine(nil) // uses DefaultPolicy

// Check before a sensitive operation
if err := engine.Check(policy.OpKeyExport, policy.MFAFIDO2); err != nil {
    // err == ErrInsufficientMFA (needs MFAFIDO2OATH)
}

// Hot-reload a custom policy
engine.SetPolicy(&policy.MFAPolicy{
    DefaultLevel: policy.MFANone,
    Operations:   map[string]*policy.OperationPolicy{ /* ... */ },
})
```

## Error Reference

| Error | Condition |
|-------|-----------|
| `ErrInsufficientMFA` | Provided level below required |
| `ErrInvalidMFALevel` | Unrecognized level string |
| `ErrInvalidOperation` | Empty operation name |
| `ErrNilPolicy` | Nil policy passed to `SetPolicy` or `AddOperationPolicy` |
| `ErrPolicyNotFound` | No policy for operation (in `RemoveOperationPolicy`) |

## Cross-References

- [Barrier Encryption Architecture](../seal/README.md) -- barrier unseal requires 3FA by default
- [Bootstrap Authentication](bootstrap.md) -- first-time system initialization
