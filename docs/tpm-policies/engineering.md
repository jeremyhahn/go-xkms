# TPM Policies — Engineering Contract

> **Status: NORMATIVE** · Feature: `tpm-policies` · Repo: `go-xkms` · Last verified: 2026-09-29

Design: [`architecture.md`](architecture.md). Surface: [`api.md`](api.md).

## Layers

| Layer | Package | Responsibility |
|---|---|---|
| Service | `pkg/tpmpolicy` | Scopes, named policies, approvals, the registry, vTPMs |
| Key routing | `pkg/backend/tpm2` (`scope.go`) | Runs each key and seal operation in the TPM scope of `KeyAttributes.TenantID` |
| Composition | `pkg/compose` (`BuildTPMPolicyService`) | The one construction path, used by xkmsd and by embedding hosts |
| Service layer | `pkg/xkms/servicer_tpm_policy.go` | Tenant binding, system scope, API types |
| Transports | `pkg/api/{rest,grpc,mcp}`, `pkg/api/transport/*` | Wire mapping only |

## Key routing (`pkg/backend/tpm2`)

- `Backend.SetScopeProvider(ScopeProvider)` installs the policy service.
  `*tpmpolicy.Service` satisfies `ScopeProvider`. Without one the backend
  behaves as it always did: one TPM, one key store, the Platform SRK.
- Every operation that loads or creates an object (`GenerateKey`, `Signer` /
  `Decrypter` per `Sign` / `Decrypt` call, `DeleteKey`, `DeriveKeyECDH`,
  symmetric keys, `DeriveFromSymmetricKey`, `AttestKey`, `Seal`, `Unseal`)
  opens the scope of `attrs.TenantID` (`""` and `system` are the system
  scope), binds the object to the scope's storage parent, uses the scope's
  key store, and closes the scope when the call ends. A signer returned to a
  caller re-opens the scope on every call, so it never pins a tenant's
  storage key in the TPM.
- `GetKey` and `ListKeys` read blobs only (`ScopeProvider.KeyStore`) and load
  nothing.
- `GenerateKey` and `GenerateSymmetricKey` record the key's assignment
  (policy, authPolicy digest) and delete the key again if it cannot be
  recorded. `Seal` records a sealed object bound to a named policy.
  `DeleteKey` removes both kinds of assignment for the name.
- `ListKeys` lists the system key directory (minus the service's own
  objects, `tpmpolicy.IsReservedObject`) and each tenant scope's recorded
  keys, with `TenantID` and `TPMPolicy` set; `TenantScopedBackend` filters by
  tenant.
- Refusals: `ErrReservedObject` (a name the service owns),
  `ErrTenantSymmetricKeyUnsupported` (a shared-mode tenant owns no Platform
  SRK), `ErrTenantImportUnsupported` (imports are parented to the Platform
  SRK). A scope that cannot open surfaces as `*ScopeError` wrapping the
  service's error, such as `tpmpolicy.ErrTPMModeNone`.
- `Unseal` of in-memory blobs: `pkg/tpm2` reads a named policy's binding
  record only when it loads the object from a key store, so when the scope's
  store holds the very object presented (same public area) the backend
  unseals it from the store (`storedSealed`).
- `TenantBoundSealing()` reports true with a scope provider;
  `xkms.TenantScopedBackend` then permits TPM2 sealing for a tenant, which it
  refuses otherwise (go-xkms#1228).

## Composition

`compose.BuildTPMPolicyService(TPMPolicyParams{Backend, Storage, VTPM,
Logger})`:

- registry over `Storage("tpm-policies")` (`StorageTPMPolicies`), tenant
  object blobs over `Storage("tpm-keys")` (`StorageTPMKeys`);
- the backend's own TPM, Platform SRK and key store for the system scope;
- the backend's TPM as the scopes' secrets sealer (every sealed secret is
  bound to the built-in `platform` policy by the service itself);
- installs the service as the backend's scope provider.

xkmsd (`pkg/server/backend_tpm2.go`, `initTPMPolicyService`) builds it when
`backends.tpm2` is enabled and closes it before the TPM on every shutdown
path. An embedding host's module (`pkg/apimodule`) builds it through
`compose.Build` when its `XKMSService` has a `tpm2` backend
(`compose.TPM2Backend`); `WithVTPM` makes vtpm mode available there, and the
host closes the stores (`Stores.Close`) at shutdown.

## Configuration

```yaml
backends:
  tpm2:
    enabled: true
    vtpm:
      enabled: true            # off unless set; vtpm mode then answers ErrVTPMUnavailable
      state_dir: /var/lib/xkms/vtpm       # default <storage.path>/vtpm
      run_dir: /run/xkms-vtpm             # default <storage.path>/vtpm-run (socket paths <= 107 bytes)
      binary: /usr/bin/swtpm              # default swtpm from PATH
```

## Tests

- `pkg/backend/tpm2/scope_sim_test.go` (simulator): named-policy keys, tenant
  isolation, mode none, sealing under a named policy, symmetric refusal,
  reserved objects.
- `pkg/server/tpm_policy_simulator_test.go` (simulator): xkmsd end to end —
  two keys bound to one policy, objects/object-policy, refused delete, sign,
  update, and two tenants isolated from each other.
- `pkg/xkms/servicer_tpm_policy_test.go`, `pkg/api/{grpc,rest,mcp}/*tpm_policy*_test.go`,
  `pkg/api/grpc/pbconv`, `pkg/api/rest/wire`: binding, system scope, error
  mapping and wire mapping over a TPM-less service
  (`pkg/testutil/tpmpolicytest.NewOffline`).
