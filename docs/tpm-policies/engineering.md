# TPM Policies — Engineering Contract

> **Status: NORMATIVE** · Feature: `tpm-policies` · Repo: `go-xkms` · Last verified: 2026-09-30

Design: [`architecture.md`](architecture.md). Surface: [`api.md`](api.md).

## Layers

| Layer | Package | Responsibility |
|---|---|---|
| Service | `pkg/tpmpolicy` | Scopes, named policies, approvals, the registry, vTPMs |
| Key routing | `pkg/backend/tpm2` (`scope.go`) | Runs each key and seal operation in the TPM scope of `KeyAttributes.TenantID` |
| Composition | `pkg/compose` (`BuildTPMPolicyService`) | The one construction path, used by xkmsd and by embedding hosts |
| Service layer | `pkg/xkms/servicer_tpm_policy.go` | Tenant binding and system scope, then delegation to `TenantTPMPolicies` |
| API conversion | `pkg/xkms/tenant_tpm_policies.go` (`TenantTPMPolicies`) | The one mapping between `*tpmpolicy.Service` and the API types, for one fixed tenant |
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
- Symmetric keys live in every scope: under the Platform SRK in the system
  and vtpm scopes, and under the tenant's storage key in shared mode, with
  their blobs in the scope's key store (`pkg/tpm2`'s
  `GenerateSymmetricKeyIn`, `GetSymmetricKeyIn`, `SymmetricEncrypterIn` and
  `DeriveFromSymmetricKeyIn`). The encrypter a shared tenant gets opens its
  scope for each `Encrypt` and `Decrypt`, because the storage key is loaded
  per operation and flushed afterwards.
- Refusals: `ErrReservedObject` (a name the service owns),
  `ErrSymmetricKeysUnsupported` (a TPM implementation without the
  store-aware symmetric methods), `ErrTenantImportUnsupported` (imports are
  parented to the Platform SRK). A scope that cannot open surfaces as `*ScopeError` wrapping the
  service's error, such as `tpmpolicy.ErrTPMModeNone`.
- `Unseal` of in-memory blobs reads a named policy's binding record from the
  key store in `UnsealOptions.Backend`. The backend passes the scope's store.
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

## Tenant adapter (`TenantTPMPolicies`)

`xkms.NewTenantTPMPolicies(svc, tenant)` (re-exported by `sdk/go`) returns
the tenant-level operations of `transport.TPMPolicyService`
(`TPMPolicyCreate` ... `TPMPolicyRotateAuthority`) with their exact
signatures, over `svc` for a fixed tenant (`""` is the system scope). It
ignores every request's `TenantID`: authorizing the tenant is the caller's
job. A nil `svc` is `ErrNotConfigured`.

- `XKMSService` binds the caller's tenant (`targetTenant`, `pkg/xkms/tenant_binding.go`) and delegates.
- xKey's local mode (`xkey/pkg/gui/services/tpm_policy_local.go`) delegates
  every `TPMPolicy*` method for the system scope, holding the TPM accessor
  around each call, so local and connected answers are the same types from
  the same code. `xkms.ParseTPMObjectKind` is the one object-kind parser
  (`*InvalidTPMObjectKindError`).

## Composite policies

Design: [`architecture.md`](architecture.md), "Composite policies and
descriptions".

- **Model** (`pkg/tpmpolicy/types.go`). `Policy{Description, Branches,
  Approvals}`: an OR of `Branch`es, each an AND of `Condition`s --
  `pcr` (`Bank`, `PCRs`; `PCRValues`/`PCRDigest` captured, never supplied),
  `auth_value` (no operand) and `locality` (`Localities` 0-4). `Approvals` is
  index-aligned with `Branches`; they are signed and revoked together.
  `PCRBranch(bank, pcrs...)` builds the one-branch policy over a PCR
  selection.
- **Validation** (`conditions.go`, one `conditionSpec` per type in a map):
  at least one branch (`ErrNoBranches`), at least one condition per branch
  (`ErrEmptyBranch`), at most one of each type (`*DuplicateConditionError`),
  only the operands of the type (`*ConditionOperandError`), known types
  (`*UnknownConditionTypeError`), banks and PCRs 0-23 (`*InvalidPCRBankError`,
  `*InvalidPCRError`, `ErrEmptyPCRSelection`), localities 0-4
  (`*InvalidLocalityError`, `ErrEmptyLocalitySelection`), no supplied values
  (`ErrPCRValuesSupplied`), descriptions up to 4096 bytes
  (`*DescriptionTooLongError`). A branch fault is wrapped in
  `*InvalidBranchError{Branch}`. Everything is checked before the TPM is
  reached.
- **Assertion order.** `pkg/tpm2` asserts a branch's conditions in canonical
  order -- `PolicyLocality`, then `PolicyPCR`, then `PolicyAuthValue` -- then
  `PolicyNV(counter == epoch)`, whatever order the request lists them in.
- **Choosing a branch at use** (`pkg/tpm2/authorized_policy_session.go`).
  Branches are tried in order. A locality condition is checked in software
  against the locality xkms sends commands at (0), only to skip a branch that
  cannot hold (`*PolicyLocalityMismatchError`); the TPM enforces it when the
  session is used. A branch with `auth_value` is tried only when a password
  was supplied (`*PolicyAuthValueMissingError`). If none succeeds the
  refusals come back in branch order in `*PolicyBranchesRefusedError`.
- **Passwords.** An object bound to a policy with an `auth_value` condition
  must have a password: creating one without is refused with
  `tpm2.ErrPolicyAuthValueRequired` (invalid argument). Such an object has no
  outer `PolicyAuthValue` branch, so the password never bypasses the policy.
- **Binding record** (`pkg/tpm2/store/tpm_policy_binding.go`): `XTPB`
  version 2 adds flag bit 1, "the policy has an `auth_value` condition".
  Version 1 records still decode, as bindings without one.
- **Descriptions** are stored on the policy; `Service.SetDescription`
  replaces one without touching approvals or the counter.
- **API mapping** (`pkg/xkms/tenant_tpm_policies.go`): `tpmPolicyToTransport`
  reports branches with hex values and each branch's `approved`, the policy's
  `approved` (every branch approved) and the first approval's epoch and
  generation; `tpmBranchesFromTransport` refuses supplied `pcr_values` or
  `pcr_digest` before the service sees them. The request shape is branches
  only: there is no bank/PCRs shortcut on the wire.
  `transport.TPMPolicyPCRBranch`, `ParseTPMPolicyBranch` and
  `TPMPolicyBranches` (re-exported by `sdk/go`) are the client-side
  builders both CLIs share.

## Key versions

Design: [`architecture.md`](architecture.md), "Key versions".

| Layer | Package | Responsibility |
|---|---|---|
| Model and store | `pkg/keyversion` | `Record`, `Version`, `State`; the `--v<n>` name rules (`Name`, `Parse`, `CheckKeyID`); `Store` over a `storage.Backend` |
| Composition | `pkg/compose` (`BuildKeyVersionStore`) | The one construction path, over `Storage("key-versions")` (`StorageKeyVersions`); `compose.Build` builds it whenever it has storage, xkmsd in `initializeKeyVersionStore` |
| Service | `pkg/xkms/key_versions.go`, `servicer_keyversion.go` | Resolving a key to its versions, choosing the version per operation, rotation, the state changes, `RotateScopeKeys` |
| Transports | `pkg/api/{rest,grpc,mcp}`, `pkg/api/transport/*` | Wire mapping only; `pbconv.KeyVersionClient` and `wire.KeyVersionClient` are the shared clients |

- **Record layout.** `{tenant}/key-versions/<backend>/<keyID>` in the
  `key-versions` storage, one JSON record per rotated key; the system tenant
  is `system`. The tenant is the key's own (`KeyAttributes.TenantID`), the
  backend its registered name.
- **No record at generate.** `GenerateKey` and `ImportKey` write nothing: a
  key without a record is version 1, alone and enabled
  (`keyversion.Implicit`), so a key that is never rotated costs no store
  write and every key created before versions existed needs no migration.
  The first `RotateKey` writes the record. Consequently `GenerateKey`,
  `ImportKey` and `CopyKey` refuse a key ID whose record exists
  (`*xkms.KeyExistsError`): its version 1 may have been retired, leaving the
  name free in the backend.
- **Reserved suffix.** `guardKeyID` refuses any ID ending in `--v<digits>`
  (`*keyversion.ReservedKeyIDError`) on generate and import; `CopyKey` and
  `UnwrapKeyByID` refuse it for the new key's ID. Every operation that names
  a key refuses a version's own name (`K--v2`): versions are reached through
  their key. Every backend accepts `K--v<n>` wherever it accepts `K`
  (TPM2 file names, PKCS#11 labels, AWS KMS aliases, GCP `[a-zA-Z0-9_-]`,
  Azure alphanumerics and dashes, Vault's escaped names).
- **Resolution** (`resolveKey`). One `ListKeys` of the (tenant-scoped)
  backend finds every backend key of `K`: `K` itself as version 1 and each
  `K--v<n>`. The record comes from the store. A version the record holds but
  the backend lacks is `*xkms.KeyVersionMissingError` (not found). The
  caller's default sealing key is resolved among the caller's own tenant's
  keys only (`resolveKeyOf`).
- **Version choice.** Current: `Sign`, `Encrypt`, `EncryptAsym`, `GetKey`,
  `ExportKey`, `ExportKeyMaterial`, `CopyKey` (source), `WrapKeyByID` (both
  keys), `AttestKey`, `Seal`. Requested or current: `DeriveKey`,
  `DeriveKeyECDH`. Requested or every enabled version newest first
  (`trialVersions`): `Verify`, AEAD and RSA-OAEP `Decrypt`, `Unseal`, and
  `UnwrapKeyByID` with AES-KW, AES-KWP, AES-GCM or RSA-OAEP. Requested or the
  single enabled one (`singleVersion`, else
  `*keyversion.KeyVersionRequiredError`): AES-CBC and RSA PKCS#1 v1.5
  `Decrypt`, and `UnwrapKeyByID` with AES-CBC or PKCS#1 v1.5. A requested
  version must be enabled (`*keyversion.VersionUnavailableError`).
- **Rotation** (`rotateKey`). Under the key's lock (`Store.Lock`), the
  record is re-read, a backend key left under the next version's name by an
  interrupted rotation is deleted, and the new version is generated through
  `generateKeyWithAttributes` -- the path `GenerateKey` uses -- with the
  current version's attributes: the algorithm and size or curve read from its
  public key, and its purpose, hash, partition, exportability, sensitivity
  and tenant. On TPM2 the new version is bound to
  `TPMPolicyService().PolicyOf(ctx, tenant, ObjectKey, <current version>)`,
  in the same tenant scope. The record is stored last; if that fails the new
  key is deleted. Numbers are never reused (`Record.Next`). X25519 and
  post-quantum keys are refused (`*xkms.KeyRotationUnsupportedError`). The
  backends' in-place `RotateKey` is no longer called by the service layer;
  the package-level `xkms.RotateKey(kid)` rotates through the same path.
- **Rotating a scope** (`RotateScopeKeys`). Every key of the tenant, in
  every backend, once. Each result has a `state`: `rotated`, `failed` (with
  `error`) or `skipped` (with `reason`), counted in `rotated`, `failed` and
  `skipped`. A backend whose keys or certificates cannot be listed is one
  `failed` result and none of its keys is rotated. Skipped
  (`pinnedKeyRules`, `SkipReason*` in `servicer_keyversion.go`):
  - on a TPM2 backend, PIV slot keys (`piv-<slot>`, `PivSlotCN`): the slot
    resolves the key by that name;
  - on a TPM2 backend, sealed objects `Seal` named
    (`xkms-sealing-key-tpm2-<uuid>`): unseal names them exactly and they have
    no versions;
  - on any backend, the barrier's seal wrapping key (`seal.SealKeyCN`,
    `xkms-barrier-seal`): the barrier and the platform store resolve it by
    name;
  - keys with a certificate (`certifiedKeys`: the last segment of each
    certificate ID the backend lists): the certificate would stay on the old
    version. Reason: "has a certificate; re-issue after rotating it
    explicitly".

  A key-based backend's default sealing key (`xkms-sealing-key-<type>`) is
  not skipped: `Seal` uses its current version and `Unseal` the recorded one.
- **Single-key rotation and certificates.** `RotateKey` rotates a key with a
  certificate and sets `RotateKeyResponse.CertificateReissueRequired`; the
  certificates are listed before rotating, so a listing failure leaves the key
  unrotated.
- **State changes** (`updateVersions`). Under the key's lock; the current
  version cannot be disabled or retired (`*keyversion.CurrentVersionError`);
  a retired version is final (`*keyversion.RetiredVersionError`); retiring
  deletes the version's backend key before the record says so.
- **Deletion.** `DeleteKey` deletes the record first, then every backend key
  of `K`, newest first; a retry after a partial failure finishes the job.
- **Listing.** `ListKeys` folds each `K--v<n>` into `K`, reports
  `KeyInfo.KeyVersion` and the current version's public key, and reads a
  record only for a key with a version after the first.
- **Sealed data.** `types.SealedData.KeyVersion` (and `SealResponse` /
  `UnsealRequest.KeyVersion`) carry the sealing key's version beside the
  ciphertext. TPM2 sealed objects have no versions.
- **Concurrency.** Mutations of one key's versions are serialized
  in-process, like the TPM policy registry's.

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
  isolation, mode none, sealing under a named policy, symmetric keys in every scope,
  reserved objects.
- `pkg/server/tpm_policy_simulator_test.go` (simulator): xkmsd end to end —
  two keys bound to one policy, objects/object-policy, refused delete, sign,
  update, two tenants isolated from each other, and two TPM2 seals without a
  key ID staying two objects that each unseal.
- `pkg/server/key_version_tpm_simulator_test.go` (simulator): a tenant's TPM2
  key bound to a named policy rotates into the same tenant scope and policy;
  both versions sign, the old signature verifies, and deleting the key
  removes both objects.
- `pkg/keyversion`: the record rules and the store. `pkg/xkms/key_versions_test.go`
  (software backend): sign/verify across versions, AES-GCM, AES-CBC, external
  RSA-OAEP and PKCS#1 v1.5 decryption after a rotation, disable/enable/retire,
  delete, the reserved suffix, listing, `RotateScopeKeys` across tenants and
  its skip rules (`TestRotateScopeKeys_SkipsPinnedAndCertifiedKeys`,
  `TestPinnedKeyReason`, `TestRotateKey_ReportsCertificateReissue`),
  sealing, derivation, unwrap. `pkg/api/{grpc,rest,mcp}/*key_version*_test.go`
  and `pkg/api/transport/*/transport_key_version_test.go`: every endpoint and
  its error mapping.
- `pkg/tpmpolicy/conditions_test.go` (validation, conversion) and
  `service_simulator_test.go` (simulator): composite policies end to end --
  OR of branches, PCR and password, locality, descriptions, per-branch
  verification. `pkg/api/transport/tpm_policy_branch_test.go`: the branch
  spec grammar.
- `pkg/xkms/servicer_tpm_policy_test.go`, `pkg/xkms/tenant_tpm_policies_test.go`, `pkg/api/{grpc,rest,mcp}/*tpm_policy*_test.go`,
  `pkg/api/grpc/pbconv`, `pkg/api/rest/wire`: binding, system scope, error
  mapping and wire mapping over a TPM-less service
  (`pkg/testutil/tpmpolicytest.NewOffline`).
