# TPM Policies — API

> **Status: NORMATIVE** · Feature: `tpm-policies` · Repo: `go-xkms` · Last verified: 2026-10-12

Design: [`architecture.md`](architecture.md). Service: `pkg/tpm2/policy.Service`,
reached only through `XKMSService` (`pkg/xkms/servicer_tpm_policy.go`), which
every transport calls.

## Tenancy

- Every policy operation acts on the caller's own tenant's TPM scope
  (`targetTenant`, `pkg/xkms/tenant_binding.go:137`): a caller may leave
  `tenant_id` empty or name its own tenant, and naming another is refused
  with the unknown-tenant not-found (`xkms.TenantBindingError`). That holds
  for a system-tenant caller too, whose own scope is the system scope
  (go-xkms#1406).
- A tenant's TPM mode and its vTPM are system-scope only
  (`requireSystemTenant`): a tenant-scoped caller is refused even for its own
  tenant.

## Operations

| Operation | REST | gRPC / Unix (`KeystoreService.`) | MCP tool | Permission |
|---|---|---|---|---|
| Create a policy of branches (captures live PCRs) | `POST /api/v1/tpm/policies` | `TPMPolicyCreate` | `tpm.policy.create` | `tpm_policy:create` |
| List policies | `GET /api/v1/tpm/policies[?tenant_id=]` | `TPMPolicyList` | `tpm.policy.list` | `tpm_policy:list` |
| Get a policy | `GET /api/v1/tpm/policies/{name}[?tenant_id=]` | `TPMPolicyGet` | `tpm.policy.get` | `tpm_policy:get` |
| Update (re-capture, re-approve) | `POST /api/v1/tpm/policies/{name}/update` | `TPMPolicyUpdate` | `tpm.policy.update` | `tpm_policy:update` |
| Revoke the approval | `POST /api/v1/tpm/policies/{name}/revoke` | `TPMPolicyRevoke` | `tpm.policy.revoke` | `tpm_policy:revoke` |
| Verify against live PCRs | `POST /api/v1/tpm/policies/{name}/verify` | `TPMPolicyVerify` | `tpm.policy.verify` | `tpm_policy:verify` |
| Delete (refused while assigned) | `DELETE /api/v1/tpm/policies/{name}` | `TPMPolicyDelete` | `tpm.policy.delete` | `tpm_policy:delete` |
| Objects bound to a policy | `GET /api/v1/tpm/policies/{name}/objects` | `TPMPolicyObjects` | `tpm.policy.objects` | `tpm_policy:get` |
| Set or clear auto-unseal | `POST /api/v1/tpm/policies/{name}/auto-unseal` | `TPMPolicySetAutoUnseal` | `tpm.policy.autoUnseal` | `tpm_policy:update` |
| Set the description | `POST /api/v1/tpm/policies/{name}/description` | `TPMPolicySetDescription` | `tpm.policy.setDescription` | `tpm_policy:update` |
| Policy of a key or sealed object | `GET /api/v1/keys/{id}/tpm-policy[?kind=sealed]` | `TPMObjectPolicy` | `tpm.object.policy` | `tpm_policy:get` |
| Rotate the policy authority | `POST /api/v1/tpm/authority/rotate` | `TPMPolicyRotateAuthority` | `tpm.authority.rotate` | `tpm_policy:rotate` |
| Get a tenant's TPM mode | `GET /api/v1/tenants/{tenantID}/tpm` | `GetTenantTPMMode` | `xkms.getTenantTPMMode` | `tenants:read` |
| Set a tenant's TPM mode | `PUT /api/v1/tenants/{tenantID}/tpm` | `SetTenantTPMMode` | `xkms.setTenantTPMMode` | `tenants:set_tpm_mode` |
| vTPM status | `GET /api/v1/tenants/{tenantID}/tpm/vtpm` | `TenantVTPMStatus` | `xkms.tenantVTPMStatus` | `tenants:read` |
| Start the vTPM | `POST /api/v1/tenants/{tenantID}/tpm/vtpm/start` | `TenantVTPMStart` | `xkms.tenantVTPMStart` | `tenants:set_tpm_mode` |
| Stop the vTPM | `POST /api/v1/tenants/{tenantID}/tpm/vtpm/stop` | `TenantVTPMStop` | `xkms.tenantVTPMStop` | `tenants:set_tpm_mode` |

- QUIC serves the REST routes over HTTP/3; the embedded transport calls
  `XKMSService` directly. The USB transport (the xkey Android companion) has
  no TPM and answers `usb.ErrNotSupported` for the whole family.
- `tpm_policy:*` is owned by xkms and declared `ScopeSelf`;
  `tenants:set_tpm_mode` is owned by xkms and declared `ScopeCross`
  (`pkg/apimodule/module_scopes.go`).
- The client side is `transport.TPMPolicyService`, part of `transport.Client`.
  The REST and QUIC clients share `wire.TPMPolicyClient`; the gRPC and Unix
  clients share `pbconv.TPMPolicyClient`.

## Keys and sealed objects

| Field | REST / MCP JSON | gRPC | Meaning |
|---|---|---|---|
| `GenerateKeyRequest.TPMPolicy` | `tpm_policy` | `GenerateKeyRequest.tpm_policy` = 11 | TPM2 key bound to the named policy; empty is `platform`. Any other backend refuses a non-empty value (`xkms.ErrTPMPolicyNotSupported`, invalid argument). |
| `SealRequest.TPMPolicy` | `tpm_policy` | `SealRequest.tpm_policy` = 6 | TPM2 sealed object bound to the named policy, `platform`, or empty for none. A TPM2 seal needs a policy, a password or both; one with neither is refused (`tpm2.ErrSealUnprotected`). |
| `SealRequest.Password` | `password` | `SealRequest.password` = 5 | The TPM2 sealed object's authorization value. With a TPM policy it counts only inside the policy (`PolicyAuthValue`); without one it is the object's only protection. |

gRPC also gained the fields a TPM2 sealed object needs to round-trip:
`SealResponse.tpm_public` = 6, `tpm_private` = 7, `wrapped_dek` = 8,
`key_id` = 9; `UnsealRequest.tpm_public` = 7, `tpm_private` = 8,
`wrapped_dek` = 9, `metadata` = 10, `password` = 11. An unseal needs a
ciphertext, or both TPM areas.

A TPM2 seal's key ID names the sealed object; without one each seal creates
a new object with a unique name (`xkms-sealing-key-tpm2-<uuid>`) in the
caller's scope, so a seal never replaces an object it did not name. The
object's name is returned in `SealResponse.KeyID` (REST/MCP `key_id`, gRPC
`key_id` = 9), and a TPM2 unseal must pass it back as `UnsealRequest.KeyID`:
without one it is refused with `xkms.ErrTPMSealedObjectKeyIDRequired`
(`*xkms.ErrValidation`, invalid argument). A sealed object bound to a named
policy is recorded against it (`sealed/<name>`). Other backends are
unchanged: without a key ID they seal under the caller's default sealing
key.

## Key versions

Design: [`architecture.md`](architecture.md), "Key versions". Every call acts
in the caller's tenant, like the other key operations; `rotate-all` alone
takes a tenant, which only a system caller may set to another tenant.

| Operation | REST | gRPC / Unix (`KeystoreService.`) | MCP tool | Permission |
|---|---|---|---|---|
| Rotate a key (new current version) | `POST /api/v1/keys/{id}/rotate?backend=` | `RotateKey` | `xkms.rotateKey` | `keys:rotate` |
| List a key's versions | `GET /api/v1/keys/{id}/versions?backend=` | `ListKeyVersions` | `xkms.listKeyVersions` | `keys:list` |
| Enable a version | `POST /api/v1/keys/{id}/versions/{n}/enable?backend=` | `EnableKeyVersion` | `xkms.enableKeyVersion` | `keys:rotate` |
| Disable a version | `POST /api/v1/keys/{id}/versions/{n}/disable?backend=` | `DisableKeyVersion` | `xkms.disableKeyVersion` | `keys:rotate` |
| Retire a version (deletes it) | `POST /api/v1/keys/{id}/versions/{n}/retire?backend=` | `RetireKeyVersion` | `xkms.retireKeyVersion` | `keys:delete` |
| Enable every disabled version | `POST /api/v1/keys/{id}/versions/enable-all?backend=` | `EnableAllKeyVersions` | `xkms.enableAllKeyVersions` | `keys:rotate` |
| Disable every non-current version | `POST /api/v1/keys/{id}/versions/disable-all?backend=` | `DisableAllKeyVersions` | `xkms.disableAllKeyVersions` | `keys:rotate` |
| Rotate every key of a tenant | `POST /api/v1/keys/rotate-all` (`{"tenant_id"}`) | `RotateScopeKeys` | `xkms.rotateScopeKeys` | `keys:rotate` |

- **Rotate-all results.** Each `KeyRotationResult` has a `state` --
  `rotated` (with `key_version`), `skipped` (with `reason`) or `failed` (with
  `error`) -- and the response counts `rotated`, `skipped` and `failed`. A
  skipped key is left alone on purpose and does not fail the call: a TPM2
  PIV slot key (`piv-<slot>`), a TPM2 sealed object `Seal` named
  (`xkms-sealing-key-tpm2-<uuid>`), the barrier's seal wrapping key
  (`xkms-barrier-seal`) -- each named exactly by its owner, so a new version
  would never be used -- and a key with a certificate ("has a certificate;
  re-issue after rotating it explicitly"). gRPC: `KeyRotationResult.state` =
  5, `reason` = 6; `RotateScopeKeysResponse.skipped` = 5.
- **Rotating a certified key.** `RotateKey` rotates a key with a certificate
  and reports `certificate_reissue_required: true` (gRPC
  `RotateKeyResponse.certificate_reissue_required` = 7): the certificate still
  certifies the previous version.

- The permissions reuse the key vocabulary: listing reads like listing keys,
  enabling and disabling versions is rotation lifecycle, and retiring
  destroys key material like deleting a key.
- The client side is `transport.KeyVersionService`, part of `transport.Client`.
  The REST and QUIC clients share `wire.KeyVersionClient`; the gRPC and Unix
  clients share `pbconv.KeyVersionClient`; the embedded transport calls
  `XKMSService`. The USB transport carries no key operations.
- Bodies: `pkg/api/transport/types_keyversion.go` -- `KeyVersionInfo`,
  `ListKeyVersionsRequest`/`Response`, `KeyVersionRequest`,
  `KeyVersionStateResponse`, `AllKeyVersionsRequest`/`Response`,
  `RotateScopeKeysRequest`/`Response`, `KeyRotationResult`. The gRPC version
  messages keep their declared `int32 version`; a negative one is refused as
  an invalid version.

`key_version` fields (JSON `key_version`, `uint32`, 0 or absent meaning
"not given"):

| Message | gRPC field | Meaning |
|---|---|---|
| `KeyInfo` (list, get) | `key_version` = 9 | The current version |
| `SignResponse` | `key_version` = 2 | The version that signed (current) |
| `VerifyRequest` / `VerifyResponse` | 9 / 3 | Verify with that version / the version it verified under |
| `EncryptResponse` | 6 | The version that encrypted (current) |
| `DecryptRequest` / `DecryptResponse` | 14 / 2 | Decrypt with that version / the version that decrypted |
| `EncryptAsymResponse` | 2 | The version whose public key encrypted |
| `RotateKeyResponse` | 6 | The new current version |
| `SealResponse` / `UnsealRequest` | 10 / 12 | The sealing key version, recorded beside the ciphertext |
| `WrapKeyByIDResponse` | `wrapping_key_version` = 3 | The wrapping key version |
| `UnwrapKeyByIDRequest` | `unwrapping_key_version` = 16 | The unwrapping key version |
| `DeriveKeyRequest` / `Response` | 19 / 5 | The base key version derived from |
| `DeriveKeyECDHRequest` / `Response` | 10 / 2 | The local key version agreed with |
| `KeyVersionInfo` | `current` = 5, `public_key_pem` = 6 | Listing detail |
| `ListKeyVersionsResponse` | `backend` = 4, `current_version` = 5 | |
| `Enable`/`DisableKeyVersionResponse` | `changed` = 4 | Whether the state changed |
| `Enable`/`DisableAllKeyVersionsResponse` | `versions` = 4, `state` = 5 | The versions reached |

Outputs never carry the version inside them: signatures, ciphertext and
sealed blobs keep their standard formats.

## Request bodies

`pkg/api/transport/types.go`: `TPMPolicy`, `TPMPolicyBranch`,
`TPMPolicyCondition`, `TPMPolicyCreateRequest`, `TPMPolicyDescriptionRequest`,
`TPMPolicyRequest`, `TPMPolicyListRequest`/`Response`,
`TPMPolicyDeleteRequest`, `TPMPolicyVerifyResponse`,
`TPMPolicyBranchVerification`, `TPMPolicyObjectsResponse`,
`TPMPolicyAutoUnsealRequest`, `TPMObjectPolicyRequest`/`Response`,
`TPMAuthorityRotateRequest`/`Response`, `TenantTPMModeResponse`,
`SetTenantTPMModeRequest`, `TenantVTPMStatusResponse`. PCR values and digests
are hex; timestamps are RFC 3339. `owner_auth` is the physical TPM's
owner-hierarchy authorization (base64 in JSON), used only to define and
undefine NV indices; it is never logged or echoed. REST `DELETE` takes
`owner_auth` in an optional body.

A policy is an OR of branches, each an AND of conditions. A create request
carries branches only; `pcr_values` and `pcr_digest` are captured from the
TPM, and a request carrying them is refused (`tpmpolicy.ErrPCRValuesSupplied`).

```json
POST /api/v1/tpm/policies
{"name": "boot-or-pin", "description": "firmware, or the password",
 "branches": [
   {"conditions": [{"type": "pcr", "bank": "sha256", "pcrs": [0, 7]},
                   {"type": "locality", "localities": [0]}]},
   {"conditions": [{"type": "auth_value"}]}]}

POST /api/v1/tpm/policies/boot-or-pin/description
{"description": "firmware and Secure Boot, or the password"}
```

A policy reports `description`, `branches` (each with its conditions,
captured `pcr_values`/`pcr_digest` and `approved`) and `approved` (every
branch approved). Verify reports `match` and `approved` for the policy and,
per branch, `branches[i].match`, `.mismatched` and `.approved`.

gRPC (`xkms.v1`, pre-v1, one wire format; removed numbers are reserved):

| Message | Fields |
|---|---|
| `TPMPolicyCondition` (new) | `type` = 1, `bank` = 2, `pcrs` = 3, `pcr_values` = 4, `pcr_digest` = 5, `localities` = 6 |
| `TPMPolicyBranch` (new) | `conditions` = 1, `approved` = 2 |
| `TPMPolicy` | `description` = 14, `branches` = 15; `bank`, `pcrs`, `pcr_values`, `pcr_digest` (3-6) removed |
| `TPMPolicyCreateRequest` | `description` = 7, `branches` = 8; `bank`, `pcrs` (3-4) removed |
| `TPMPolicyDescriptionRequest` (new) | `tenant_id` = 1, `name` = 2, `description` = 3 |
| `TPMPolicyBranchVerification` (new) | `match` = 1, `mismatched` = 2, `approved` = 3 |
| `TPMPolicyVerifyResponse` | `branches` = 5; `mismatched` (3) removed |

## Go SDK: offline authorization

Design: [`architecture.md`](architecture.md), "Offline authorization".
`sdk/go/tpmpolicy.go` exports:

- `TPMPolicyBindingResolver` (`:89`), what a TPM consults for named
  policies; `TPM.SetPolicyBindingResolver` installs one.
- `TPMStaticPolicyResolver` (`:94`) and `NewTPMStaticPolicyResolver(records
  ...[]byte)` (`:214`): a resolver over `.tpmpolicy` binding records, needing
  no database.
- `ErrTPMPolicyUnbound` (`:224`): the policy has no record in the resolver. A
  record without approvals resolves to `ErrTPMPolicyRevoked`.
- Refusals of `NewTPMStaticPolicyResolver`: `*TPMPolicyBindingFormatError`
  (`:253`) for a record that does not decode, `ErrTPMPolicyApprovalInvalid`
  (`:259`) for an approval that does not decode or is unsigned, and
  `ErrTPMPolicyApprovalMismatch` (`:264`) for an approval not signed by the
  record's authority or approving another policy, and for two records of one
  policy that disagree.

## Errors

Classified by `apierrors.TPMPolicyClassOf` (typed errors, then
`TPMPolicySentinelClasses`), read by the gRPC, MCP and REST handlers and by
each transport's key-operation mapper:

| Error | Class | gRPC | REST | MCP |
|---|---|---|---|---|
| `tpmpolicy.ErrPolicyNotFound`, `ErrScopeNotFound`, `ErrNotAssigned`, tenant binding | NotFound | `NotFound` | 404 | not found |
| `tpmpolicy.ErrPolicyExists` | AlreadyExists | `AlreadyExists` | 409 | duplicate |
| `*tpmpolicy.PolicyInUseError` (lists the objects), `*ScopeInUseError`, `*PCRBankUnavailableError`, `ErrTPMModeNone`, `ErrVTPMUnavailable`, `ErrNotVTPMMode`, `ErrPolicyRevoked` | FailedPrecondition | `FailedPrecondition` | 409 | internal error code (message kept) |
| `*InvalidNameError`, `*InvalidModeError`, `*InvalidTenantError`, `*InvalidPCRBankError`, `*InvalidPCRError`, `*InvalidLocalityError`, `*UnknownConditionTypeError`, `*DuplicateConditionError`, `*ConditionOperandError`, `*DescriptionTooLongError`, `ErrReservedPolicy`, `ErrEmptyPCRSelection`, `ErrEmptyLocalitySelection`, `ErrNoBranches`, `ErrEmptyBranch`, `ErrPCRValuesSupplied`, `ErrSystemScopeMode`, `pkg/tpm2.ErrPolicyAuthValueRequired` (a key or sealed object without a password bound to a policy with an `auth_value` condition), `*xkms.InvalidTPMObjectKindError`, `*xkms.ErrKeyIDParse`, `xkms.ErrTPMPolicyNotSupported`, `tpm2.ErrReservedObject` | InvalidArgument | `InvalidArgument` | 400 | invalid params |
| `tpm2.ErrSymmetricKeysUnsupported`, `tpm2.ErrTenantImportUnsupported` | Unimplemented | `Unimplemented` | 501 | method not found |
| `xkms.ErrNotConfigured` (no TPM2 backend) | Unavailable | `Unavailable` | 503 | service unavailable |

Key-version errors are classified by `apierrors.KeyVersionClassOf`, which
every transport's key-operation mapper reads first:

| Error | Class | gRPC | REST | MCP |
|---|---|---|---|---|
| `*keyversion.KeyVersionRequiredError` (AES-CBC or PKCS#1 v1.5 ciphertext, several enabled versions, no `key_version`), `*keyversion.ReservedKeyIDError`, `*keyversion.InvalidVersionError` | InvalidArgument | `InvalidArgument` | 400 | invalid params |
| `*keyversion.VersionNotFoundError`, `*xkms.KeyVersionMissingError` | NotFound | `NotFound` | 404 | not found |
| `*keyversion.CurrentVersionError` (disabling or retiring the current version), `*keyversion.VersionUnavailableError` (a disabled or retired version named), `*keyversion.RetiredVersionError` | FailedPrecondition | `FailedPrecondition` | 409 | internal error code (message kept) |
| `*xkms.KeyExistsError` (a new key under a rotated key's ID) | AlreadyExists | `AlreadyExists` | 409 | duplicate |
| `*xkms.KeyRotationUnsupportedError` (X25519, post-quantum) | Unimplemented | `Unimplemented` | 501 | method not found |
| `xkms.ErrKeyVersionsNotConfigured` (no version store) | Unavailable | `Unavailable` | 503 | service unavailable |
