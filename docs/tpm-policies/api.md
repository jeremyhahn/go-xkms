# TPM Policies — API

> **Status: NORMATIVE** · Feature: `tpm-policies` · Repo: `go-xkms` · Last verified: 2026-09-29

Design: [`architecture.md`](architecture.md). Service: `pkg/tpmpolicy.Service`,
reached only through `XKMSService` (`pkg/xkms/servicer_tpm_policy.go`), which
every transport calls.

## Tenancy

- Every policy operation acts on a tenant's TPM scope. A tenant-scoped caller
  acts on its own tenant: it may leave `tenant_id` empty or name its own
  tenant, and naming another is refused with the unknown-tenant not-found
  (`xkms.TenantBindingError`). A cross-tenant (system) caller may name any
  tenant; an empty `tenant_id` is the system scope.
- A tenant's TPM mode and its vTPM are system-scope only
  (`requirePlatformScope`): a tenant-scoped caller is refused even for its own
  tenant.

## Operations

| Operation | REST | gRPC / Unix (`KeystoreService.`) | MCP tool | Permission |
|---|---|---|---|---|
| Create a policy (captures live PCRs) | `POST /api/v1/tpm/policies` | `TPMPolicyCreate` | `tpm.policy.create` | `tpm_policy:create` |
| List policies | `GET /api/v1/tpm/policies[?tenant_id=]` | `TPMPolicyList` | `tpm.policy.list` | `tpm_policy:list` |
| Get a policy | `GET /api/v1/tpm/policies/{name}[?tenant_id=]` | `TPMPolicyGet` | `tpm.policy.get` | `tpm_policy:get` |
| Update (re-capture, re-approve) | `POST /api/v1/tpm/policies/{name}/update` | `TPMPolicyUpdate` | `tpm.policy.update` | `tpm_policy:update` |
| Revoke the approval | `POST /api/v1/tpm/policies/{name}/revoke` | `TPMPolicyRevoke` | `tpm.policy.revoke` | `tpm_policy:revoke` |
| Verify against live PCRs | `POST /api/v1/tpm/policies/{name}/verify` | `TPMPolicyVerify` | `tpm.policy.verify` | `tpm_policy:verify` |
| Delete (refused while assigned) | `DELETE /api/v1/tpm/policies/{name}` | `TPMPolicyDelete` | `tpm.policy.delete` | `tpm_policy:delete` |
| Objects bound to a policy | `GET /api/v1/tpm/policies/{name}/objects` | `TPMPolicyObjects` | `tpm.policy.objects` | `tpm_policy:get` |
| Set or clear auto-unseal | `POST /api/v1/tpm/policies/{name}/auto-unseal` | `TPMPolicySetAutoUnseal` | `tpm.policy.autoUnseal` | `tpm_policy:update` |
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
| `SealRequest.TPMPolicy` | `tpm_policy` | `SealRequest.tpm_policy` = 6 | TPM2 sealed object bound to the named policy, `platform`, or empty for none. |
| `SealRequest.Password` | `password` | `SealRequest.password` = 5 | The sealed object's authorization value. |

gRPC also gained the fields a TPM2 sealed object needs to round-trip:
`SealResponse.tpm_public` = 6, `tpm_private` = 7, `wrapped_dek` = 8,
`key_id` = 9; `UnsealRequest.tpm_public` = 7, `tpm_private` = 8,
`wrapped_dek` = 9, `metadata` = 10, `password` = 11. An unseal needs a
ciphertext, or both TPM areas.

A TPM2 seal's key ID names the sealed object; without one the object is
`xkms-sealing-key-tpm2` in the caller's scope. A sealed object bound to a
named policy is recorded against it (`sealed/<name>`).

## Request bodies

`pkg/api/transport/types.go`: `TPMPolicy`, `TPMPolicyCreateRequest`,
`TPMPolicyRequest`, `TPMPolicyListRequest`/`Response`,
`TPMPolicyDeleteRequest`, `TPMPolicyVerifyResponse`,
`TPMPolicyObjectsResponse`, `TPMPolicyAutoUnsealRequest`,
`TPMObjectPolicyRequest`/`Response`, `TPMAuthorityRotateRequest`/`Response`,
`TenantTPMModeResponse`, `SetTenantTPMModeRequest`,
`TenantVTPMStatusResponse`. PCR values and digests are hex; timestamps are
RFC 3339. `owner_auth` is the physical TPM's owner-hierarchy authorization
(base64 in JSON), used only to define and undefine NV indices; it is never
logged or echoed. REST `DELETE` takes `owner_auth` in an optional body.

## Errors

Classified by `apierrors.TPMPolicyClassOf` (typed errors, then
`TPMPolicySentinelClasses`), read by the gRPC, MCP and REST handlers and by
each transport's key-operation mapper:

| Error | Class | gRPC | REST | MCP |
|---|---|---|---|---|
| `tpmpolicy.ErrPolicyNotFound`, `ErrScopeNotFound`, `ErrNotAssigned`, tenant binding | NotFound | `NotFound` | 404 | not found |
| `tpmpolicy.ErrPolicyExists` | AlreadyExists | `AlreadyExists` | 409 | duplicate |
| `*tpmpolicy.PolicyInUseError` (lists the objects), `*ScopeInUseError`, `*PCRBankUnavailableError`, `ErrTPMModeNone`, `ErrVTPMUnavailable`, `ErrNotVTPMMode`, `ErrPolicyRevoked` | FailedPrecondition | `FailedPrecondition` | 409 | internal error code (message kept) |
| `*InvalidNameError`, `*InvalidModeError`, `*InvalidTenantError`, `*InvalidPCRBankError`, `*InvalidPCRError`, `ErrReservedPolicy`, `ErrEmptyPCRSelection`, `ErrSystemScopeMode`, `*xkms.InvalidTPMObjectKindError`, `*xkms.ErrKeyIDParse`, `xkms.ErrTPMPolicyNotSupported`, `tpm2.ErrReservedObject` | InvalidArgument | `InvalidArgument` | 400 | invalid params |
| `tpm2.ErrSymmetricKeysUnsupported`, `tpm2.ErrTenantImportUnsupported` | Unimplemented | `Unimplemented` | 501 | method not found |
| `xkms.ErrNotConfigured` (no TPM2 backend) | Unavailable | `Unavailable` | 503 | service unavailable |
