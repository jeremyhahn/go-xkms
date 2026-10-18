# Go-xKMS API Specifications

> **Status: REFERENCE** · Last verified: 2026-10-12
> Catalogue of every REST route, gRPC RPC and MCP method, checked against the route table, the `.proto` files and the MCP dispatch map; feature folders are normative for request and response shapes.

All transports call the same `transport.XKMSServicer`
(`pkg/api/transport/servicer.go:36`). Request and response shapes for each
capability are documented in its feature folder's `api.md`.

## REST API

The route table is `pkg/api/rest/routes.go`. Each route has one of three
auth modes:

- **Public** — no credentials needed.
- **Permission** — an authenticated caller who holds the route's
  resource/action permission.
- **Session** — any authenticated session.

Some routes are registered only when their subsystem is configured, such as
the CA, invites, WebAuthn or SSH.

Errors are JSON `{"error": "...", "message": "...", "code": <int>}`
(`ErrorResponse`, `pkg/api/rest/types.go:149-153`).

### Public routes

| Method | Path |
|---|---|
| GET, HEAD | `/health` |
| GET | `/health/live`, `/health/ready`, `/health/startup` |
| GET | `/api/v1/algorithms`, `/api/v1/capabilities` |
| GET | `/v1/ca/bootstrap` |

(`routes.go:124-131`)

### `/api/v1` — keys and backends

Prefix: `routes.go:136`.

| Method | Path |
|---|---|
| GET | `/backends`, `/backends/{id}` |
| POST, GET | `/keys` |
| GET, DELETE | `/keys/{id}` |
| POST | `/keys/{id}/sign`, `/keys/{id}/verify`, `/keys/{id}/rotate` |
| POST | `/keys/{id}/encrypt`, `/keys/{id}/decrypt`, `/keys/{id}/encrypt-asym` |
| POST | `/keys/{id}/export`, `/keys/{id}/export-material` |
| GET | `/keys/{id}/versions`, `/keys/{id}/tpm-policy` |
| POST | `/keys/{id}/versions/enable-all`, `/keys/{id}/versions/disable-all` |
| POST | `/keys/{id}/versions/{version}/enable`, `/disable`, `/retire` |
| POST | `/keys/rotate-all`, `/keys/import-params`, `/keys/import`, `/keys/copy` |
| POST | `/keys/wrap`, `/keys/unwrap`, `/keys/wrap-by-id`, `/keys/unwrap-by-id` |
| POST | `/keys/derive-ecdh`, `/attest` |

### `/api/v1` — certificates, sealing, FROST

| Method | Path |
|---|---|
| POST, GET | `/certs` |
| GET, DELETE, HEAD | `/certs/{id}` |
| POST, GET | `/certs/{id}/chain` |
| GET | `/tls/{id}` |
| POST | `/seal`, `/unseal` |
| GET | `/seal/capability` |
| POST, GET | `/frost/keys` |
| POST | `/frost/keys/import` |
| GET, DELETE | `/frost/keys/{id}` |
| POST | `/frost/keys/{id}/nonces`, `/frost/keys/{id}/sign`, `/frost/aggregate`, `/frost/verify` |

### `/api/v1` — CA

| Method | Path |
|---|---|
| GET | `/ca/bundle`, `/ca/certificate`, `/ca/crl`, `/ca/revoked/{serial}` |
| POST | `/ca/sign-csr`, `/ca/issue`, `/ca/revoke`, `/ca/crl` |
| POST | `/ca/tcg/ek`, `/ca/tcg/ak`, `/ca/tcg/sign-csr`, `/ca/tcg/enroll`, `/ca/tcg/lak` |

Without a configured CA, `/ca/bundle` falls back to the generic bundle handler
(`routes.go:272`, `:285`).

### `/api/v1` — PIN, PIV, bootstrap, credentials

| Method | Path |
|---|---|
| GET | `/bootstrap/keys` |
| POST | `/pin/so/set`, `/pin/user/set`, `/pin/so/change`, `/pin/user/change`, `/pin/so/verify`, `/pin/user/verify` |
| GET | `/pin/lockout` |
| POST | `/pin/lockout/reset` |
| GET | `/piv/slots` |
| GET, POST, DELETE | `/piv/slots/{slot}/certificate` |
| POST | `/piv/slots/{slot}/generate`, `/piv/slots/{slot}/import`, `/piv/slots/{slot}/csr` |
| GET | `/piv/slots/{slot}/export` |
| POST | `/credentials/submit` |
| GET | `/credentials`, `/credentials/strategy` |

### `/api/v1` — tenants, TPM policy

| Method | Path |
|---|---|
| POST, GET | `/tenants/` |
| GET, DELETE | `/tenants/{tenantID}` |
| PUT | `/tenants/{tenantID}/entitlements`, `/tenants/{tenantID}/quotas` |
| GET, PUT | `/tenants/{tenantID}/tpm` |
| GET | `/tenants/{tenantID}/tpm/vtpm` |
| POST | `/tenants/{tenantID}/tpm/vtpm/start`, `/tenants/{tenantID}/tpm/vtpm/stop` |
| POST, GET | `/tpm/policies` |
| GET, DELETE | `/tpm/policies/{name}` |
| POST | `/tpm/policies/{name}/update`, `/revoke`, `/verify`, `/auto-unseal`, `/description` |
| GET | `/tpm/policies/{name}/objects` |
| POST | `/tpm/authority/rotate` |

### `/api/v1` — passwords, platform secrets, PKCS#11 state, OIDC

| Method | Path |
|---|---|
| POST, GET | `/passwords/` |
| GET, PUT, DELETE | `/passwords/{id}` |
| POST | `/passwords/access-mode`, `/passwords/generate` |
| GET | `/password-vault`, `/password-vault/session` |
| POST | `/password-vault/unlock`, `/password-vault/lock`, `/password-vault/factors`, `/password-vault/recover` |
| PUT, DELETE | `/password-vault/factors/{id}` |
| GET | `/platform/secrets`, `/platform/status` |
| PUT, GET, DELETE | `/platform/secrets/{name}` |
| POST | `/platform/secrets/{name}/reseal` |
| POST | `/pkcs11state/put`, `/put-if-absent`, `/compare-and-swap`, `/compare-and-delete`, `/get`, `/delete`, `/list` |
| POST, GET | `/oidc/credentials` |
| GET, DELETE | `/oidc/credentials/{scope}/{name}` |
| POST | `/oidc/credentials/{scope}/{name}/import`, `/refresh`, `/token`, `/device`, `/device/poll` |

### `/api/v1/auth`

Registered when a token issuer is configured (`routes.go:423-427`).

| Method | Path | Auth |
|---|---|---|
| POST | `/api/v1/auth/login/piv`, `/api/v1/auth/refresh` | Public |
| GET | `/api/v1/auth/me`, `/api/v1/auth/validate` | Session |
| POST | `/api/v1/auth/logout` | Session |

### `/api/v1/webauthn`

Prefix: `routes.go:437`. The ceremony routes are public; adding a credential
to an existing account (`POST /credentials/begin`, `routes.go:447`) needs a
session.

| Method | Path |
|---|---|
| POST | `/registration/begin`, `/registration/finish`, `/login/begin`, `/login/finish` |
| POST | `/sdk/registration/begin`, `/sdk/registration/finish`, `/sdk/authentication/begin`, `/sdk/authentication/finish` |
| POST | `/credentials/begin` |

### `/api/v1/invites` (public)

Prefix: `routes.go:456`.

| Method | Path |
|---|---|
| GET | `/{tenant_id}/{token}` |
| POST | `/{tenant_id}/{token}/fido2/begin`, `/{tenant_id}/{token}/fido2/finish`, `/{tenant_id}/{token}/piv/activate` |

### `/api/v1/users`

Prefix: `routes.go:466`.

| Method | Path |
|---|---|
| POST, GET | `/` |
| GET, DELETE | `/{username}` |
| GET | `/{username}/credentials` |
| POST | `/{username}/enable`, `/{username}/disable`, `/{username}/cert-bindings` |

### `/xkms/v1/ssh`

Prefix: `routes.go:488`.

| Method | Path |
|---|---|
| POST, GET | `/keys` |
| POST | `/keys/import` |
| GET, DELETE | `/keys/{scope}/{owner}/{name}` |
| GET | `/keys/{scope}/{owner}/{name}/public` |
| POST | `/keys/{scope}/{owner}/{name}/sign` |
| POST, GET | `/known-hosts` |
| DELETE | `/known-hosts/{host}` |
| POST | `/known-hosts/{host}/verify` |
| POST, GET | `/authorized-keys` |
| GET, DELETE | `/authorized-keys/{scope}/{owner}/{name}` |
| POST | `/authorized-keys/emit`, `/authorized-keys/verify` |

### HTTP/3

QUIC is HTTP/3 served on the REST port (`pkg/server/server.go:2433-2434`),
so every REST route above is also reachable over HTTP/3.

## gRPC API

### `xkms.v1.KeystoreService`

Defined in `pkg/api/grpc/proto/xkmsv1/xkms.proto:15`. Registered on the TCP
listener (`pkg/api/grpc/server.go:166`) and on the Unix socket
(`pkg/api/unix/grpc_server.go:338`). Regenerate the stubs with `make proto`.

| Area | RPCs |
|---|---|
| Health, discovery | `Health`, `ListBackends`, `GetBackendInfo`, `Algorithms` |
| Keys | `GenerateKey`, `ListKeys`, `GetKey`, `DeleteKey`, `RotateKey`, `RotateScopeKeys`, `CopyKey`, `AttestKey` |
| Key versions | `ListKeyVersions`, `EnableKeyVersion`, `DisableKeyVersion`, `EnableAllKeyVersions`, `DisableAllKeyVersions`, `RetireKeyVersion` |
| Crypto | `Sign`, `Verify`, `Encrypt`, `Decrypt`, `EncryptAsym` |
| Derivation | `DeriveKey`, `DeriveKeyECDH`, `DeriveKeyECDHSecure`, `UseResidentKey`, `DestroyResidentKey`, `GenerateEphemeralECDH` |
| Import, export | `GetImportParameters`, `WrapKey`, `UnwrapKey`, `WrapKeyByID`, `UnwrapKeyByID`, `ImportKey`, `ExportKey`, `ExportKeyMaterial` |
| Certificates | `SaveCert`, `GetCert`, `DeleteCert`, `ListCerts`, `CertExists`, `SaveCertChain`, `GetCertChain`, `GetTLSCertificate` |
| Sealing | `Seal`, `Unseal`, `CanSeal` |
| FROST | `FrostGenerateKey`, `FrostImportKey`, `FrostListKeys`, `FrostGetKey`, `FrostDeleteKey`, `FrostGenerateNonces`, `FrostSignRound`, `FrostAggregate`, `FrostVerify` |
| CA | `GetCABundle`, `GetCACertificate`, `SignCSR`, `IssueCertificate`, `RevokeCertificate`, `GenerateCRL`, `IsRevoked` |
| TCG CA | `IssueEKCertificate`, `IssueAKCertificate`, `SignTCGCSR`, `EnrollDevice`, `IssueLAKCertificate` |
| Bootstrap | `BootstrapListenerKeys` |
| PIN | `SetSOPIN`, `SetUserPIN`, `ChangeSOPIN`, `ChangeUserPIN`, `VerifySOPIN`, `VerifyUserPIN`, `GetLockoutStatus`, `ResetLockout` |
| PIV | `ListPIVSlots`, `GetPIVCertificate`, `StorePIVCertificate`, `DeletePIVCertificate`, `GeneratePIVKey`, `ImportPIVCertificate`, `ExportPIVCertificate`, `GeneratePIVCSR` |
| Tenants | `CreateTenant`, `GetTenant`, `ListTenants`, `DeleteTenant`, `UpdateTenantEntitlements`, `UpdateTenantQuotas` |
| Passwords | `PasswordAdd`, `PasswordGet`, `PasswordList`, `PasswordUpdate`, `PasswordDelete`, `PasswordGenerate`, `PasswordStoreUnlock`, `PasswordStoreLock`, `PasswordStoreStatus`, `PasswordStoreSetAccessMode`, `PasswordVaultStatus`, `PasswordVaultEnroll`, `PasswordVaultRotate`, `PasswordVaultRemoveFactor`, `PasswordVaultRecover` |
| TPM policy | `TPMPolicyCreate`, `TPMPolicyGet`, `TPMPolicyList`, `TPMPolicyUpdate`, `TPMPolicyRevoke`, `TPMPolicyVerify`, `TPMPolicyDelete`, `TPMPolicyObjects`, `TPMPolicySetAutoUnseal`, `TPMPolicySetDescription`, `TPMObjectPolicy`, `TPMPolicyRotateAuthority` |
| Tenant TPM | `GetTenantTPMMode`, `SetTenantTPMMode`, `TenantVTPMStatus`, `TenantVTPMStart`, `TenantVTPMStop` |
| OIDC credentials | `OIDCCredentialCreate`, `OIDCCredentialImport`, `OIDCCredentialGet`, `OIDCCredentialList`, `OIDCCredentialDelete`, `OIDCCredentialRefresh`, `OIDCCredentialGetAccessToken`, `OIDCCredentialDeviceStart`, `OIDCCredentialDevicePoll` |
| PKCS#11 state | `PKCS11StatePut`, `PKCS11StatePutIfAbsent`, `PKCS11StateCAS`, `PKCS11StateCAD`, `PKCS11StateGet`, `PKCS11StateDelete`, `PKCS11StateList` |
| Platform seal store | `SealStorePut`, `SealStoreGet`, `SealStoreDelete`, `SealStoreList`, `SealStoreReseal`, `SealStoreStatus` |
| Users | `CreateUser`, `ListUsers`, `GetUser`, `DeleteUser`, `EnableUser`, `DisableUser`, `BindUserCert`, `ListUserCredentials` |
| WebAuthn | `BeginRegistration`, `FinishRegistration`, `BeginAuthentication`, `FinishAuthentication` |
| Invites | `GetInvite`, `BeginInviteRegistration`, `FinishInviteRegistration`, `ActivateInvitePIV` |
| SSH | `SSHGenerateKey`, `SSHImportKey`, `SSHListKeys`, `SSHGetKey`, `SSHDeleteKey`, `SSHExportPublic`, `SSHSign`, `SSHAddKnownHost`, `SSHListKnownHosts`, `SSHRemoveKnownHost`, `SSHAddAuthorizedKey`, `SSHListAuthorizedKeys`, `SSHRemoveAuthorizedKey` |

### `trustedca.admin.v1.AdminService`

Defined in `api/proto/admin.proto:24` and served by the ACME server
(`pkg/acme/api/server/server.go:815`, `:860`). See
[acme-issuance](../acme-issuance/api.md).

| Area | RPCs |
|---|---|
| Tenants | `CreateTenant`, `GetTenant`, `UpdateTenant`, `DeleteTenant`, `ListTenants` |
| EAB | `CreateEAB`, `GetEAB`, `DeleteEAB`, `ListEABs` |
| Tenant roles | `CreateTenantRole`, `GetTenantRole`, `UpdateTenantRole`, `DeleteTenantRole`, `ListTenantRoles` |
| Tenant users | `CreateTenantUser`, `GetTenantUser`, `UpdateTenantUser`, `DeleteTenantUser`, `ListTenantUsers` |
| Certificates | `ListCertificates`, `GetCertificate`, `RevokeCertificate` |
| Accounts | `ListAccounts`, `GetAccount`, `DisableAccount` |
| Status | `GetStatus`, `GetStats` |

## MCP

MCP is served by the embedded qrdb node on `server.mcp_port`
(`pkg/server/qrdb_node.go:85-86`). Each xkms method is one MCP tool. The
tool is named `xkms_<method>`, with dots turned into underscores, and takes
one optional `params_json` string argument (`pkg/mcptool/client.go:82-89`,
`:405-422`). Methods dispatch through `rpcMethods`
(`pkg/api/mcp/server.go:247`), which also declares each method's permission:

| Area | Methods |
|---|---|
| Health, discovery | `health`, `xkms.algorithms`, `xkms.listBackends`, `xkms.getBackend` |
| Keys | `xkms.generateKey`, `xkms.getKey`, `xkms.deleteKey`, `xkms.listKeys`, `xkms.rotateKey`, `xkms.copyKey`, `xkms.attestKey` |
| Key versions | `xkms.listKeyVersions`, `xkms.enableKeyVersion`, `xkms.disableKeyVersion`, `xkms.retireKeyVersion`, `xkms.enableAllKeyVersions`, `xkms.disableAllKeyVersions`, `xkms.rotateScopeKeys` |
| Crypto | `xkms.sign`, `xkms.verify`, `xkms.encrypt`, `xkms.decrypt`, `xkms.asymmetricEncrypt`, `xkms.asymmetricDecrypt`, `xkms.deriveKey`, `xkms.deriveKeyECDH` |
| Import, export | `xkms.getImportParameters`, `xkms.wrapKey`, `xkms.unwrapKey`, `xkms.wrapKeyByID`, `xkms.unwrapKeyByID`, `xkms.importKey`, `xkms.exportKey`, `xkms.exportKeyMaterial` |
| Certificates | `xkms.saveCert`, `xkms.getCert`, `xkms.deleteCert`, `xkms.listCerts`, `xkms.certExists`, `xkms.saveCertChain`, `xkms.getCertChain`, `xkms.getTLSCertificate` |
| Sealing | `xkms.seal`, `xkms.unseal`, `xkms.canSeal` |
| PIV | `xkms.listPIVSlots`, `xkms.getPIVCertificate`, `xkms.storePIVCertificate`, `xkms.deletePIVCertificate`, `xkms.generatePIVKey`, `xkms.importPIVCertificate`, `xkms.exportPIVCertificate`, `xkms.generatePIVCSR` |
| CA | `xkms.ca.bundle`, `xkms.ca.certificate`, `xkms.ca.sign-csr`, `xkms.ca.issue`, `xkms.ca.revoke`, `xkms.ca.crl`, `xkms.ca.is-revoked`, `xkms.ca.tcg.issue-ek`, `xkms.ca.tcg.issue-ak`, `xkms.ca.tcg.sign-csr`, `xkms.ca.tcg.enroll`, `xkms.ca.tcg.issue-lak` |
| Bootstrap | `bootstrap.showKeys` |
| PIN | `xkms.setSOPIN`, `xkms.setUserPIN`, `xkms.changeSOPIN`, `xkms.changeUserPIN`, `xkms.verifySOPIN`, `xkms.verifyUserPIN`, `xkms.getLockoutStatus`, `xkms.resetLockout` |
| Tenants | `xkms.createTenant`, `xkms.getTenant`, `xkms.listTenants`, `xkms.deleteTenant`, `xkms.updateTenantEntitlements`, `xkms.updateTenantQuotas`, `xkms.getTenantTPMMode`, `xkms.setTenantTPMMode`, `xkms.tenantVTPMStatus`, `xkms.tenantVTPMStart`, `xkms.tenantVTPMStop` |
| Credentials | `credentials.submit`, `credentials.strategy` |
| Users | `user.create`, `user.list`, `user.get`, `user.delete`, `user.enable`, `user.disable`, `user.bindCert`, `user.listCredentials` |
| Invites | `invite.get`, `invite.pivActivate` |
| Passwords | `password.add`, `password.get`, `password.list`, `password.update`, `password.delete`, `password.unlock`, `password.lock`, `password.status`, `password.generate`, `password.setAccessMode`, `password.vault.status`, `password.vault.enroll`, `password.vault.rotate`, `password.vault.removeFactor`, `password.vault.recover` |
| Platform seal store | `sealStore.put`, `sealStore.get`, `sealStore.delete`, `sealStore.list`, `sealStore.reseal`, `sealStore.status` |
| TPM policy | `tpm.policy.create`, `tpm.policy.get`, `tpm.policy.list`, `tpm.policy.update`, `tpm.policy.revoke`, `tpm.policy.verify`, `tpm.policy.delete`, `tpm.policy.objects`, `tpm.policy.autoUnseal`, `tpm.policy.setDescription`, `tpm.object.policy`, `tpm.authority.rotate` |
| OIDC credentials | `oidc.credential.create`, `oidc.credential.import`, `oidc.credential.get`, `oidc.credential.list`, `oidc.credential.delete`, `oidc.credential.refresh`, `oidc.credential.token`, `oidc.credential.device.start`, `oidc.credential.device.poll` |
| SSH | `ssh.keys.generate`, `ssh.keys.import`, `ssh.keys.list`, `ssh.keys.get`, `ssh.keys.delete`, `ssh.keys.export`, `ssh.keys.sign`, `ssh.knownHosts.add`, `ssh.knownHosts.list`, `ssh.knownHosts.remove`, `ssh.knownHosts.verify`, `ssh.authorizedKeys.add`, `ssh.authorizedKeys.get`, `ssh.authorizedKeys.list`, `ssh.authorizedKeys.remove`, `ssh.authorizedKeys.emit`, `ssh.authorizedKeys.verify` |

WebAuthn registration and authentication, and the invite FIDO2 ceremony, are
not exposed over MCP (`pkg/api/mcp/server.go:393-396`).

## CLI

`xkmsctl` reaches the same surface. Its global flags are in
`cmd/xkmsctl/root.go:116-153`; see [quick-reference.md](./quick-reference.md#binaries)
and each feature folder's `cli.md`.
