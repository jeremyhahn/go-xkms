- **The MCP surface now serves PIN management, custodian groups, tenant
  administration, and non-ECDH key derivation.** 25 JSON-RPC methods that REST
  and gRPC already served had no MCP handler and were unreachable
  ("method not found"), not merely unauthorized:
  `xkms.setSOPIN`/`setUserPIN`/`changeSOPIN`/`changeUserPIN`/`verifySOPIN`/
  `verifyUserPIN`/`getLockoutStatus`/`resetLockout`;
  `xkms.createCustodianGroup`/`getCustodianGroup`/`listCustodianGroups`/
  `deleteCustodianGroup`/`addCustodianMember`/`removeCustodianMember`/
  `distributeShares`;
  `xkms.createTenant`/`getTenant`/`listTenants`/`deleteTenant`/
  `tenantBarrierInit`/`tenantBarrierUnseal`/`tenantBarrierStatus`/
  `updateTenantEntitlements`/`updateTenantQuotas`; and `xkms.deriveKey`. Every
  handler delegates to the same `XKMSService` methods REST and gRPC already
  call and carries an RBAC permission mirroring gRPC's `s.authorize` calls
  (`pin:read`/`pin:write`, `ceremony:*`, `tenants:*`/`tenant_barrier:*`,
  `keys:derive`) — REST serves the PIN, custodian, and tenant routes under
  session-only auth with no RBAC permission of their own, so gRPC's
  already-enforced grants are this table's source. `GetTenant`, `DeleteTenant`,
  and the three `TenantBarrier*` methods reproduce REST's cross-tenant
  anti-enumeration behavior: a tenant-scoped caller naming another tenant
  receives the identical refusal a nonexistent tenant ID would. The MCP
  client transport (`pkg/api/transport/mcp`) already called every one of
  these method names; only the server-side handlers, dispatch registration,
  and authorization mapping were missing (#773).
