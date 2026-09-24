- **BREAKING: `admin.NewTenantAwareAdminService` now returns `(*TenantAwareAdminService, error)`
  and refuses construction when the storage factory's tenant DAO fails to
  initialize**: previously, when a `storage.TenantAwareFactory` claimed
  tenant-aware support but its `TenantDAO()` call failed, construction logged
  the failure and silently continued with a `nil` local tenant DAO — a
  degraded mode nobody approved. It now returns `*admin.TenantDAOInitError`
  (wrapping the cause via `Unwrap`) and constructs nothing. A `storageFactory`
  that simply does not implement `storage.TenantAwareFactory` remains a
  legitimate, unrefused configuration: it is xkmsd's only production shape
  today (`cmd/xkmsd/acme.go` wires `objstore.NewFactoryFromKVStore`, the
  plain non-tenant-aware factory), the local tenant DAO is never
  authoritative for tenant existence — only an optional linkage row for
  CA/EAB/status state qrdb has no concept of, with qrdb's `TenantServicer`
  as the sole tenant authority — and every method already guards
  `tenantDAO != nil`. `cmd/xkmsd/admin.go` and `pkg/acme/client/trustedca.go`
  now propagate the error through their own typed errors instead of
  discarding it. (go-xkms#867)
