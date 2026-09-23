- **BREAKING: the tenant "legacy path" that served CRUD and barrier
  operations directly off `*seal.BarrierRegistry` when no `TenantService` was
  composed is deleted — `TenantService` is now required everywhere a tenant
  operation is served.** `pkg/xkms/servicer_tenant.go`
  (`XKMSService.CreateTenant`, `GetTenant`, `ListTenants`, `DeleteTenant`,
  `TenantBarrierInit`, `TenantBarrierUnseal`, `TenantBarrierStatus`) no longer
  falls back to `s.barrierRegistry` when `s.tenantService` is nil; every one
  now returns the typed `ErrTenantServiceNotConfigured`. `XKMSService`'s
  `barrierRegistry` field and `SetBarrierRegistry` method, and the
  `ErrBarrierRegistryNotConfigured` sentinel, are deleted along with the
  three helper functions (`validateTenantStrategy`, `tenantInitCredentials`,
  `tenantUnsealCredentials`) the deleted branches alone used.

  `pkg/api/rest.NewTenantHandlers` now returns `(*TenantHandlers, error)`
  instead of `*TenantHandlers`: it requires both `registry` and `svc`, and
  requires `svc.TenantService()` to already be composed, rejecting a
  barrier-registry-only configuration with the existing
  `ErrTenantNotConfigured` at construction time rather than serving some
  routes and 500ing others at request time. Every handler
  (`CreateTenantHandler`, `ListTenantsHandler`, `GetTenantHandler`,
  `DeleteTenantHandler`, `TenantBarrierStatusHandler`,
  `TenantBarrierInitHandler`, `TenantBarrierUnsealHandler`) lost its
  registry-direct branch; `TenantBarrierInitHandler` / `UnsealHandler` now
  build their response via `xkmsService.TenantBarrierStatus` instead of
  reading `h.registry.TenantStatus` directly, matching
  `TenantBarrierStatusHandler`'s existing path. `pkg/api/rest/errors.go`'s
  `mapErrorToStatusCode` gained mappings for go-qrdb's own
  `qrdbsdk.ErrTenantMissing` (404) and `qrdbsdk.ErrTenantExists` (409): the
  servicer-routed path was previously under-exercised (every existing test
  wired only the registry, not a `TenantService`, so the internal fallback
  silently absorbed the gap), and now that the fallback is gone these
  sentinels are the ones a composed `TenantService` actually returns.

  `pkg/server/server.go` no longer calls the deleted `svc.SetBarrierRegistry`
  when wiring `XKMSService`.