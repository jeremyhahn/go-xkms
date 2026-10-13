# Admin Views

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed reference for the views in `pkg/acme/web/packages/admin/src/views/`.

Views reach the API through `src/lib/api/admin-api.ts`, mostly via the stores
in `src/lib/stores/`. The paths below are the ones that file calls.

## Dashboard

`Dashboard.svelte` shows CA status and statistics through the `status` store
(`GET /admin/status`, `GET /admin/stats`). It also lists the certificates
expiring within 30 days
(`GET /admin/certificates?expires_days=30&per_page=5`).

## Seal Manager

`SealManager.svelte` shows the barrier's seal state through the shared barrier
API and polls it every 10 s.

## Certificates

`Certificates.svelte` is a paginated certificate list from the `certs` store
(`GET /admin/certificates`).

## Accounts

`Accounts.svelte` is a paginated ACME account list from the `accounts` store
(`GET /admin/accounts`).

## CA Manager

`CAManager.svelte` shows the root CA status (`GET /admin/status`) and each
tenant's CA status (`GET /api/v1/tenants/{id}/ca-status`). It creates tenant
intermediate CAs (`POST /api/v1/tenants/{id}/intermediate-cas`).

## Orders and Order Detail

`Orders.svelte` and `OrderDetail.svelte` read the `orders` store
(`GET /admin/orders`, `GET /admin/orders/{id}`).

## Tenants

`Tenants.svelte` lists tenants (`GET /api/v1/tenants`) and creates them with
an ID and a name (`POST /api/v1/tenants`).

## Tenant Detail

`TenantDetail.svelte` has four tabs:
- **Overview**: tenant information
- **Certificate Authorities**: CA status, plus creating the tenant root CA and
  intermediate CAs (`/api/v1/tenants/{id}/ca-status`, `/root-ca`,
  `/intermediate-cas`)
- **EAB Credentials**: placeholder text only
- **Settings**: placeholder text only

## Audit Log

`AuditLog.svelte` is a paginated audit list (`GET /admin/audit`).

## Connection Settings

`ConnectionSettings.svelte` is read-only. It shows the API base URL from
`getApiBaseUrl()` and the connection status. The sidebar always shows it.

## Settings

`Settings.svelte` offers the theme choice: Light, Dark or System.

## Unused views

`EABManager.svelte`, `RoleManager.svelte` and `UserManager.svelte` are in the
`views/` directory, but `App.svelte` never imports them, so they are
unreachable.
