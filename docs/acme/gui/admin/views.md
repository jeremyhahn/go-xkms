# Admin Views

All views are Svelte components in `web/packages/admin/src/views/`.

## Dashboard

`Dashboard.svelte` -- CA status overview.

Displays: CA identity, version, uptime, key/signature algorithms, root and intermediate CA info.

Statistics: total/valid/revoked/expired certificates, total/active accounts, total/pending/completed orders.

Calls `GET /api/v1/status`, `GET /api/v1/stats`.

## Certificates

`Certificates.svelte` -- Certificate management.

Features: paginated list with subject, serial, status, validity dates. Filter by status or subject. View certificate details. Revoke certificates with reason.

Calls `GET /api/v1/certificates`, `GET /api/v1/certificates/{serial}`, `POST /api/v1/certificates/{serial}/revoke`.

## Accounts

`Accounts.svelte` -- ACME account management.

Features: paginated list with status, contact, creation date, order count. View account details. Disable accounts.

Calls `GET /api/v1/accounts`, `GET /api/v1/accounts/{id}`, `DELETE /api/v1/accounts/{id}`.

## Tenants

`Tenants.svelte` -- Multi-tenant management list.

Features: list all tenants, create new tenants, navigate to tenant detail.

Calls `GET /api/v1/tenants`, `POST /api/v1/tenants`.

## Tenant Detail

`TenantDetail.svelte` -- Individual tenant management.

Sub-sections:
- **Info** -- View/edit tenant name and settings
- **EAB** -- List, create, and delete External Account Binding credentials
- **Roles** -- CRUD operations on tenant roles
- **Users** -- CRUD operations on tenant users

Calls tenant, EAB, role, and user endpoints under `/api/v1/tenants/{id}/`.

## Connection Settings

`ConnectionSettings.svelte` -- Configure how the desktop app connects to the CA server (desktop mode only).

Options: transport protocol, server address, TLS certificates, auth token, timeout.

## Settings

`Settings.svelte` -- Application preferences (theme, display options).
