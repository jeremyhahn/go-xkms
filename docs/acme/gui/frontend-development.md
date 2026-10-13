# Frontend Development

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed notes on developing the ACME SPAs in the `pkg/acme/web` npm workspace.

## Workspace structure

```
pkg/acme/web/
  package.json                    # npm workspace root
  packages/
    shared/                       # @trustedca/shared
      src/
        api/
          client.ts               # ApiClient + apiClient singleton (fetch-based)
          transport.ts            # Wails/browser detection, base URL resolution
          types.ts                # TypeScript types mirroring the Go API
          setup.ts, barrier.ts    # setup-wizard and seal/unseal calls
        components/               # shared Svelte components
        stores/
          theme.ts                # light/dark/system store
          notifications.ts        # toast store
          seal.svelte.ts          # seal state
          setup-wizard.svelte.ts  # setup wizard state
        utils/                    # formatters.ts, validators.ts
    admin/                        # @trustedca/admin
      src/
        views/                    # view components
        lib/api/admin-api.ts      # typed calls on top of apiClient
        App.svelte                # root component with sidebar navigation
      vite.config.ts              # dev server :5173, proxies /api to https://localhost:8443
    client/                       # @trustedca/client
      src/
        views/
        lib/api/client-api.ts
        App.svelte
      vite.config.ts              # dev server :5174, proxies /api to http://localhost:18443
```

Apps import shared code as `@trustedca/shared/...`. Each `vite.config.ts`
aliases that to `../shared/src`.

## Adding a new view

1. Create `pkg/acme/web/packages/{admin,client}/src/views/MyView.svelte`
2. Import it in `App.svelte`:
   ```svelte
   import MyView from './views/MyView.svelte';
   ```
3. Add a navigation item:
   ```typescript
   { label: 'My View', icon: 'dashboard', view: 'my-view' }
   ```
4. Add the branch in the template:
   ```svelte
   {:else if activeView === 'my-view'}
     <MyView />
   ```

Icon keys known to `Sidebar.svelte`: `dashboard`, `certificate`, `accounts`,
`tenants`, `settings`, `connection`, `register`, `request`, `renew`, `revoke`,
`device`, `autorenew`, `config`, `challenge`, `lock`, `orders`, `ca`, `audit`.
An unknown key renders the `dashboard` icon. The client app's Certificates
entry uses `certificates`, which is not a key, so it shows the dashboard icon.

## Adding an API endpoint

### Frontend

Add a typed wrapper to the app's `lib/api/*-api.ts`. The wrappers call the
shared `apiClient` with the full path:

```typescript
import { apiClient } from '@trustedca/shared/api/client';

const API_V1 = '/api/v1';
const cert = await apiClient.get<ManagedCertInfo>(`${API_V1}/certificates/${name}`);
```

Methods: `get<T>(path, params?)`, `post<T>(path, body?)`, `put<T>(path, body?)`, `patch<T>(path, body?)`, `delete<T>(path)`.

The client automatically:
- prefixes `getApiBaseUrl()` (empty, same-origin, unless `window.__API_BASE_URL__` is set)
- sets `Content-Type: application/json` and `Accept: application/json`
- adds `Authorization: Bearer ...` and `X-Tenant-ID` when set
- unwraps `data` from the JSON response
- throws `ApiClientError` (`status`, `code`, `message`) on failure
- clears auth state on 401

### Backend

Add the route to `pkg/acme/gui/{admin,client}/api/router.go`. For example:

```go
v1.HandleFunc("/my-endpoint", h.myHandler).Methods(http.MethodGet)
```

## Svelte store patterns

### Theme store

```typescript
import { theme, themeMode, setThemeMode, toggleTheme, initTheme } from '@trustedca/shared/stores/theme';

initTheme();             // once, in the root onMount
setThemeMode('system');  // 'light' | 'dark' | 'system'
toggleTheme();           // flips between light and dark
```

The mode persists in `localStorage` under `trustedca-theme`. `system`
follows `prefers-color-scheme`. See [theming.md](theming.md).

### Notification store

```typescript
import { notifySuccess, notifyError, notifyWarning, notifyInfo } from '@trustedca/shared/stores/notifications';

notifySuccess('Certificate issued');
notifyError('Request failed', 10000);  // optional duration in ms
```

Notifications auto-dismiss after 5 seconds by default, or 8 seconds for
`notifyError`. The `<Toast />` component renders them.

## TypeScript types

`pkg/acme/web/packages/shared/src/api/types.ts` is maintained by hand to
match the Go API's JSON. Key groups:

- **Envelope**: `ApiResponse<T>`, `ApiError`, `Pagination`
- **CA**: `CAStatus`, `CAStats`, `CertificateInfo`, `AccountInfo`, `OrderInfo`
- **Tenant**: `TenantInfo`, `TenantSettingsInfo`, `EABInfo`, `CreateTenantRequest`
- **Client**: `RegisterRequest`, `CertRequest`, `AccountConfig`, `CertificateSpec`, `ManagedCertInfo`
- **Device**: `EnrollRequest`, `AttestRequest`, `EABDeviceInfoDTO`
