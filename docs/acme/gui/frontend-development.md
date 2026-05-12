# Frontend Development

## Workspace Structure

```
web/
  package.json                    # npm workspace root
  packages/
    shared/                       # @trustedca/shared
      src/
        api/
          client.ts               # ApiClient singleton (fetch-based)
          transport.ts            # Wails/browser detection, base URL resolution
          types.ts                # TypeScript types matching Go structs
        components/               # Shared Svelte components
        stores/
          theme.ts                # Dark/light mode store
          notifications.ts        # Toast notification store
    admin/                        # Admin SPA
      src/
        views/                    # View components
        App.svelte                # Root component with sidebar navigation
      vite.config.ts
    client/                       # Client SPA
      src/
        views/                    # View components
        App.svelte                # Root component with sidebar navigation
      vite.config.ts
```

Packages reference each other via npm workspace aliases (e.g., `@trustedca/shared`).

## Adding a New View

1. Create `web/packages/{app}/src/views/MyView.svelte`
2. Import it in `App.svelte`:
   ```svelte
   import MyView from './views/MyView.svelte';
   ```
3. Add a navigation item:
   ```typescript
   { label: 'My View', icon: 'dashboard', view: 'my-view' }
   ```
4. Add the route in the template:
   ```svelte
   {:else if activeView === 'my-view'}
     <MyView />
   ```

Available icon keys: `dashboard`, `certificate`, `accounts`, `tenants`, `settings`, `connection`, `register`, `request`, `renew`, `revoke`, `device`, `autorenew`, `config`, `challenge`.

## Adding an API Endpoint

### Frontend

Use the singleton `apiClient` from `@trustedca/shared`:

```typescript
import { apiClient } from '@trustedca/shared/api/client';
import type { CertificateInfo } from '@trustedca/shared/api/types';

const cert = await apiClient.get<CertificateInfo>('/certificates/ABC123');
```

Methods: `get<T>(path, params?)`, `post<T>(path, body?)`, `put<T>(path, body?)`, `patch<T>(path, body?)`, `delete<T>(path)`.

The client automatically:
- Prepends the base URL (absolute in Wails, relative in browser)
- Sets `Content-Type: application/json` and `Accept: application/json`
- Injects `Authorization` and `X-Tenant-ID` headers when set
- Unwraps the `{ data: T }` response envelope
- Throws `ApiClientError` with `status`, `code`, and `message` on failure
- Clears auth state on 401

### Backend

Add the route in the appropriate `router.go`:

```go
v1.HandleFunc("/my-endpoint", h.myHandler).Methods("GET")
```

## Svelte Store Patterns

### Theme Store

```typescript
import { theme, toggleTheme, initTheme } from '@trustedca/shared/stores/theme';

// Call once in root component onMount
initTheme();

// Toggle: $theme flips between 'light' and 'dark'
toggleTheme();
```

Persists to `localStorage` under `trustedca-theme`. Falls back to `prefers-color-scheme` media query.

### Notification Store

```typescript
import { notifySuccess, notifyError, notifyWarning, notifyInfo } from '@trustedca/shared/stores/notifications';

notifySuccess('Certificate issued');
notifyError('Request failed', 8000);  // 8s duration
```

Notifications auto-dismiss after 5 seconds (8 seconds for errors). The `<Toast />` component renders them.

## TypeScript Type Sync

Types in `web/packages/shared/src/api/types.ts` mirror Go structs from `pkg/admin/types.go`. When Go types change, update the TypeScript types manually. Key type groups:

- **Response envelope**: `ApiResponse<T>`, `ApiError`, `Pagination`
- **CA types**: `CAStatus`, `CAStats`, `CertificateInfo`, `AccountInfo`, `OrderInfo`
- **Tenant types**: `TenantInfo`, `TenantSettingsInfo`, `EABInfo`, `CreateTenantRequest`
- **Client types**: `RegisterRequest`, `CertRequest`, `ClientConfig`, `RenewalConfig`
- **Device types**: `EnrollRequest`, `AttestRequest`, `EABDeviceInfoDTO`
