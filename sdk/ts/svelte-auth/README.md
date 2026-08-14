# @go-xkms/svelte-auth

Reusable Svelte 5 passwordless-login surface for go-xkms deployments:

- **Token store** (`stores/auth.svelte.ts`) — localStorage-backed access/refresh
  pair, 3-state status rune, monotonic session-generation guard, pre-emptive
  refresh with a 60s skew window, single-flight renewal, rotated-refresh-token
  persistence, cross-tab `storage` sync.
- **401-recovery fetch layer** (`authFetch.ts`) — one interceptor over
  `window.fetch` that renews once and replays on a 401 from a configured API
  path; the refresh path is never intercepted.
- **CredentialProvider seam** (`provider.ts`) — the panels never touch
  `navigator.credentials` directly. The browser gets
  `BrowserCredentialProvider`; a desktop shell (Wails/Electron) injects its own
  provider backed by local hardware (FIDO2 CTAP2, PIV).
- **Components** — `LoginPanel.svelte` (passkey + certificate chooser with
  anti-enumeration failure copy) and `RegisterPanel.svelte` (attestation
  ceremony).

This is a **source-only** package (`exports` point at `src/index.ts`); the
consuming app's bundler compiles the Svelte sources.

## Wiring

```ts
import { createClient } from '@go-xkms/sdk';
import { initAuth, getValidAccessToken } from '@go-xkms/svelte-auth';

const client = createClient({
  baseURL: window.location.origin,
  // The store IS the token factory: expired tokens are renewed pre-emptively.
  token: getValidAccessToken,
});

const { authStore, provider } = initAuth({
  client,
  storagePrefix: 'xkms',            // -> xkms_token / xkms_refresh_token
  apiPrefixes: ['/api/', '/xkms/'], // 401-recovery scope
  refreshPath: '/api/v1/auth/refresh',
});
```

```svelte
<script lang="ts">
  import { LoginPanel } from '@go-xkms/svelte-auth';
</script>

<LoginPanel
  {provider}
  {client}
  title="xKMS"
  defaultTenant="system"
  onSuccess={(tokens, me) => routeDashboard()}
/>
```

`authStore.status` is the route-guard signal (`pending` /
`authenticated` / `unauthenticated`). `onSuccess` fires only after the
tokens are persisted and the in-tab status has flipped, so a guard watching
`authStore.status` will not bounce the freshly-signed-in user.

## Tailwind / daisyUI

The components emit daisyUI class names (`btn`, `card`, `input`, `alert`) and
no palette of their own. Because this is a source-only package, the consuming
app's Tailwind build must scan these sources or the classes are purged.
Add an `@source` directive to the app stylesheet (same pattern as
`pkg/acme/web/packages/admin/src/app.css`):

```css
@import "tailwindcss";
@source "../node_modules/@go-xkms/svelte-auth/src/**/*.svelte";
@plugin "daisyui";
```

Adjust the relative path to wherever the package resolves from your app.

## Swapping in from go-quicbaas

This package is the extracted, generalized form of the quicbaas orchestrator
frontend's `stores/auth.svelte.ts` + `stores/authFetch.ts` +
`LoginView`/`RegisterView`. To consume it there:

1. Replace `stores/auth.svelte.ts` imports with `@go-xkms/svelte-auth`
   (`setAuthenticated`, `endSession` — formerly `setUnauthenticated` —
   `getValidAccessToken`, `validateSession`, `authStore`).
2. Call `initAuth({ client, storagePrefix: 'quicbaas' })` at bootstrap to keep
   the existing `quicbaas_token` / `quicbaas_refresh_token` slots; drop the
   local `installAuthFetch`.
3. Wrap the quicbaas SDK's auth client in the `AuthApi` shape (its
   `webAuthnBeginLogin(tenant, email)` becomes a small adapter reading
   `tenant_id`/`email` from the request object) and render `LoginPanel` with
   `defaultTenant="system"` in place of `LoginView`.

## Desktop CredentialProvider seam

A desktop shell keeps the panels and swaps the ceremony transport:

```ts
import { initAuth, type CredentialProvider } from '@go-xkms/svelte-auth';

const desktopProvider: CredentialProvider = {
  methods: async () => ['passkey', 'certificate'],
  getAssertion: (options) => bridge.fido2Assert(options),      // CTAP2 via host
  createCredential: (options) => bridge.fido2Make(options),    // CTAP2 via host
  loginCertificate: () => bridge.pivLogin(),                   // PIV via host
};

initAuth({ client, provider: desktopProvider });
```

`isWailsRuntime()` from `@go-xkms/sdk` is the usual switch for choosing the
desktop provider over the browser default.

## Development

```sh
npm install
npm test          # vitest (jsdom + @testing-library/svelte)
npm run check     # svelte-check
```
