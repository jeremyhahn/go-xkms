# @go-xkms/sdk (TypeScript)

The TypeScript SDK for go-xkms: a framework-free **REST client** for the
entire xkmsd HTTP surface, the **WebAuthn wire bridge** (go-webauthn
base64url JSON ⇄ browser BufferSource), and — on the separate
`@go-xkms/sdk/ssh-console` subpath — a framework-agnostic **embedded SSH
console** client (xterm.js + the go-xkms console WebSocket protocol), reusable
by any web UI: xkey (Svelte), the xkms web UI, and go-trusted-platform's device
view (React).

## REST client

```ts
import { createClient, XkmsApiError } from '@go-xkms/sdk';

const xkms = createClient({
  baseURL: 'https://xkms.example.com:8443',
  token: () => sessionStore.accessToken, // resolved per request
});

const { backends } = await xkms.backends.list();
const key = await xkms.keys.generate({ key_id: 'web-1', key_type: 'ecdsa' });
const sig = await xkms.keys.sign('web-1', { backend: 'tpm2', data: b64 });

try {
  await xkms.tenants.get('missing');
} catch (err) {
  if (err instanceof XkmsApiError) console.log(err.status, err.code, err.correlationId);
}
```

Domain clients: `health`, `capabilities`, `auth`, `backends`, `keys`, `certs`,
`seal`, `frost`, `pin`, `piv`, `ca`, `cluster`, `tenants`, `passwords`,
`oidcCredentials`, `platform`, `tpmPolicies`, `credentials`,
`factors`, `users`, `ssh`. Every request/response type mirrors the Go
DTO json tags exactly; Go `[]byte` members are standard-base64 strings.

Named TPM policies (PCR-bank capture, approval lifecycle, auto-unseal, and
the keys/sealed objects bound to them) are `tpmPolicies` — see
`docs/tpm-policies/api.md`. A tenant's TPM mode and its vTPM are system-scope
operations on `tenants` (`getTPMMode`, `setTPMMode`, `vtpmStatus`,
`vtpmStart`, `vtpmStop`).

### OIDC credentials

`oidcCredentials` manages server-side OIDC credentials: named OAuth/OIDC
logins xkmsd holds on the tenant barrier and refreshes itself. A credential is
tenant-shared (`scope: 'tenant'`) or personal (`scope: 'user'`, visible only
to its owner). Consumers fetch a current access token by reference; the server
never returns the refresh token or client secret.

```ts
const ref = { scope: 'tenant', name: 'codex' } as const;

// Create pending, then log in with the device flow.
await xkms.oidcCredentials.create({ ...ref, config: { template: 'openai' } });
const started = await xkms.oidcCredentials.startDeviceLogin(ref);
show(started.device_login!.user_code, started.device_login!.verification_uri);
const done = await xkms.oidcCredentials.waitForDeviceLogin(started, { signal });
// done.status: 'active' once approved, or the status the server settled on.

// Or import tokens obtained elsewhere (e.g. a codex auth.json).
await xkms.oidcCredentials.importTokens(ref, { access_token, refresh_token, id_token });

const { access_token } = await xkms.oidcCredentials.getAccessToken(ref);
```

Methods: `list(tenantId?)`, `create`, `get`, `delete`, `importTokens`,
`refresh`, `getAccessToken`, `startDeviceLogin`, `pollDeviceLogin`, and
`waitForDeviceLogin`, which polls at the device login's `interval_seconds`
(re-read on every poll) until the credential leaves `pending`. It rejects with
`OIDCDeviceLoginError` (`reason: 'expired' | 'not_started'`) when no approval
can arrive, and with the signal's reason when aborted. Every reference takes
optional `tenant_id` and `owner`; empty means the caller's own. Provider
templates: `openai` (device login or import), `anthropic` (import only, never
refreshed), `google`, `microsoft`, `okta`, `auth0`, `keycloak`.

### Authentication

- `auth.loginCert()` — POST `/api/v1/auth/login/piv` with
  `credentials: 'include'` (mTLS certificate exchange) → token pair.
- `auth.refresh(rt)` / `auth.me()` / `auth.validate()` / `auth.logout(rt)`.
- WebAuthn ceremonies: `auth.webAuthnRegisterBegin/Finish` (an account's
  first passkey), `auth.webAuthnAddCredentialBegin` (a further passkey for the
  signed-in account; finish with `webAuthnRegisterFinish`),
  `auth.webAuthnBeginLogin/FinishLogin`, session correlation via the
  `X-Session-Id` header, with `parseCreationOptions`,
  `parseRequestOptions`, `encodeAttestationResponse`,
  `encodeAssertionResponse` bridging the browser credential API.

## SSH console

The console is a **client-side** terminal, and it lives on its own subpath so
that consumers which only use the REST client never pull xterm into their
bundle. xkmsd serves no console endpoint: it stores SSH keys and signs
authentication challenges with them, and never terminates an SSH session — a
console there would let an authenticated caller proxy an interactive shell to
any reachable host through the appliance. The bridge this client connects to
runs on the operator's own machine (xkey's loopback service).

```ts
import { SSHConsoleClient } from '@go-xkms/sdk/ssh-console';

const client = new SSHConsoleClient({ fontSize: 13 });
client.onError = (msg) => console.error(msg);
client.onClose = () => console.log('session ended');

// `url` comes from the host app (xkey's loopback service) and already carries
// a one-time token.
client.open(document.getElementById('terminal')!, { url });

// On container resize:
client.fit();

// On teardown:
client.dispose();
```

`@xterm/xterm` and `@xterm/addon-fit` are peer-style dependencies the consuming
app provides (the bundle keeps them external).

## WebSocket protocol

The client connects to a WebSocket served by the go-xkms console bridge
(`pkg/ssh/console.NewWSHandler`, re-exported as `sshclient.NewConsoleWSHandler`)
running in the client-side host app:

| Frame | Direction | Meaning |
|-------|-----------|---------|
| **binary** | client→server | keystrokes (stdin) |
| **binary** | server→client | terminal output (stdout) |
| **text** `{"type":"resize","rows":R,"cols":C}` | client→server | window resize |
| **text** `{"type":"error","message":"..."}` | server→client | error |
| **text** `{"type":"exit"}` | server→client | session ended |

The pure helpers `parseControl` / `encodeResize` implement the text-frame
encoding and are tested independently of the DOM.

## Build & test

```bash
npm install
npm run build      # tsup → dist (ESM + CJS + d.ts)
npm test           # vitest (REST clients, webauthn bridge, console protocol)
npm run typecheck  # tsc --noEmit
```
