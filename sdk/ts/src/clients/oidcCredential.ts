// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

import type { HttpCore, QueryParams } from '../http.js';
import type {
  OIDCAccessToken,
  OIDCCredential,
  OIDCCredentialCreateRequest,
  OIDCCredentialListResponse,
  OIDCCredentialRef,
  OIDCCredentialTokens,
} from '../types/oidcCredential.js';

const BASE = '/api/v1/oidc/credentials';

/** The poll interval used when a device login does not name one (RFC 8628 §3.2). */
const DEFAULT_DEVICE_INTERVAL_SECONDS = 5;

/** Why waitForDeviceLogin gave up on a device login that is still pending. */
export type OIDCDeviceLoginFailure = 'expired' | 'not_started';

/**
 * OIDCDeviceLoginError is thrown by waitForDeviceLogin when a credential is
 * still pending but no approval can arrive: its device login passed its
 * expiry ("expired"), or it has no device login in progress
 * ("not_started").
 */
export class OIDCDeviceLoginError extends Error {
  readonly reason: OIDCDeviceLoginFailure;

  constructor(reason: OIDCDeviceLoginFailure, name: string) {
    super(
      reason === 'expired'
        ? `oidc credential "${name}": device login expired before it was approved`
        : `oidc credential "${name}": no device login in progress`,
    );
    this.name = 'OIDCDeviceLoginError';
    this.reason = reason;
  }
}

/** Options of OidcCredentialClient.waitForDeviceLogin. */
export interface WaitForDeviceLoginOptions {
  /** Aborts the wait; the promise rejects with the signal's reason. */
  signal?: AbortSignal;
  /** Called with each poll's credential while it is still pending. */
  onPending?: (credential: OIDCCredential) => void;
}

function credentialPath(ref: OIDCCredentialRef, action?: string): string {
  const path = `${BASE}/${encodeURIComponent(ref.scope)}/${encodeURIComponent(ref.name)}`;
  return action ? `${path}/${action}` : path;
}

/** refQuery is the query naming a credential's tenant and owner (empty: the caller's). */
function refQuery(ref: OIDCCredentialRef): QueryParams {
  return { tenant_id: ref.tenant_id, owner: ref.owner };
}

/** sleep resolves after ms, or rejects with the signal's reason once it aborts. */
function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Server-side OIDC credentials: named OAuth/OIDC logins xkmsd holds on the
 * tenant barrier and refreshes itself, tenant-shared (scope "tenant") or
 * personal (scope "user", visible only to its owner). Consumers get a current
 * access token by reference; the server never hands out the refresh token.
 * Mirrors pkg/api/rest/handlers_oidc_credential.go.
 */
export class OidcCredentialClient {
  constructor(private readonly http: HttpCore) {}

  /** GET /api/v1/oidc/credentials?tenant_id= — the shared credentials and the caller's personal ones. */
  list(tenantId?: string): Promise<OIDCCredentialListResponse> {
    return this.http.request('GET', BASE, { query: { tenant_id: tenantId } });
  }

  /**
   * POST /api/v1/oidc/credentials (201). With tokens the credential is
   * active at once; without, it is pending a device login or an import.
   */
  create(req: OIDCCredentialCreateRequest): Promise<OIDCCredential> {
    return this.http.request('POST', BASE, { body: req });
  }

  /** GET /api/v1/oidc/credentials/{scope}/{name}?tenant_id=&owner= — the public view (no tokens). */
  get(ref: OIDCCredentialRef): Promise<OIDCCredential> {
    return this.http.request('GET', credentialPath(ref), { query: refQuery(ref) });
  }

  /** DELETE /api/v1/oidc/credentials/{scope}/{name}?tenant_id=&owner= (204). */
  async delete(ref: OIDCCredentialRef): Promise<void> {
    await this.http.request<void>('DELETE', credentialPath(ref), {
      query: refQuery(ref),
      parse: 'void',
    });
  }

  /**
   * POST /api/v1/oidc/credentials/{scope}/{name}/import — replaces the
   * credential's login with tokens obtained elsewhere and makes it active.
   */
  importTokens(ref: OIDCCredentialRef, tokens: OIDCCredentialTokens): Promise<OIDCCredential> {
    return this.http.request('POST', credentialPath(ref, 'import'), {
      query: refQuery(ref),
      body: { tokens },
    });
  }

  /** POST /api/v1/oidc/credentials/{scope}/{name}/refresh — refreshes now. */
  refresh(ref: OIDCCredentialRef): Promise<OIDCCredential> {
    return this.http.request('POST', credentialPath(ref, 'refresh'), { query: refQuery(ref) });
  }

  /**
   * POST /api/v1/oidc/credentials/{scope}/{name}/token — a current access
   * token, refreshed first when inside its refresh margin. The answer is a
   * bearer secret: hold it no longer than its use.
   */
  getAccessToken(ref: OIDCCredentialRef): Promise<OIDCAccessToken> {
    return this.http.request('POST', credentialPath(ref, 'token'), { query: refQuery(ref) });
  }

  /**
   * POST /api/v1/oidc/credentials/{scope}/{name}/device — starts a device
   * login; the returned credential's device_login carries the user code and
   * verification URI.
   */
  startDeviceLogin(ref: OIDCCredentialRef): Promise<OIDCCredential> {
    return this.http.request('POST', credentialPath(ref, 'device'), { query: refQuery(ref) });
  }

  /**
   * POST /api/v1/oidc/credentials/{scope}/{name}/device/poll — polls the
   * device login once; the credential stays pending until the user approves.
   */
  pollDeviceLogin(ref: OIDCCredentialRef): Promise<OIDCCredential> {
    return this.http.request('POST', credentialPath(ref, 'device/poll'), { query: refQuery(ref) });
  }

  /**
   * waitForDeviceLogin polls a device login until the credential leaves
   * "pending" and resolves with it — "active" once the user approved, or
   * whatever status the server settled on. It waits the device login's
   * interval_seconds before every poll (re-read from each poll, so a
   * server-side slow-down is honoured), and never polls in a busy loop.
   *
   * Pass the credential startDeviceLogin returned so the first wait uses its
   * interval. Rejects with OIDCDeviceLoginError when the credential is still
   * pending past its device login's expiry or has no device login, with the
   * signal's reason when aborted, and with the poll's error when one fails.
   */
  async waitForDeviceLogin(
    credential: OIDCCredentialRef | OIDCCredential,
    opts: WaitForDeviceLoginOptions = {},
  ): Promise<OIDCCredential> {
    let current: OIDCCredential | undefined = 'status' in credential ? credential : undefined;
    for (;;) {
      if (current !== undefined && current.status !== 'pending') {
        return current;
      }
      const login = current?.device_login;
      if (current !== undefined && login === undefined) {
        throw new OIDCDeviceLoginError('not_started', credential.name);
      }
      if (login !== undefined && Date.now() >= Date.parse(login.expires_at)) {
        throw new OIDCDeviceLoginError('expired', credential.name);
      }
      const interval = login?.interval_seconds || DEFAULT_DEVICE_INTERVAL_SECONDS;
      await sleep(interval * 1000, opts.signal);
      current = await this.pollDeviceLogin(credential);
      if (current.status === 'pending') {
        opts.onPending?.(current);
      }
    }
  }
}
