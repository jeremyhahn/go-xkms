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

/**
 * Authenticated-fetch recovery layer.
 *
 * Access tokens are short-lived by design. The token factory
 * (getValidAccessToken) refreshes PRE-EMPTIVELY, which handles the ordinary
 * case, but it cannot cover every one:
 *
 *   • a request that was already in flight when the token lapsed,
 *   • clock skew between browser and server,
 *   • a token the server revoked early (admin action, key rotation).
 *
 * In all of those the server answers 401. This installs ONE interceptor over
 * window.fetch that, on a 401 from a same-origin API request, renews the
 * session once and replays the request with the fresh bearer. It is
 * deliberately a single global choke point rather than per-call retry logic:
 * there is exactly one place to reason about, and it covers every SDK client
 * class plus any direct fetch a view makes.
 *
 * Guarantees:
 *   • single-flight — concurrent 401s share one renewal (refreshAccessToken
 *     owns that lock).
 *   • replay at most once — a retried request that 401s again is returned
 *     as-is. The session is over; the host route guard takes over.
 *   • the refresh path itself is never intercepted (no recursion).
 *   • unauthenticated requests (no Authorization header and no stored
 *     session) pass straight through: a 401 from a public endpoint is a real
 *     answer, not a stale-token symptom.
 *
 * Generalized from go-quicbaas: the API path prefixes and the refresh path
 * come from the package config (or per-install overrides) instead of being
 * hardcoded constants.
 */

import {
  DEFAULT_API_PREFIXES,
  DEFAULT_REFRESH_PATH,
} from './config.ts';
import {
  authConfig,
  isAuthStoreConfigured,
  readAuthToken,
  readRefreshToken,
  refreshAccessToken,
} from './stores/auth.svelte.ts';

/** Per-install overrides; anything omitted falls back to the store config. */
export interface AuthFetchOptions {
  /** Same-origin path prefixes treated as API calls. */
  apiPrefixes?: string[];
  /** Renewal endpoint path, never intercepted. */
  refreshPath?: string;
}

let _installed = false;
let _originalFetch: typeof fetch | null = null;
let _overrides: AuthFetchOptions = {};

function effectiveApiPrefixes(): string[] {
  if (_overrides.apiPrefixes !== undefined) return _overrides.apiPrefixes;
  if (isAuthStoreConfigured()) return authConfig().apiPrefixes;
  return [...DEFAULT_API_PREFIXES];
}

function effectiveRefreshPath(): string {
  if (_overrides.refreshPath !== undefined) return _overrides.refreshPath;
  if (isAuthStoreConfigured()) return authConfig().refreshPath;
  return DEFAULT_REFRESH_PATH;
}

/** Resolve a fetch input to a URL string without throwing on odd inputs. */
function requestURL(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

/** Read the Authorization header from either the init or a Request input. */
function authorizationOf(input: RequestInfo | URL, init?: RequestInit): string {
  const fromInit = new Headers(init?.headers ?? {}).get('Authorization');
  if (fromInit) return fromInit;
  if (typeof input !== 'string' && !(input instanceof URL)) {
    return input.headers.get('Authorization') ?? '';
  }
  return '';
}

/**
 * Decide whether a 401 for this request is worth retrying after a renewal.
 * Only same-origin API calls made on behalf of a signed-in user qualify.
 */
function isRenewable(input: RequestInfo | URL, init?: RequestInit): boolean {
  // Nothing to renew with until the package is wired up.
  if (!isAuthStoreConfigured()) return false;

  const url = requestURL(input);
  if (url.includes(effectiveRefreshPath())) return false;

  let path: string;
  try {
    path = new URL(url, window.location.origin).pathname;
  } catch {
    return false;
  }
  if (!effectiveApiPrefixes().some((prefix) => path.startsWith(prefix))) {
    return false;
  }

  // Something must identify the caller as a signed-in user: either the
  // request already carried a bearer, or we hold one to attach on replay.
  if (!authorizationOf(input, init) && !readAuthToken()) return false;

  // Without a refresh credential there is nothing to renew with.
  return readRefreshToken() !== '';
}

/** Replay a request with a freshly minted bearer. */
function withBearer(init: RequestInit | undefined, token: string): RequestInit {
  const headers = new Headers(init?.headers ?? {});
  headers.set('Authorization', `Bearer ${token}`);
  return { ...init, headers };
}

/**
 * installAuthFetch replaces window.fetch with the recovery wrapper. Calling
 * it more than once is a no-op, so app bootstrap and tests can both invoke
 * it.
 */
export function installAuthFetch(options?: AuthFetchOptions): void {
  if (_installed || typeof window === 'undefined') return;
  _overrides = options ?? {};
  _originalFetch = window.fetch.bind(window);
  const original = _originalFetch;

  window.fetch = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const resp = await original(input, init);
    if (resp.status !== 401 || !isRenewable(input, init)) return resp;

    // Single-flight: concurrent 401s all await the same renewal.
    const token = await refreshAccessToken();
    if (!token) return resp;

    // A Request input carries its own (now stale) Authorization header, so
    // rebuild it from the URL to guarantee the replay uses the new bearer.
    return original(requestURL(input), withBearer(init, token));
  };

  _installed = true;
}

/**
 * uninstallAuthFetch restores the original window.fetch. Intended for tests
 * so one case's interceptor cannot leak into the next.
 */
export function uninstallAuthFetch(): void {
  if (!_installed || _originalFetch === null) return;
  window.fetch = _originalFetch;
  _originalFetch = null;
  _overrides = {};
  _installed = false;
}
