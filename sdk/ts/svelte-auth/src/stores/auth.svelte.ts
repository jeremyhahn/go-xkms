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
 * Authentication state store — the single source of truth for whether the
 * current tab is signed in.
 *
 * Generalized from the go-quicbaas orchestrator frontend store: the
 * localStorage keys come from the configured storagePrefix and the renewal
 * round-trip goes through the INJECTED AuthClient (config.client.auth.refresh)
 * instead of a hardcoded fetch, so the same store serves any deployment or
 * downstream product.
 *
 * Reactivity shape: module-scope `let x = $state(...)` + getter object.
 * A directly-exported $state proxy does not propagate template updates across
 * module boundaries in Svelte 5 — consumers must read `authStore.status`.
 */

import {
  AuthNotConfiguredError,
  resolveAuthConfig,
  type AuthPackageConfig,
  type ResolvedAuthConfig,
} from '../config.ts';

export type AuthStatus = 'pending' | 'authenticated' | 'unauthenticated';

let config: ResolvedAuthConfig | null = null;

let status = $state<AuthStatus>('pending');

/**
 * Monotonic session generation. Every deliberate session transition (login,
 * logout, cross-tab takeover) bumps it, so an ASYNC session check can tell
 * whether the session it was validating is still the current one.
 *
 * Without this a validateSession() that was in flight when the user signed out
 * resolves afterwards and writes 'authenticated' back — resurrecting a session
 * the user just ended. The window is small but real, and it is a security
 * regression, not a cosmetic one.
 */
let generation = 0;

// Single-flight guard so concurrent requests trigger at most one refresh call.
let _refreshInFlight: Promise<string> | null = null;

// Skew window: refresh when fewer than this many seconds remain so an
// in-flight request never races the access-token expiry.
const REFRESH_SKEW_SECONDS = 60;

/** Reactive facade — read `authStore.status` from templates and effects. */
export const authStore = {
  get status(): AuthStatus {
    return status;
  },
};

/**
 * configureAuthStore injects the deployment config (client, storage prefix).
 * initAuth() calls this; tests may call it directly. Reconfiguring resets the
 * single-flight guard but leaves status/storage untouched.
 */
export function configureAuthStore(next: AuthPackageConfig): void {
  config = resolveAuthConfig(next);
  _refreshInFlight = null;
}

/** isAuthStoreConfigured reports whether configureAuthStore has run. */
export function isAuthStoreConfigured(): boolean {
  return config !== null;
}

/** authConfig returns the resolved config, or throws AuthNotConfiguredError. */
export function authConfig(): ResolvedAuthConfig {
  if (config === null) throw new AuthNotConfiguredError();
  return config;
}

/** tokenKey is the localStorage key holding the access token. */
export function tokenKey(): string {
  return `${authConfig().storagePrefix}_token`;
}

/** refreshTokenKey is the localStorage key holding the refresh token. */
export function refreshTokenKey(): string {
  return `${authConfig().storagePrefix}_refresh_token`;
}

/** Read the persisted access token, or '' when none is stored. */
export function readAuthToken(): string {
  if (typeof window === 'undefined') return '';
  return window.localStorage.getItem(tokenKey()) ?? '';
}

/** Read the persisted refresh token, or '' when none is stored. */
export function readRefreshToken(): string {
  if (typeof window === 'undefined') return '';
  return window.localStorage.getItem(refreshTokenKey()) ?? '';
}

/** Tokens returned by a successful login/registration finish. */
export interface AuthTokens {
  access_token: string;
  refresh_token?: string;
}

/**
 * Persist tokens and flip the in-tab status to 'authenticated'. Called by
 * every login-completion path (passkey, certificate, registration) the
 * instant the server confirms the session, so a host app's route guard sees
 * the flip in THIS tab instead of bouncing the freshly-signed-in user back
 * to the login chooser.
 */
export function setAuthenticated(tokens: AuthTokens): void {
  if (typeof window !== 'undefined') {
    window.localStorage.setItem(tokenKey(), tokens.access_token);
    if (tokens.refresh_token) {
      window.localStorage.setItem(refreshTokenKey(), tokens.refresh_token);
    }
  }
  generation++;
  status = 'authenticated';
}

/** Clear persisted tokens and flip the in-tab status to 'unauthenticated'. */
export function endSession(): void {
  if (typeof window !== 'undefined') {
    window.localStorage.removeItem(tokenKey());
    window.localStorage.removeItem(refreshTokenKey());
  }
  generation++;
  status = 'unauthenticated';
}

/** Force the status to a known value without touching token storage. */
export function setAuthStatus(next: AuthStatus): void {
  status = next;
}

/**
 * Seconds until the given JWT expires, or null when the token is not a
 * decodable JWT with a numeric exp claim. Pure string/Base64 work — no
 * signature verification (the server is the authority); this only decides
 * when to pre-emptively refresh. Returning null (rather than 0) lets the
 * caller leave an undecodable/opaque token untouched instead of refreshing
 * it needlessly.
 */
function secondsUntilExpiry(jwt: string): number | null {
  const parts = jwt.split('.');
  const claimsSegment = parts.length === 3 ? parts[1] : undefined;
  if (claimsSegment === undefined) return null;
  try {
    const json = atob(claimsSegment.replace(/-/g, '+').replace(/_/g, '/'));
    const claims = JSON.parse(json) as { exp?: number };
    if (typeof claims.exp !== 'number') return null;
    return claims.exp - Math.floor(Date.now() / 1000);
  } catch {
    return null;
  }
}

/**
 * A definitive rejection is an error the SERVER answered (it carries a
 * numeric HTTP status — e.g. the SDK's XkmsApiError). Anything else (TypeError,
 * XkmsNetworkError, aborted request) is treated as transient: the session is
 * kept and the next request retries.
 */
function isDefinitiveRejection(err: unknown): boolean {
  return typeof (err as { status?: unknown }).status === 'number';
}

/**
 * Exchange the stored refresh token for a fresh access token via the injected
 * AuthClient, persist it, and return it. Returns '' (and fails the session
 * closed) when no refresh token is stored or the server rejects it.
 * Concurrent callers share one in-flight request.
 */
export async function refreshAccessToken(): Promise<string> {
  if (_refreshInFlight !== null) return _refreshInFlight;
  if (typeof window === 'undefined') return '';
  const cfg = authConfig();

  const refreshToken = readRefreshToken();
  if (!refreshToken) {
    endSession();
    return '';
  }

  _refreshInFlight = (async (): Promise<string> => {
    try {
      const pair = await cfg.client.auth.refresh(refreshToken);
      const next = pair.access_token ?? '';
      if (!next) {
        endSession();
        return '';
      }
      // The server ROTATES the refresh credential: the one we just presented
      // is revoked. Persisting the replacement is what makes the SECOND
      // renewal work — storing only the access token would strand the session
      // at the next expiry with a dead refresh token.
      window.localStorage.setItem(tokenKey(), next);
      if (pair.refresh_token) {
        window.localStorage.setItem(refreshTokenKey(), pair.refresh_token);
      }
      status = 'authenticated';
      return next;
    } catch (err) {
      if (isDefinitiveRejection(err)) {
        // A rejected refresh token means the session is over — fail closed so
        // the host app's route guard bounces the user to the login chooser.
        endSession();
        return '';
      }
      // Network failure: do NOT clear the session (transient); the caller
      // falls back to the existing token and the next request retries.
      return readAuthToken();
    } finally {
      _refreshInFlight = null;
    }
  })();

  return _refreshInFlight;
}

/**
 * Resolve the access token to attach to an outgoing request, refreshing it
 * pre-emptively when it is missing/expired or within the skew window. Wire
 * this as the SDK client's TokenProvider so a long-lived tab whose
 * short-lived access token expires mid-session transparently obtains a new
 * one instead of silently 401-ing.
 */
export async function getValidAccessToken(): Promise<string> {
  const token = readAuthToken();
  if (!token) return '';
  const remaining = secondsUntilExpiry(token);
  // Undecodable/opaque token, or comfortably valid: use it as-is.
  if (remaining === null || remaining > REFRESH_SKEW_SECONDS) return token;
  // Known to be expired or about to expire, and only worth a round-trip if we
  // actually hold a refresh token. refreshAccessToken returns the new token on
  // success, the still-valid existing token on a transient network failure, or
  // '' on a definitive rejection (after flipping the session to
  // unauthenticated) — return its result verbatim so a dead token is never
  // attached.
  if (!readRefreshToken()) return token;
  return refreshAccessToken();
}

/**
 * Validate the persisted token against the server and set the status
 * accordingly. With no token we are unauthenticated; a server-rejected or
 * unreachable token also resolves to 'unauthenticated' so protected UI is
 * never shown without a confirmed session.
 */
export async function validateSession(): Promise<void> {
  const cfg = authConfig();
  // Snapshot the session this check belongs to; a login or logout that happens
  // while we await invalidates our verdict.
  const checking = generation;
  const commit = (next: AuthStatus): void => {
    if (generation === checking) status = next;
  };

  // Resolve through the refresh-aware accessor: on a page load after the
  // access token expired, validating it verbatim would report
  // 'unauthenticated' for a session that is in fact still renewable.
  const token = await getValidAccessToken();
  if (!token) {
    commit('unauthenticated');
    return;
  }
  try {
    await cfg.client.auth.validate();
    commit('authenticated');
  } catch {
    commit('unauthenticated');
  }
}

/**
 * handleStorageEvent applies a cross-tab `storage` event to this tab's
 * status: another tab signing in (access token written) or out (token
 * removed / storage cleared) is a deliberate session transition, so the
 * generation is bumped to invalidate any in-flight validation. Storage is
 * NOT touched — the originating tab already wrote it.
 */
export function handleStorageEvent(event: StorageEvent): void {
  if (config === null) return;
  if (event.key === null) {
    // storage.clear() in another tab — the session is gone.
    generation++;
    status = 'unauthenticated';
    return;
  }
  if (event.key !== tokenKey()) return;
  generation++;
  status = event.newValue ? 'authenticated' : 'unauthenticated';
}

let _crossTabInstalled = false;

/**
 * installCrossTabSync subscribes to the window `storage` event so a sign-in
 * or sign-out in one tab is reflected in every other tab. Idempotent; returns
 * an uninstaller (used by tests).
 */
export function installCrossTabSync(): () => void {
  if (typeof window === 'undefined' || _crossTabInstalled) return () => {};
  window.addEventListener('storage', handleStorageEvent);
  _crossTabInstalled = true;
  return () => {
    window.removeEventListener('storage', handleStorageEvent);
    _crossTabInstalled = false;
  };
}
