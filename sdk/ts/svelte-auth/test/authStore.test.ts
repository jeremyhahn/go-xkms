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
 * Auth store tests: storage-key configuration, status transitions,
 * pre-emptive refresh through the INJECTED client, single-flight, the
 * session-generation guard, and cross-tab storage sync.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  authStore,
  configureAuthStore,
  endSession,
  getValidAccessToken,
  handleStorageEvent,
  installCrossTabSync,
  readAuthToken,
  readRefreshToken,
  refreshAccessToken,
  refreshTokenKey,
  setAuthStatus,
  setAuthenticated,
  tokenKey,
  validateSession,
} from '../src/stores/auth.svelte.ts';
import { AuthNotConfiguredError } from '../src/config.ts';
import { FakeApiError, jwtExpiringIn, makeFakeClient, tokenPair } from './helpers.ts';

describe('auth store', () => {
  let fake = makeFakeClient();

  beforeEach(() => {
    window.localStorage.clear();
    fake = makeFakeClient();
    configureAuthStore({ client: fake.client });
    setAuthStatus('pending');
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Configuration / storage keys
  // -------------------------------------------------------------------------

  it('derives storage keys from the default prefix', () => {
    expect(tokenKey()).toBe('xkms_token');
    expect(refreshTokenKey()).toBe('xkms_refresh_token');
  });

  it('derives storage keys from a custom prefix', () => {
    configureAuthStore({ client: fake.client, storagePrefix: 'acme' });
    setAuthenticated({ access_token: 'a1', refresh_token: 'r1' });

    expect(window.localStorage.getItem('acme_token')).toBe('a1');
    expect(window.localStorage.getItem('acme_refresh_token')).toBe('r1');
  });

  // -------------------------------------------------------------------------
  // setAuthenticated / endSession / status transitions
  // -------------------------------------------------------------------------

  it('persists both tokens and flips status on setAuthenticated', () => {
    setAuthenticated({ access_token: 'access-1', refresh_token: 'refresh-1' });

    expect(window.localStorage.getItem(tokenKey())).toBe('access-1');
    expect(window.localStorage.getItem(refreshTokenKey())).toBe('refresh-1');
    expect(authStore.status).toBe('authenticated');
  });

  it('clears tokens and flips status on endSession', () => {
    setAuthenticated({ access_token: 'access-1', refresh_token: 'refresh-1' });
    endSession();

    expect(window.localStorage.getItem(tokenKey())).toBeNull();
    expect(window.localStorage.getItem(refreshTokenKey())).toBeNull();
    expect(authStore.status).toBe('unauthenticated');
  });

  // -------------------------------------------------------------------------
  // Pre-emptive refresh (token factory)
  // -------------------------------------------------------------------------

  it('uses a comfortably-valid access token without a round trip', async () => {
    const live = jwtExpiringIn(600);
    setAuthenticated({ access_token: live, refresh_token: 'refresh-1' });

    await expect(getValidAccessToken()).resolves.toBe(live);
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('renews inside the 60s skew window and persists the ROTATED refresh token', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(30), refresh_token: 'refresh-1' });
    const renewed = jwtExpiringIn(900);
    fake.mocks.refresh.mockResolvedValue(tokenPair(renewed, 'refresh-2'));

    await expect(getValidAccessToken()).resolves.toBe(renewed);
    expect(fake.mocks.refresh).toHaveBeenCalledTimes(1);
    expect(fake.mocks.refresh).toHaveBeenCalledWith('refresh-1');
    expect(window.localStorage.getItem(tokenKey())).toBe(renewed);
    // The rotated credential MUST be stored: the server revoked refresh-1, so
    // keeping it would strand the session at the next renewal.
    expect(window.localStorage.getItem(refreshTokenKey())).toBe('refresh-2');
  });

  it('renews an access token that has crossed the expiry boundary', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(-30), refresh_token: 'refresh-1' });
    const renewed = jwtExpiringIn(900);
    fake.mocks.refresh.mockResolvedValue(tokenPair(renewed, 'refresh-2'));

    await expect(getValidAccessToken()).resolves.toBe(renewed);
    expect(authStore.status).toBe('authenticated');
  });

  it('coalesces concurrent renewals into a single refresh call', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(-30), refresh_token: 'refresh-1' });
    const renewed = jwtExpiringIn(900);
    let release: (pair: ReturnType<typeof tokenPair>) => void = () => {};
    fake.mocks.refresh.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );

    const inflight = Promise.all([
      getValidAccessToken(),
      getValidAccessToken(),
      getValidAccessToken(),
    ]);
    release(tokenPair(renewed, 'refresh-2'));

    await expect(inflight).resolves.toEqual([renewed, renewed, renewed]);
    expect(fake.mocks.refresh).toHaveBeenCalledTimes(1);
  });

  it('ends the session when the server rejects the refresh credential', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(-30), refresh_token: 'refresh-1' });
    fake.mocks.refresh.mockRejectedValue(
      new FakeApiError(401, 'invalid or expired refresh token'),
    );

    await expect(getValidAccessToken()).resolves.toBe('');
    expect(authStore.status).toBe('unauthenticated');
    expect(window.localStorage.getItem(tokenKey())).toBeNull();
    expect(window.localStorage.getItem(refreshTokenKey())).toBeNull();
  });

  it('keeps the session on a transient network failure', async () => {
    const stale = jwtExpiringIn(-30);
    setAuthenticated({ access_token: stale, refresh_token: 'refresh-1' });
    fake.mocks.refresh.mockRejectedValue(new TypeError('network down'));

    // The existing token is returned so the next request retries, rather than
    // logging the operator out because their wifi blipped.
    await expect(refreshAccessToken()).resolves.toBe(stale);
    expect(window.localStorage.getItem(refreshTokenKey())).toBe('refresh-1');
    expect(authStore.status).not.toBe('unauthenticated');
  });

  it('does not attempt a renewal without a stored refresh credential', async () => {
    window.localStorage.setItem(tokenKey(), jwtExpiringIn(-30));

    await expect(getValidAccessToken()).resolves.not.toBe('');
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('refreshAccessToken called directly with no stored refresh credential ends the session', async () => {
    // Unlike getValidAccessToken (which short-circuits before calling
    // refreshAccessToken), refreshAccessToken itself must also fail closed
    // when invoked with nothing to renew — e.g. a caller that skips the
    // token-factory and renews eagerly.
    window.localStorage.setItem(tokenKey(), jwtExpiringIn(600));
    setAuthStatus('authenticated');

    await expect(refreshAccessToken()).resolves.toBe('');
    expect(authStore.status).toBe('unauthenticated');
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('ends the session when the server answers a refresh with an empty access token', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(-30), refresh_token: 'refresh-1' });
    fake.mocks.refresh.mockResolvedValue({
      access_token: '',
      refresh_token: 'refresh-2',
      token_type: 'Bearer',
      expires_in: 900,
    });

    await expect(refreshAccessToken()).resolves.toBe('');
    expect(authStore.status).toBe('unauthenticated');
    expect(window.localStorage.getItem(tokenKey())).toBeNull();
  });

  it('ends the session when the server answers a refresh with no access_token field at all', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(-30), refresh_token: 'refresh-1' });
    // A malformed/legacy server response that omits the field entirely
    // (undefined, not just empty) — the `?? ''` fallback must catch this too.
    fake.mocks.refresh.mockResolvedValue({
      refresh_token: 'refresh-2',
      token_type: 'Bearer',
      expires_in: 900,
    });

    await expect(refreshAccessToken()).resolves.toBe('');
    expect(authStore.status).toBe('unauthenticated');
  });

  it('returns empty for a missing access token', async () => {
    await expect(getValidAccessToken()).resolves.toBe('');
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('leaves an opaque (non-JWT) token untouched', async () => {
    setAuthenticated({ access_token: 'opaque-token', refresh_token: 'refresh-1' });

    await expect(getValidAccessToken()).resolves.toBe('opaque-token');
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('leaves a JWT with an undecodable claims segment untouched (secondsUntilExpiry catch path)', async () => {
    // Three dot-separated segments (so it LOOKS like a JWT), but the claims
    // segment is not valid base64 — atob() throws, which secondsUntilExpiry
    // must catch and treat as "not decodable" rather than propagating.
    setAuthenticated({ access_token: 'header.###.sig', refresh_token: 'refresh-1' });

    await expect(getValidAccessToken()).resolves.toBe('header.###.sig');
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('leaves a JWT whose exp claim is not a number untouched', async () => {
    const header = btoa(JSON.stringify({ alg: 'none', typ: 'at+jwt' }));
    const payload = btoa(JSON.stringify({ sub: 'user-1', exp: 'soon' }));
    const weird = `${header}.${payload}.sig`;
    setAuthenticated({ access_token: weird, refresh_token: 'refresh-1' });

    await expect(getValidAccessToken()).resolves.toBe(weird);
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // validateSession + generation guard
  // -------------------------------------------------------------------------

  it('marks the session authenticated when the server validates it', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    setAuthStatus('pending');

    await validateSession();

    expect(authStore.status).toBe('authenticated');
    expect(fake.mocks.validate).toHaveBeenCalledTimes(1);
  });

  it('marks unauthenticated without a validate round trip when there is no token at all', async () => {
    // localStorage is cleared in beforeEach; nothing was ever signed in.
    await validateSession();

    expect(authStore.status).toBe('unauthenticated');
    expect(fake.mocks.validate).not.toHaveBeenCalled();
  });

  it('marks the session unauthenticated when the server rejects the token', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    fake.mocks.validate.mockRejectedValue(new FakeApiError(401, 'invalid token'));

    await validateSession();

    expect(authStore.status).toBe('unauthenticated');
  });

  it('does not resurrect a session ended while validation was in flight', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    // An always-affirmative server: only the generation guard can prevent the
    // stale verdict from being committed.
    let release: (v: { subject: string }) => void = () => {};
    fake.mocks.validate.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );

    const inFlight = validateSession();
    // Wait until the round trip is actually outstanding, then sign out.
    await vi.waitFor(() => expect(fake.mocks.validate).toHaveBeenCalled());
    endSession();
    release({ subject: 'user-1' });
    await inFlight;

    expect(authStore.status).toBe('unauthenticated');
  });

  // -------------------------------------------------------------------------
  // Cross-tab storage sync
  // -------------------------------------------------------------------------

  it('reflects a sign-out performed in another tab', () => {
    setAuthenticated({ access_token: 'access-1', refresh_token: 'refresh-1' });

    handleStorageEvent(
      new StorageEvent('storage', { key: tokenKey(), newValue: null }),
    );

    expect(authStore.status).toBe('unauthenticated');
  });

  it('reflects a sign-in performed in another tab', () => {
    setAuthStatus('unauthenticated');

    handleStorageEvent(
      new StorageEvent('storage', { key: tokenKey(), newValue: 'access-2' }),
    );

    expect(authStore.status).toBe('authenticated');
  });

  it('treats a full storage clear as the end of the session', () => {
    setAuthenticated({ access_token: 'access-1', refresh_token: 'refresh-1' });

    handleStorageEvent(new StorageEvent('storage', { key: null }));

    expect(authStore.status).toBe('unauthenticated');
  });

  it('ignores storage events for unrelated keys', () => {
    setAuthenticated({ access_token: 'access-1', refresh_token: 'refresh-1' });

    handleStorageEvent(
      new StorageEvent('storage', { key: 'some_other_key', newValue: null }),
    );

    expect(authStore.status).toBe('authenticated');
  });

  it('installCrossTabSync wires the window storage event', () => {
    const uninstall = installCrossTabSync();
    setAuthenticated({ access_token: 'access-1', refresh_token: 'refresh-1' });

    window.dispatchEvent(
      new StorageEvent('storage', { key: tokenKey(), newValue: null }),
    );

    expect(authStore.status).toBe('unauthenticated');
    uninstall();
  });

  it('installCrossTabSync is idempotent on a second call', () => {
    const uninstall1 = installCrossTabSync();
    const uninstall2 = installCrossTabSync();

    // The second install is a no-op (it does not double-subscribe), so its
    // uninstaller is a no-op too — calling it must not disturb the first
    // subscription or throw.
    expect(() => uninstall2()).not.toThrow();
    setAuthenticated({ access_token: 'access-1', refresh_token: 'refresh-1' });
    window.dispatchEvent(
      new StorageEvent('storage', { key: tokenKey(), newValue: null }),
    );
    expect(authStore.status).toBe('unauthenticated');

    uninstall1();
  });

  it('invalidates an in-flight validation when another tab signs out', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    let release: (v: { subject: string }) => void = () => {};
    fake.mocks.validate.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );

    const inFlight = validateSession();
    await vi.waitFor(() => expect(fake.mocks.validate).toHaveBeenCalled());
    handleStorageEvent(
      new StorageEvent('storage', { key: tokenKey(), newValue: null }),
    );
    release({ subject: 'user-1' });
    await inFlight;

    expect(authStore.status).toBe('unauthenticated');
  });

  // -------------------------------------------------------------------------
  // Misconfiguration
  // -------------------------------------------------------------------------

  it('readAuthToken returns empty for a missing token', () => {
    expect(readAuthToken()).toBe('');
  });

  // -------------------------------------------------------------------------
  // SSR guard (typeof window === 'undefined')
  // -------------------------------------------------------------------------

  it('readAuthToken and readRefreshToken return empty without a window (SSR)', () => {
    vi.stubGlobal('window', undefined);
    try {
      expect(readAuthToken()).toBe('');
      expect(readRefreshToken()).toBe('');
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('refreshAccessToken returns empty without a window (SSR), before even checking for a refresh token', async () => {
    vi.stubGlobal('window', undefined);
    try {
      await expect(refreshAccessToken()).resolves.toBe('');
    } finally {
      vi.unstubAllGlobals();
    }
    // No renewal call was attempted since the SSR guard short-circuits first.
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('surfaces AuthNotConfiguredError as a typed error class', () => {
    const err = new AuthNotConfiguredError();
    expect(err.name).toBe('AuthNotConfiguredError');
    expect(err).toBeInstanceOf(Error);
  });
});
