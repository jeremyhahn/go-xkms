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
 * 401-recovery fetch layer tests: renew-once-replay, refresh-path exclusion,
 * non-API passthrough, renewal-failure surfacing, and configurable prefixes.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { installAuthFetch, uninstallAuthFetch } from '../src/authFetch.ts';
import {
  authStore,
  configureAuthStore,
  setAuthStatus,
  setAuthenticated,
} from '../src/stores/auth.svelte.ts';
import { FakeApiError, jwtExpiringIn, makeFakeClient, tokenPair } from './helpers.ts';

/** A JSON Response with the given status/body. */
function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('authFetch 401 recovery layer', () => {
  let fake = makeFakeClient();

  beforeEach(() => {
    window.localStorage.clear();
    fake = makeFakeClient();
    configureAuthStore({ client: fake.client });
    setAuthStatus('pending');
  });

  afterEach(() => {
    uninstallAuthFetch();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('renews and replays a request that the server answered with 401', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    const renewed = jwtExpiringIn(900);
    fake.mocks.refresh.mockResolvedValue(tokenPair(renewed, 'refresh-2'));

    const calls: Array<{ url: string; authorization: string }> = [];
    const base = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const authorization = new Headers(init?.headers ?? {}).get('Authorization') ?? '';
      calls.push({ url: String(input), authorization });
      return calls.length === 1
        ? jsonResponse(401, { error: 'Invalid or expired token' })
        : jsonResponse(200, { keys: [] });
    });
    vi.stubGlobal('fetch', base);
    installAuthFetch();

    const resp = await window.fetch('/api/v1/keys', {
      headers: { Authorization: 'Bearer stale' },
    });

    expect(resp.status).toBe(200);
    expect(calls).toHaveLength(2);
    expect(calls[0]?.authorization).toBe('Bearer stale');
    // The replay carries the RENEWED bearer, not the stale one.
    expect(calls[1]?.authorization).toBe(`Bearer ${renewed}`);
    expect(fake.mocks.refresh).toHaveBeenCalledTimes(1);
  });

  it('replays at most once — a second 401 is returned to the caller', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    fake.mocks.refresh.mockResolvedValue(tokenPair(jwtExpiringIn(900), 'refresh-2'));
    let apiCalls = 0;
    const base = vi.fn(async () => {
      apiCalls++;
      return jsonResponse(401, { error: 'Invalid or expired token' });
    });
    vi.stubGlobal('fetch', base);
    installAuthFetch();

    const resp = await window.fetch('/api/v1/keys', {
      headers: { Authorization: 'Bearer stale' },
    });

    expect(resp.status).toBe(401);
    expect(apiCalls).toBe(2);
    expect(fake.mocks.refresh).toHaveBeenCalledTimes(1);
  });

  it('never intercepts the refresh path itself', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    const base = vi.fn(async () => jsonResponse(401, { error: 'nope' }));
    vi.stubGlobal('fetch', base);
    installAuthFetch();

    const resp = await window.fetch('/api/v1/auth/refresh', { method: 'POST' });

    expect(resp.status).toBe(401);
    // Exactly one transport call and no renewal attempt: no recursion.
    expect(base).toHaveBeenCalledTimes(1);
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('surfaces the original 401 and ends the session when the renewal is rejected', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    fake.mocks.refresh.mockRejectedValue(new FakeApiError(401, 'refresh token revoked'));
    const base = vi.fn(async () => jsonResponse(401, { error: 'Invalid or expired token' }));
    vi.stubGlobal('fetch', base);
    installAuthFetch();

    const resp = await window.fetch('/api/v1/keys', {
      headers: { Authorization: 'Bearer stale' },
    });

    expect(resp.status).toBe(401);
    // No replay happened — one transport call only.
    expect(base).toHaveBeenCalledTimes(1);
    // The rejected renewal failed the session closed.
    expect(authStore.status).toBe('unauthenticated');
  });

  it('passes through a 401 when there is no session to renew', async () => {
    const base = vi.fn(async () => jsonResponse(401, { error: 'unauthenticated' }));
    vi.stubGlobal('fetch', base);
    installAuthFetch();

    const resp = await window.fetch('/api/v1/keys');

    expect(resp.status).toBe(401);
    expect(base).toHaveBeenCalledTimes(1);
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('leaves non-API requests alone', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    const base = vi.fn(async () => jsonResponse(401, { error: 'nope' }));
    vi.stubGlobal('fetch', base);
    installAuthFetch();

    const resp = await window.fetch('/assets/app.css');

    expect(resp.status).toBe(401);
    expect(base).toHaveBeenCalledTimes(1);
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('honors the configured apiPrefixes (default includes /xkms/)', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    const renewed = jwtExpiringIn(900);
    fake.mocks.refresh.mockResolvedValue(tokenPair(renewed, 'refresh-2'));
    let calls = 0;
    const base = vi.fn(async () => {
      calls++;
      return calls === 1
        ? jsonResponse(401, { error: 'expired' })
        : jsonResponse(200, {});
    });
    vi.stubGlobal('fetch', base);
    installAuthFetch();

    const resp = await window.fetch('/xkms/v1/keys', {
      headers: { Authorization: 'Bearer stale' },
    });

    expect(resp.status).toBe(200);
    expect(fake.mocks.refresh).toHaveBeenCalledTimes(1);
  });

  it('honors per-install prefix overrides', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    fake.mocks.refresh.mockResolvedValue(tokenPair(jwtExpiringIn(900), 'refresh-2'));
    const base = vi.fn(async () => jsonResponse(401, { error: 'expired' }));
    vi.stubGlobal('fetch', base);
    installAuthFetch({ apiPrefixes: ['/custom/'] });

    // /api/ is NOT in the override list, so no renewal is attempted.
    const resp = await window.fetch('/api/v1/keys', {
      headers: { Authorization: 'Bearer stale' },
    });

    expect(resp.status).toBe(401);
    expect(base).toHaveBeenCalledTimes(1);
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('recovers a 401 for a request made with a URL object input', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    const renewed = jwtExpiringIn(900);
    fake.mocks.refresh.mockResolvedValue(tokenPair(renewed, 'refresh-2'));
    let calls = 0;
    const base = vi.fn(async () => {
      calls++;
      return calls === 1
        ? jsonResponse(401, { error: 'expired' })
        : jsonResponse(200, { keys: [] });
    });
    vi.stubGlobal('fetch', base);
    installAuthFetch();

    const url = new URL('/api/v1/keys', window.location.origin);
    const resp = await window.fetch(url, { headers: { Authorization: 'Bearer stale' } });

    expect(resp.status).toBe(200);
    expect(fake.mocks.refresh).toHaveBeenCalledTimes(1);
    // requestURL() resolved the URL object via .toString() for the replay.
    expect(base.mock.calls[1]?.[0]).toBe(url.toString());
  });

  it('recovers a 401 for a Request whose Authorization header lives on the Request itself', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    const renewed = jwtExpiringIn(900);
    fake.mocks.refresh.mockResolvedValue(tokenPair(renewed, 'refresh-2'));
    let calls = 0;
    const base = vi.fn(async () => {
      calls++;
      return calls === 1
        ? jsonResponse(401, { error: 'expired' })
        : jsonResponse(200, { keys: [] });
    });
    vi.stubGlobal('fetch', base);
    installAuthFetch();

    const req = new Request(new URL('/api/v1/keys', window.location.origin), {
      headers: { Authorization: 'Bearer stale' },
    });
    const resp = await window.fetch(req);

    expect(resp.status).toBe(200);
    // The Request carried its own Authorization header (no init), which is
    // what makes authorizationOf() read it off the Request rather than init.
    expect(fake.mocks.refresh).toHaveBeenCalledTimes(1);
  });

  it('treats an unparsable request URL as non-renewable instead of throwing', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    const base = vi.fn(async () => jsonResponse(401, { error: 'expired' }));
    vi.stubGlobal('fetch', base);
    installAuthFetch();

    // An absolute URL with an invalid host is rejected by the WHATWG URL
    // parser regardless of the resolution base, exercising isRenewable's
    // catch branch instead of crashing the interceptor.
    await expect(
      window.fetch('http://[invalid', { headers: { Authorization: 'Bearer stale' } }),
    ).resolves.toMatchObject({ status: 401 });
    expect(base).toHaveBeenCalledTimes(1);
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('honors a per-install refreshPath override', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    const base = vi.fn(async () => jsonResponse(401, { error: 'nope' }));
    vi.stubGlobal('fetch', base);
    installAuthFetch({ refreshPath: '/custom/renew' });

    const resp = await window.fetch('/custom/renew', { method: 'POST' });

    expect(resp.status).toBe(401);
    // Exactly one transport call and no renewal attempt: the override path is
    // excluded, just like the store-configured default would exclude its own.
    expect(base).toHaveBeenCalledTimes(1);
    expect(fake.mocks.refresh).not.toHaveBeenCalled();
  });

  it('renews a request whose bearer lives only in storage, not on the Request object', async () => {
    setAuthenticated({ access_token: jwtExpiringIn(600), refresh_token: 'refresh-1' });
    const renewed = jwtExpiringIn(900);
    fake.mocks.refresh.mockResolvedValue(tokenPair(renewed, 'refresh-2'));
    let calls = 0;
    const base = vi.fn(async () => {
      calls++;
      return calls === 1
        ? jsonResponse(401, { error: 'expired' })
        : jsonResponse(200, { keys: [] });
    });
    vi.stubGlobal('fetch', base);
    installAuthFetch();

    // A Request with NO Authorization header at all — authorizationOf() must
    // fall back to '' instead of throwing, and isRenewable() still qualifies
    // the call because a bearer is held in storage.
    const req = new Request(new URL('/api/v1/keys', window.location.origin));
    const resp = await window.fetch(req);

    expect(resp.status).toBe(200);
    expect(fake.mocks.refresh).toHaveBeenCalledTimes(1);
  });

  it('installs only once', async () => {
    const base = vi.fn(async () => jsonResponse(200, {}));
    vi.stubGlobal('fetch', base);
    installAuthFetch();
    const wrapped = window.fetch;
    installAuthFetch();

    expect(window.fetch).toBe(wrapped);
  });
});
