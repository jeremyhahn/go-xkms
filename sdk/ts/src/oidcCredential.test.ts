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
 * Wire-contract coverage for OidcCredentialClient (server-side OIDC
 * credentials, pkg/api/rest/handlers_oidc_credential.go): every method's
 * verb, path, query and body, error propagation, and the device-login
 * polling helper's pacing, expiry and abort behaviour.
 */

import { afterEach, describe, it, expect, vi } from 'vitest';
import { createClient } from './client.js';
import { newFakeFetch } from './testutil.js';
import { XkmsApiError } from './errors.js';
import { OIDCDeviceLoginError } from './clients/oidcCredential.js';
import type { OIDCCredential, OIDCCredentialRef } from './types/oidcCredential.js';

const BASE = 'https://xkms.example.com';
const COLLECTION = `${BASE}/api/v1/oidc/credentials`;

function make(fake: ReturnType<typeof newFakeFetch>) {
  return createClient({ baseURL: BASE, fetch: fake.fetch, token: () => 'tk' });
}

const shared: OIDCCredentialRef = { scope: 'tenant', name: 'codex' };
const personal: OIDCCredentialRef = { tenant_id: 't1', scope: 'user', owner: 'alice', name: 'my login' };

function credential(over: Partial<OIDCCredential> = {}): OIDCCredential {
  return {
    scope: 'tenant',
    name: 'codex',
    config: { template: 'openai' },
    status: 'pending',
    refreshable: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...over,
  };
}

describe('OidcCredentialClient (wire contract)', () => {
  it('lists a tenant\'s credentials, scoping by tenant_id only when given', async () => {
    const fake = newFakeFetch({ body: { credentials: [credential()] } });
    const c = make(fake);

    const resp = await c.oidcCredentials.list();
    expect(fake.calls[0]?.method).toBe('GET');
    expect(fake.calls[0]?.url).toBe(COLLECTION);
    expect(resp.credentials[0]?.name).toBe('codex');

    await c.oidcCredentials.list('t1');
    expect(fake.calls[1]?.url).toBe(`${COLLECTION}?tenant_id=t1`);
  });

  it('creates a credential with the ref fields, config and tokens flattened into the body', async () => {
    const fake = newFakeFetch({ status: 201, body: credential({ status: 'active' }) });
    const c = make(fake);

    const created = await c.oidcCredentials.create({
      scope: 'user',
      name: 'claude',
      config: { template: 'anthropic' },
      tokens: { access_token: 'sk-ant-oat01' },
    });
    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(COLLECTION);
    expect(fake.calls[0]?.body).toEqual({
      scope: 'user',
      name: 'claude',
      config: { template: 'anthropic' },
      tokens: { access_token: 'sk-ant-oat01' },
    });
    expect(created.status).toBe('active');
  });

  it('gets and deletes by scope/name, naming tenant and owner in the query and escaping the name', async () => {
    const fake = newFakeFetch({ body: credential() });
    const c = make(fake);

    await c.oidcCredentials.get(shared);
    expect(fake.calls[0]?.method).toBe('GET');
    expect(fake.calls[0]?.url).toBe(`${COLLECTION}/tenant/codex`);

    await c.oidcCredentials.get(personal);
    expect(fake.calls[1]?.url).toBe(`${COLLECTION}/user/my%20login?tenant_id=t1&owner=alice`);

    fake.respond({ status: 204 });
    await expect(c.oidcCredentials.delete(personal)).resolves.toBeUndefined();
    expect(fake.calls[2]?.method).toBe('DELETE');
    expect(fake.calls[2]?.url).toBe(`${COLLECTION}/user/my%20login?tenant_id=t1&owner=alice`);
    expect(fake.calls[2]?.body).toBeUndefined();
  });

  it('imports tokens under a {tokens} body', async () => {
    const fake = newFakeFetch({ body: credential({ status: 'active' }) });
    const c = make(fake);

    const tokens = { access_token: 'at', refresh_token: 'rt', id_token: 'it' };
    await c.oidcCredentials.importTokens(shared, tokens);
    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(`${COLLECTION}/tenant/codex/import`);
    expect(fake.calls[0]?.body).toEqual({ tokens });
  });

  it('routes refresh, token, device start and device poll as body-less POSTs', async () => {
    const fake = newFakeFetch({ body: credential() });
    const c = make(fake);

    await c.oidcCredentials.refresh(personal);
    fake.respond({ body: { access_token: 'at', token_type: 'Bearer' } });
    const token = await c.oidcCredentials.getAccessToken(shared);
    fake.respond({ body: credential() });
    await c.oidcCredentials.startDeviceLogin(shared);
    await c.oidcCredentials.pollDeviceLogin(shared);

    expect(fake.calls.map((call) => [call.method, call.url, call.body])).toEqual([
      ['POST', `${COLLECTION}/user/my%20login/refresh?tenant_id=t1&owner=alice`, undefined],
      ['POST', `${COLLECTION}/tenant/codex/token`, undefined],
      ['POST', `${COLLECTION}/tenant/codex/device`, undefined],
      ['POST', `${COLLECTION}/tenant/codex/device/poll`, undefined],
    ]);
    expect(token).toEqual({ access_token: 'at', token_type: 'Bearer' });
  });

  it('surfaces a refused call as XkmsApiError with the server\'s status and message', async () => {
    const fake = newFakeFetch({
      status: 409,
      body: { error: 'oidc credential: relogin required', message: 'refresh token was revoked' },
    });
    const c = make(fake);

    const err = await c.oidcCredentials.getAccessToken(shared).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(409);
    expect((err as XkmsApiError).message).toBe('refresh token was revoked');

    fake.respond({ status: 404, body: { error: 'oidc credential: not found' } });
    const delErr = await c.oidcCredentials.delete(shared).catch((e: unknown) => e);
    expect(delErr).toBeInstanceOf(XkmsApiError);
    expect((delErr as XkmsApiError).status).toBe(404);
  });
});

describe('OidcCredentialClient.waitForDeviceLogin', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const NOW = Date.parse('2026-06-01T00:00:00Z');
  const deviceLogin = (interval: number, expiresInSeconds = 600) => ({
    user_code: 'ABCD-EFGH',
    verification_uri: 'https://auth.example.com/device',
    interval_seconds: interval,
    expires_at: new Date(NOW + expiresInSeconds * 1000).toISOString(),
  });

  it('waits each poll\'s interval before polling and resolves once the credential is active', async () => {
    vi.useFakeTimers({ now: NOW });
    const fake = newFakeFetch();
    fake.respond({ body: credential({ device_login: deviceLogin(7) }) });
    fake.respond({ body: credential({ status: 'active' }) });
    const c = make(fake);
    const pending: OIDCCredential[] = [];

    const done = c.oidcCredentials.waitForDeviceLogin(credential({ device_login: deviceLogin(2) }), {
      onPending: (cred) => pending.push(cred),
    });

    // No poll before the started login's 2s interval elapses.
    await vi.advanceTimersByTimeAsync(1999);
    expect(fake.calls).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(fake.calls).toHaveLength(1);
    expect(pending).toHaveLength(1);

    // The poll answered with a 7s interval (a slow-down): honoured.
    await vi.advanceTimersByTimeAsync(6999);
    expect(fake.calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);

    const result = await done;
    expect(result.status).toBe('active');
    expect(fake.calls).toHaveLength(2);
    expect(fake.calls.every((call) => call.url === `${COLLECTION}/tenant/codex/device/poll`)).toBe(true);
  });

  it('resolves with a settled non-active status rather than polling on', async () => {
    vi.useFakeTimers({ now: NOW });
    const fake = newFakeFetch({ body: credential({ status: 'expired', status_reason: 'device code expired' }) });
    const c = make(fake);

    const done = c.oidcCredentials.waitForDeviceLogin(credential({ device_login: deviceLogin(1) }));
    await vi.advanceTimersByTimeAsync(1000);
    expect((await done).status).toBe('expired');
    expect(fake.calls).toHaveLength(1);
  });

  it('returns a credential that is not pending without polling at all', async () => {
    const fake = newFakeFetch();
    const c = make(fake);
    const active = credential({ status: 'active' });
    await expect(c.oidcCredentials.waitForDeviceLogin(active)).resolves.toBe(active);
    expect(fake.calls).toHaveLength(0);
  });

  it('rejects once a still-pending device login passes its expiry', async () => {
    vi.useFakeTimers({ now: NOW });
    const fake = newFakeFetch({ body: credential({ device_login: deviceLogin(5, 5) }) });
    const c = make(fake);

    const done = c.oidcCredentials.waitForDeviceLogin(credential({ device_login: deviceLogin(5, 5) }));
    const settled = done.catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(5000);
    const err = await settled;
    expect(err).toBeInstanceOf(OIDCDeviceLoginError);
    expect((err as OIDCDeviceLoginError).reason).toBe('expired');
    expect(fake.calls).toHaveLength(1);
  });

  it('rejects a pending credential that has no device login in progress', async () => {
    const fake = newFakeFetch();
    const c = make(fake);
    const err = await c.oidcCredentials.waitForDeviceLogin(credential()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OIDCDeviceLoginError);
    expect((err as OIDCDeviceLoginError).reason).toBe('not_started');
    expect(fake.calls).toHaveLength(0);
  });

  it('polls a bare reference at the default 5s interval', async () => {
    vi.useFakeTimers({ now: NOW });
    const fake = newFakeFetch({ body: credential({ status: 'active' }) });
    const c = make(fake);

    const done = c.oidcCredentials.waitForDeviceLogin(personal);
    await vi.advanceTimersByTimeAsync(4999);
    expect(fake.calls).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1);
    expect((await done).status).toBe('active');
    expect(fake.calls[0]?.url).toBe(`${COLLECTION}/user/my%20login/device/poll?tenant_id=t1&owner=alice`);
  });

  it('stops waiting when aborted, mid-wait or before it starts, without another poll', async () => {
    vi.useFakeTimers({ now: NOW });
    const fake = newFakeFetch({ body: credential({ device_login: deviceLogin(5) }) });
    const c = make(fake);
    const ctl = new AbortController();

    const done = c.oidcCredentials
      .waitForDeviceLogin(credential({ device_login: deviceLogin(5) }), { signal: ctl.signal })
      .catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(1000);
    ctl.abort(new Error('closed'));
    expect(((await done) as Error).message).toBe('closed');
    await vi.advanceTimersByTimeAsync(10000);
    expect(fake.calls).toHaveLength(0);

    const again = await c.oidcCredentials
      .waitForDeviceLogin(credential({ device_login: deviceLogin(5) }), { signal: ctl.signal })
      .catch((e: unknown) => e);
    expect((again as Error).message).toBe('closed');
  });

  it('propagates a failed poll', async () => {
    vi.useFakeTimers({ now: NOW });
    const fake = newFakeFetch({ status: 403, body: { error: 'forbidden' } });
    const c = make(fake);

    const done = c.oidcCredentials
      .waitForDeviceLogin(credential({ device_login: deviceLogin(1) }))
      .catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(1000);
    const err = await done;
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(403);
  });
});
