/**
 * auth.test.ts — session token endpoints and WebAuthn ceremony plumbing
 * (X-Session-Id / X-User-Id headers, credentials: 'include' on cert login).
 */

import { describe, it, expect } from 'vitest';
import { createClient } from './client.js';
import { newFakeFetch } from './testutil.js';
import type { AttestationCredentialJSON, AssertionCredentialJSON } from './webauthn.js';

const BASE = 'https://xkms.example.com';

function client(fake: ReturnType<typeof newFakeFetch>, token?: () => string) {
  return createClient({
    baseURL: BASE,
    fetch: fake.fetch,
    ...(token !== undefined ? { token } : {}),
  });
}

const tokenPair = {
  access_token: 'at',
  refresh_token: 'rt',
  token_type: 'Bearer',
  expires_in: 900,
};

describe('AuthClient token endpoints', () => {
  it('loginCert POSTs with credentials include and no bearer', async () => {
    const fake = newFakeFetch({ body: tokenPair });
    const c = client(fake, () => 'stale-token');
    const resp = await c.auth.loginCert();
    expect(resp.access_token).toBe('at');
    const call = fake.calls[0]!;
    expect(call.url).toBe(`${BASE}/api/v1/auth/login/piv`);
    expect(call.method).toBe('POST');
    expect(call.credentials).toBe('include');
    expect(call.headers['Authorization']).toBeUndefined();
  });

  it('honors authPaths overrides', async () => {
    const fake = newFakeFetch({ body: tokenPair });
    const c = createClient({
      baseURL: BASE,
      fetch: fake.fetch,
      authPaths: { loginCert: '/custom/login' },
    });
    await c.auth.loginCert();
    expect(fake.calls[0]?.url).toBe(`${BASE}/custom/login`);
    // Non-overridden members keep their defaults.
    expect(c.authPaths.refresh).toBe('/api/v1/auth/refresh');
  });

  it('refresh POSTs the refresh_token without a bearer', async () => {
    const fake = newFakeFetch({ body: tokenPair });
    const c = client(fake, () => 'old');
    await c.auth.refresh('rt-1');
    const call = fake.calls[0]!;
    expect(call.url).toBe(`${BASE}/api/v1/auth/refresh`);
    expect(call.body).toEqual({ refresh_token: 'rt-1' });
    expect(call.headers['Authorization']).toBeUndefined();
  });

  it('me / validate ride the token provider', async () => {
    const fake = newFakeFetch({
      body: { subject: 'alice', permissions: {}, capabilities: {} },
    });
    const c = client(fake, () => 'live-token');
    const me = await c.auth.me();
    expect(me.subject).toBe('alice');
    expect(fake.calls[0]?.headers['Authorization']).toBe('Bearer live-token');

    fake.respond({ body: { subject: 'alice' } });
    await c.auth.validate();
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/auth/validate`);
  });

  it('logout POSTs the refresh token and resolves on 204', async () => {
    const fake = newFakeFetch({ status: 204 });
    const c = client(fake, () => 't');
    await expect(c.auth.logout('rt-9')).resolves.toBeUndefined();
    const call = fake.calls[0]!;
    expect(call.url).toBe(`${BASE}/api/v1/auth/logout`);
    expect(call.body).toEqual({ refresh_token: 'rt-9' });
    expect(call.headers['Authorization']).toBe('Bearer t');
  });

  it('logout defaults to an empty refresh_token when none is supplied', async () => {
    const fake = newFakeFetch({ status: 204 });
    const c = client(fake, () => 't');
    await c.auth.logout();
    expect(fake.calls[0]?.body).toEqual({ refresh_token: '' });
  });

  it('loginCert propagates a non-2xx response as XkmsApiError', async () => {
    const fake = newFakeFetch({ status: 401, body: { error: 'no client certificate' } });
    const c = client(fake);
    const err = await c.auth.loginCert().catch((e: unknown) => e);
    expect(err).toMatchObject({ name: 'XkmsApiError', status: 401 });
  });
});

describe('AuthClient WebAuthn ceremonies', () => {
  const optionsEnvelope = { publicKey: { challenge: 'AQID' } };

  it('registration begin captures X-Session-Id and returns the raw envelope', async () => {
    const fake = newFakeFetch({
      body: optionsEnvelope,
      headers: { 'X-Session-Id': 'sess-1' },
    });
    const c = client(fake);
    const start = await c.auth.webAuthnRegisterBegin({
      email: 'a@example.com',
      display_name: 'Alice',
    });
    expect(start.sessionId).toBe('sess-1');
    expect(start.options).toEqual(optionsEnvelope);
    const call = fake.calls[0]!;
    expect(call.url).toBe(`${BASE}/api/v1/webauthn/registration/begin`);
    expect(call.body).toEqual({ email: 'a@example.com', display_name: 'Alice' });
  });

  it('registration begin defaults sessionId to "" when the header is absent', async () => {
    const fake = newFakeFetch({ body: optionsEnvelope });
    const c = client(fake);
    const start = await c.auth.webAuthnRegisterBegin({ email: 'a@example.com' });
    expect(start.sessionId).toBe('');
  });

  it('registration finish echoes X-Session-Id', async () => {
    const fake = newFakeFetch({ body: { token: 't', user_id: 'u' } });
    const c = client(fake);
    const cred = {
      id: 'c',
      rawId: 'AQ',
      type: 'public-key',
      response: { clientDataJSON: 'Ag', attestationObject: 'Aw' },
      clientExtensionResults: {},
    } as AttestationCredentialJSON;
    const resp = await c.auth.webAuthnRegisterFinish('sess-1', cred);
    expect(resp.token).toBe('t');
    const call = fake.calls[0]!;
    expect(call.headers['X-Session-Id']).toBe('sess-1');
    expect(call.body).toMatchObject({ rawId: 'AQ' });
  });

  it('registration status passes user_id/email as query params', async () => {
    const fake = newFakeFetch({ body: { registered: true } });
    const c = client(fake);
    const resp = await c.auth.webAuthnRegistrationStatus({ email: 'a@example.com' });
    expect(resp.registered).toBe(true);
    expect(fake.calls[0]?.url).toBe(
      `${BASE}/api/v1/webauthn/registration/status?email=a%40example.com`,
    );
  });

  it('login begin captures X-Session-Id and X-User-Id', async () => {
    const fake = newFakeFetch({
      body: optionsEnvelope,
      headers: { 'X-Session-Id': 'sess-2', 'X-User-Id': 'dXNlcg' },
    });
    const c = client(fake);
    const start = await c.auth.webAuthnBeginLogin({ email: 'a@example.com' });
    expect(start.sessionId).toBe('sess-2');
    expect(start.userId).toBe('dXNlcg');
  });

  it('login begin omits userId when the header is absent (discoverable flow)', async () => {
    const fake = newFakeFetch({
      body: optionsEnvelope,
      headers: { 'X-Session-Id': 'sess-3' },
    });
    const c = client(fake);
    const start = await c.auth.webAuthnBeginLogin();
    expect(start.userId).toBeUndefined();
    expect(fake.calls[0]?.body).toEqual({});
  });

  it('login begin defaults sessionId to "" when the header is absent', async () => {
    const fake = newFakeFetch({ body: optionsEnvelope });
    const c = client(fake);
    const start = await c.auth.webAuthnBeginLogin({ email: 'a@example.com' });
    expect(start.sessionId).toBe('');
  });

  it('login finish echoes both session and user headers', async () => {
    const fake = newFakeFetch({ body: { token: 't', refresh_token: 'r', user_id: 'u' } });
    const c = client(fake);
    const cred = {
      id: 'c',
      rawId: 'AQ',
      type: 'public-key',
      response: { clientDataJSON: 'Ag', authenticatorData: 'Aw', signature: 'BA' },
      clientExtensionResults: {},
    } as AssertionCredentialJSON;
    const resp = await c.auth.webAuthnFinishLogin('sess-2', cred, 'dXNlcg');
    expect(resp.refresh_token).toBe('r');
    const call = fake.calls[0]!;
    expect(call.headers['X-Session-Id']).toBe('sess-2');
    expect(call.headers['X-User-Id']).toBe('dXNlcg');
  });
});
