/**
 * http.test.ts — the shared HTTP core: URL building, bearer attachment,
 * error-envelope mapping, correlation IDs, and network-failure wrapping.
 */

import { describe, it, expect } from 'vitest';
import { HttpCore, buildURL } from './http.js';
import { XkmsApiError, XkmsNetworkError } from './errors.js';
import { newFakeFetch } from './testutil.js';

const BASE = 'https://xkms.example.com:8443';

describe('buildURL', () => {
  it('joins base and path, trimming trailing slashes', () => {
    expect(buildURL(`${BASE}/`, '/api/v1/keys')).toBe(`${BASE}/api/v1/keys`);
    expect(buildURL(BASE, 'health')).toBe(`${BASE}/health`);
  });

  it('encodes query parameters and omits empty values', () => {
    const url = buildURL(BASE, '/api/v1/keys', {
      backend: 'tpm2',
      page: 2,
      empty: '',
      missing: undefined,
      nil: null,
      odd: 'a b&c',
    });
    expect(url).toBe(`${BASE}/api/v1/keys?backend=tpm2&page=2&odd=a%20b%26c`);
  });
});

describe('HttpCore', () => {
  it('attaches Authorization from an async token provider', async () => {
    const fake = newFakeFetch({ body: { ok: true } });
    const core = new HttpCore({
      baseURL: BASE,
      token: async () => 'tok-123',
      fetch: fake.fetch,
    });
    await core.request('GET', '/api/v1/backends');
    expect(fake.calls[0]?.headers['Authorization']).toBe('Bearer tok-123');
  });

  it('omits Authorization when the provider yields an empty token', async () => {
    const fake = newFakeFetch({ body: {} });
    const core = new HttpCore({ baseURL: BASE, token: () => '', fetch: fake.fetch });
    await core.request('GET', '/health');
    expect(fake.calls[0]?.headers['Authorization']).toBeUndefined();
  });

  it('omits Authorization when auth: false even with a token', async () => {
    const fake = newFakeFetch({ body: {} });
    const core = new HttpCore({ baseURL: BASE, token: () => 't', fetch: fake.fetch });
    await core.request('POST', '/api/v1/auth/refresh', {
      auth: false,
      body: { refresh_token: 'r' },
    });
    expect(fake.calls[0]?.headers['Authorization']).toBeUndefined();
    expect(fake.calls[0]?.headers['Content-Type']).toBe('application/json');
  });

  it('serializes JSON bodies and decodes JSON responses', async () => {
    const fake = newFakeFetch({ body: { key_id: 'k1', key_type: 'ecdsa' } });
    const core = new HttpCore({ baseURL: BASE, fetch: fake.fetch });
    const resp = await core.request<{ key_id: string }>('POST', '/api/v1/keys', {
      body: { key_id: 'k1', key_type: 'ecdsa' },
    });
    expect(resp.key_id).toBe('k1');
    expect(fake.calls[0]?.body).toEqual({ key_id: 'k1', key_type: 'ecdsa' });
  });

  it('maps the server error envelope to XkmsApiError', async () => {
    const fake = newFakeFetch({
      status: 404,
      body: { error: 'rest: backend not found', message: 'no such backend', code: 404 },
      headers: { 'X-Correlation-ID': 'corr-42' },
    });
    const core = new HttpCore({ baseURL: BASE, fetch: fake.fetch });
    const err = await core.request('GET', '/api/v1/backends/nope').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    const apiErr = err as XkmsApiError;
    expect(apiErr.status).toBe(404);
    expect(apiErr.code).toBe('rest: backend not found');
    expect(apiErr.message).toBe('no such backend');
    expect(apiErr.correlationId).toBe('corr-42');
    expect(apiErr.envelope?.code).toBe(404);
  });

  it('tolerates non-JSON error bodies', async () => {
    const fake = newFakeFetch({ status: 502, text: '<html>bad gateway</html>' });
    const core = new HttpCore({ baseURL: BASE, fetch: fake.fetch });
    const err = await core.request('GET', '/health').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(502);
    expect((err as XkmsApiError).code).toBe('http_502');
  });

  it('carries the SSH mismatch envelope fields through', async () => {
    const fake = newFakeFetch({
      status: 409,
      body: {
        error: 'hostkey_mismatch',
        host: 'db1',
        expected: 'SHA256:aaa',
        received: 'SHA256:bbb',
      },
    });
    const core = new HttpCore({ baseURL: BASE, fetch: fake.fetch });
    const err = await core
      .request('POST', '/xkms/v1/ssh/known-hosts/db1/verify', { body: {} })
      .catch((e: unknown) => e);
    const apiErr = err as XkmsApiError;
    expect(apiErr.envelope?.expected).toBe('SHA256:aaa');
    expect(apiErr.envelope?.received).toBe('SHA256:bbb');
  });

  it('still throws a usable XkmsApiError when the error body stream itself fails to read', async () => {
    const core = new HttpCore({
      baseURL: BASE,
      fetch: (() =>
        Promise.resolve({
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
          headers: { get: () => null },
          text: () => Promise.reject(new Error('stream aborted')),
        } as unknown as Response)) as typeof fetch,
    });
    const err = await core.request('GET', '/health').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(500);
    expect((err as XkmsApiError).code).toBe('http_500');
  });

  it('wraps fetch rejections in XkmsNetworkError', async () => {
    const core = new HttpCore({
      baseURL: BASE,
      fetch: (() => Promise.reject(new Error('ECONNREFUSED'))) as typeof fetch,
    });
    const err = await core.request('GET', '/health').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsNetworkError);
  });

  it('returns undefined for 204 responses', async () => {
    const fake = newFakeFetch({ status: 204 });
    const core = new HttpCore({ baseURL: BASE, fetch: fake.fetch });
    const out = await core.request('POST', '/api/v1/auth/logout', {
      body: { refresh_token: 'r' },
      parse: 'void',
    });
    expect(out).toBeUndefined();
  });

  it('decodes text responses when parse: text', async () => {
    const fake = newFakeFetch({ text: '-----BEGIN CERTIFICATE-----' });
    const core = new HttpCore({ baseURL: BASE, fetch: fake.fetch });
    const pem = await core.request<string>('GET', '/v1/ca/bootstrap', { parse: 'text' });
    expect(pem).toContain('BEGIN CERTIFICATE');
  });

  it('resolves okOn statuses without throwing', async () => {
    const fake = newFakeFetch({ status: 404 });
    const core = new HttpCore({ baseURL: BASE, fetch: fake.fetch });
    const { response } = await core.requestRaw<void>('HEAD', '/api/v1/certs/x', {
      parse: 'void',
      okOn: [404],
    });
    expect(response.status).toBe(404);
  });

  it('resolves okOn statuses for a JSON parse as undefined data rather than decoding the error body', async () => {
    const fake = newFakeFetch({ status: 404, body: { error: 'not found' } });
    const core = new HttpCore({ baseURL: BASE, fetch: fake.fetch });
    const { data, response } = await core.requestRaw<{ error: string } | undefined>(
      'GET',
      '/api/v1/keys/missing',
      { okOn: [404] },
    );
    expect(response.status).toBe(404);
    expect(data).toBeUndefined();
  });

  it('decodes an empty 200 body as undefined rather than throwing a JSON parse error', async () => {
    const fake = newFakeFetch({ status: 200, text: '' });
    const core = new HttpCore({ baseURL: BASE, fetch: fake.fetch });
    const out = await core.request('GET', '/api/v1/policies/boot/export');
    expect(out).toBeUndefined();
  });
});
