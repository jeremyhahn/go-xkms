/**
 * factors.test.ts — wire-contract tests for FactorsClient.
 *
 * The N-factor routes are the one place in the API where the owning user
 * moves between the query string (list) and the request body (add), and where
 * a path parameter silently overrides whatever the body carries (relabel,
 * rotate). Those are the mistakes worth pinning, so every assertion here
 * checks the verb, the path, and which side of the wire each field landed on.
 */

import { describe, it, expect } from 'vitest';
import { createClient } from './client.js';
import { newFakeFetch } from './testutil.js';
import { XkmsApiError } from './errors.js';

const BASE = 'https://xkms.example.com';

function make(fake: ReturnType<typeof newFakeFetch>) {
  return createClient({ baseURL: BASE, fetch: fake.fetch, token: () => 'tk' });
}

function record(over: Record<string, unknown> = {}) {
  return {
    id: 'f-1',
    user_id: 42,
    type: 'fido2',
    label: 'YubiKey 5',
    credential: 'Y3JlZA==',
    registered_at: '2026-01-01T00:00:00Z',
    ...over,
  };
}

describe('FactorsClient.list', () => {
  it('sends the owner as a user_id query parameter', async () => {
    const fake = newFakeFetch({ body: { factors: [record()], total: 1 } });
    const c = make(fake);

    const resp = await c.factors.list(42);

    expect(fake.calls[0]?.method).toBe('GET');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/factors/?user_id=42`);
    expect(fake.calls[0]?.headers['Authorization']).toBe('Bearer tk');
    expect(resp.factors[0]?.id).toBe('f-1');
    expect(resp.total).toBe(1);
  });

  it('surfaces the server rejection of a missing or zero user id', async () => {
    const fake = newFakeFetch({
      status: 400,
      body: { error: 'rest: missing or invalid user_id' },
    });
    const c = make(fake);

    await expect(c.factors.list(0)).rejects.toBeInstanceOf(XkmsApiError);
    // 0 is falsy but still a real value the server must reject; the client
    // must not quietly drop the parameter and turn this into a list-all.
    await expect(c.factors.list(0)).rejects.toMatchObject({ status: 400 });
  });
});

describe('FactorsClient.add', () => {
  it('puts the owning user in the body, not the path', async () => {
    const fake = newFakeFetch({ status: 201, body: { factor: record() } });
    const c = make(fake);

    await c.factors.add({
      user_id: 42,
      type: 'mtls',
      label: 'laptop cert',
      credential: 'Y3JlZA==',
      spki_credential: 'c3BraQ==',
      created_by: 'admin',
    });

    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/factors/`);
    expect(fake.calls[0]?.body).toEqual({
      user_id: 42,
      type: 'mtls',
      label: 'laptop cert',
      credential: 'Y3JlZA==',
      spki_credential: 'c3BraQ==',
      created_by: 'admin',
    });
  });

  it('propagates a rejected enrolment', async () => {
    const fake = newFakeFetch({ status: 400, body: { error: 'rest: type is required' } });
    const c = make(fake);

    await expect(
      c.factors.add({ user_id: 42, type: '', credential: 'Y3JlZA==' }),
    ).rejects.toMatchObject({ status: 400 });
  });
});

describe('FactorsClient.get', () => {
  it('addresses the factor by path and encodes the id', async () => {
    const fake = newFakeFetch({ body: { factor: record({ id: 'f/1' }) } });
    const c = make(fake);

    await c.factors.get('f/1');

    expect(fake.calls[0]?.method).toBe('GET');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/factors/f%2F1`);
  });

  it('surfaces a missing factor', async () => {
    const fake = newFakeFetch({ status: 404, body: { error: 'not found' } });
    const c = make(fake);

    await expect(c.factors.get('nope')).rejects.toMatchObject({ status: 404 });
  });
});

describe('FactorsClient.remove', () => {
  it('omits force by default and sends force=true only when asked', async () => {
    const fake = newFakeFetch({ body: { status: 'revoked' } });
    const c = make(fake);

    await c.factors.remove('f-1');
    expect(fake.calls[0]?.method).toBe('DELETE');
    // No stray ?force=false — the server tests for the literal string "true",
    // so anything else must simply be absent.
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/factors/f-1`);

    fake.respond({ body: { status: 'revoked' } });
    await c.factors.remove('f-1', true);
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/factors/f-1?force=true`);
  });

  it('surfaces the last-active-factor refusal', async () => {
    const fake = newFakeFetch({
      status: 409,
      body: { error: 'cannot revoke last active factor' },
    });
    const c = make(fake);

    await expect(c.factors.remove('f-1')).rejects.toMatchObject({ status: 409 });
  });
});

describe('FactorsClient.relabel', () => {
  it('PATCHes the factor with only the new label', async () => {
    const fake = newFakeFetch({ body: { factor: record({ label: 'renamed' }) } });
    const c = make(fake);

    const resp = await c.factors.relabel('f-1', { label: 'renamed' });

    // PATCH must survive the HttpMethod union — a narrowed union silently
    // broke this call once already.
    expect(fake.calls[0]?.method).toBe('PATCH');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/factors/f-1`);
    expect(fake.calls[0]?.body).toEqual({ label: 'renamed' });
    expect(resp.factor.label).toBe('renamed');
  });

  it('surfaces a rejected empty label', async () => {
    const fake = newFakeFetch({ status: 400, body: { error: 'rest: label is required' } });
    const c = make(fake);

    await expect(c.factors.relabel('f-1', { label: '' })).rejects.toMatchObject({ status: 400 });
  });
});

describe('FactorsClient.rotate', () => {
  it('takes the old factor from the path and the replacement from the body', async () => {
    const fake = newFakeFetch({ body: { new_factor: record({ id: 'f-2' }) } });
    const c = make(fake);

    const resp = await c.factors.rotate('f-1', {
      new_factor: { user_id: 42, type: 'fido2', label: 'new key', credential: 'bmV3' },
    });

    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/factors/f-1/rotate`);
    // old_factor_id is NOT sent — the handler overwrites it from the path.
    expect(fake.calls[0]?.body).toEqual({
      new_factor: { user_id: 42, type: 'fido2', label: 'new key', credential: 'bmV3' },
    });
    expect(resp.new_factor.id).toBe('f-2');
  });

  it('surfaces a rejected replacement missing its type', async () => {
    const fake = newFakeFetch({ status: 400, body: { error: 'rest: type is required' } });
    const c = make(fake);

    await expect(
      c.factors.rotate('f-1', { new_factor: { user_id: 42, type: '', credential: 'bmV3' } }),
    ).rejects.toMatchObject({ status: 400 });
  });
});

describe('FactorsClient.login', () => {
  it('posts the type and lookup key to the login route', async () => {
    const fake = newFakeFetch({
      body: { user_id: 42, username: 'alice', active: true, roles: ['admin'] },
    });
    const c = make(fake);

    const resp = await c.factors.login({ type: 'piv', lookup_key: 'bG9va3Vw' });

    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/factors/login`);
    expect(fake.calls[0]?.body).toEqual({ type: 'piv', lookup_key: 'bG9va3Vw' });
    expect(resp.username).toBe('alice');
    expect(resp.user_id).toBe(42);
  });

  it('surfaces an unresolvable credential', async () => {
    const fake = newFakeFetch({ status: 401, body: { error: 'no such factor' } });
    const c = make(fake);

    await expect(
      c.factors.login({ type: 'fido2', lookup_key: 'dW5rbm93bg==' }),
    ).rejects.toMatchObject({ status: 401 });
  });
});
