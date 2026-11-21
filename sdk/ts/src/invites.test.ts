import { describe, it, expect } from 'vitest';
import { createClient } from './client.js';
import { newFakeFetch } from './testutil.js';

const BASE = 'https://xkms.test';

function make(fake: ReturnType<typeof newFakeFetch>) {
  return createClient({ baseURL: BASE, fetch: fake.fetch, token: () => 'tk' });
}

describe('InvitesClient', () => {
  it('reads an invite without a bearer token, escaping the path', async () => {
    const fake = newFakeFetch({ body: { email: 'a@b.c', expires_at: 'x', methods: ['webauthn'] } });
    const info = await make(fake).invites.get('t 1', 'a/b');
    expect(info.email).toBe('a@b.c');
    expect(fake.calls[0].method).toBe('GET');
    expect(fake.calls[0].url).toBe(`${BASE}/api/v1/invites/t%201/a%2Fb`);
    expect(fake.calls[0].headers.Authorization).toBeUndefined();
  });

  it('begins registration and parses options_json into the envelope', async () => {
    const fake = newFakeFetch({
      body: { session_id: 's1', options_json: JSON.stringify({ publicKey: { challenge: 'c' } }) },
    });
    const start = await make(fake).invites.beginRegistration('t1', 'tok');
    expect(start).toEqual({ sessionId: 's1', options: { publicKey: { challenge: 'c' } } });
    expect(fake.calls[0].method).toBe('POST');
    expect(fake.calls[0].url).toBe(`${BASE}/api/v1/invites/t1/tok/fido2/begin`);
  });

  it('finishes registration with the session and the attestation as JSON text', async () => {
    const fake = newFakeFetch({ body: { user_id: '42' } });
    const cred = { id: 'c', rawId: 'c', type: 'public-key', response: {} } as never;
    const res = await make(fake).invites.finishRegistration('t1', 'tok', 's1', cred);
    expect(res.user_id).toBe('42');
    expect(fake.calls[0].url).toBe(`${BASE}/api/v1/invites/t1/tok/fido2/finish`);
    expect(fake.calls[0].body).toEqual({ session_id: 's1', attestation_json: JSON.stringify(cred) });
  });

  it('rejects an unusable link with status 404', async () => {
    const fake = newFakeFetch({ status: 404, body: { error: 'link is not valid' } });
    await expect(make(fake).invites.get('t1', 'tok')).rejects.toMatchObject({ status: 404 });
  });
});
