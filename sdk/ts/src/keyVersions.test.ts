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
 * keyVersions.test.ts — wire contract of the key-version client
 * (keys.versions) and of the key_version fields the crypto operations carry.
 */

import { describe, it, expect } from 'vitest';
import { createClient } from './client.js';
import { newFakeFetch } from './testutil.js';
import { XkmsApiError } from './errors.js';

const BASE = 'https://xkms.example.com';

function make(fake: ReturnType<typeof newFakeFetch>) {
  return createClient({ baseURL: BASE, fetch: fake.fetch, token: () => 'tk' });
}

describe('KeyVersionsClient (keys.versions)', () => {
  it('lists a key\'s versions with the backend query and escapes the key ID', async () => {
    const fake = newFakeFetch({
      body: {
        key_id: 'a b',
        backend: 'software',
        current_version: 2,
        versions: [
          { version: 1, state: 'disabled' },
          { version: 2, state: 'enabled', current: true },
        ],
      },
    });
    const listed = await make(fake).keys.versions.list('a b', 'software');
    expect(fake.calls[0]?.method).toBe('GET');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/keys/a%20b/versions?backend=software`);
    expect(listed.current_version).toBe(2);
    expect(listed.versions[1]?.current).toBe(true);
  });

  it('routes enable, disable and retire to the version path', async () => {
    const fake = newFakeFetch({ body: { key_id: 'k', version: 1, state: 'retired', changed: true } });
    const c = make(fake);
    await c.keys.versions.enable('k', 1, 'software');
    await c.keys.versions.disable('k', 1, 'software');
    const retired = await c.keys.versions.retire('k', 1, 'software');
    expect(fake.calls.map((call) => [call.method, call.url])).toEqual([
      ['POST', `${BASE}/api/v1/keys/k/versions/1/enable?backend=software`],
      ['POST', `${BASE}/api/v1/keys/k/versions/1/disable?backend=software`],
      ['POST', `${BASE}/api/v1/keys/k/versions/1/retire?backend=software`],
    ]);
    expect(retired.state).toBe('retired');
  });

  it('routes enableAll and disableAll', async () => {
    const fake = newFakeFetch({ body: { key_id: 'k', state: 'disabled', versions: [1], count: 1 } });
    const c = make(fake);
    await c.keys.versions.enableAll('k', 'software');
    const all = await c.keys.versions.disableAll('k', 'software');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/keys/k/versions/enable-all?backend=software`);
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/keys/k/versions/disable-all?backend=software`);
    expect(all.versions).toEqual([1]);
  });

  it('rotateAll sends the tenant only when one is named', async () => {
    const fake = newFakeFetch({ body: { tenant_id: 'acme', results: [], rotated: 0, failed: 0 } });
    const c = make(fake);
    await c.keys.versions.rotateAll('acme');
    await c.keys.versions.rotateAll();
    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/keys/rotate-all`);
    expect(fake.calls[0]?.body).toEqual({ tenant_id: 'acme' });
    expect(fake.calls[1]?.body).toEqual({});
  });

  it('surfaces a current-version refusal as XkmsApiError 409', async () => {
    const fake = newFakeFetch({
      status: 409,
      body: { error: 'cannot disable version 2 of key "k": it is the current version', code: 409 },
    });
    const err = await make(fake).keys.versions.disable('k', 2, 'software').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(409);
  });

  it('surfaces a decrypt that needs key_version as XkmsApiError 400', async () => {
    const fake = newFakeFetch({ status: 400, body: { error: 'key_version is required', code: 400 } });
    const err = await make(fake).keys.decrypt('k', { ciphertext: 'Y3Q=', mode: 'cbc-pad', iv: 'aXY=' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(400);
  });
});

describe('key_version on the crypto operations', () => {
  it('sends key_version on verify and decrypt and reads it back', async () => {
    const fake = newFakeFetch({ body: { valid: true, key_version: 1 } });
    const c = make(fake);
    const verified = await c.keys.verify('k', { backend: 'software', data: 'ZA==', signature: 'c2ln', key_version: 1 });
    expect(fake.calls[0]?.body).toMatchObject({ key_version: 1 });
    expect(verified.key_version).toBe(1);

    fake.respond({ body: { plaintext: 'cA==', key_version: 1 } });
    const dec = await c.keys.decrypt('k', { ciphertext: 'Y3Q=', key_version: 1 });
    expect(fake.calls[1]?.body).toMatchObject({ key_version: 1 });
    expect(dec.key_version).toBe(1);
  });

  it('reads the version sign, encrypt and rotate report', async () => {
    const fake = newFakeFetch({ body: { signature: 'c2ln', key_version: 2 } });
    const c = make(fake);
    expect((await c.keys.sign('k', { backend: 'software', data: 'ZA==' })).key_version).toBe(2);
    fake.respond({ body: { ciphertext: 'Y3Q=', nonce: '', tag: '', key_version: 2 } });
    expect((await c.keys.encrypt('k', { plaintext: 'cA==' })).key_version).toBe(2);
    fake.respond({ body: { success: true, key_id: 'k', key_type: 'SIGNING', key_version: 3 } });
    expect((await c.keys.rotate('k', 'software')).key_version).toBe(3);
  });
});
