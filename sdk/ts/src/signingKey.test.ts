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
 * Wire-contract coverage for SigningKeyClient (repository signing-key
 * bindings, pkg/api/rest/handlers_signing_key.go): every method's verb,
 * path, query and body, and error propagation.
 */

import { describe, it, expect } from 'vitest';
import { createClient } from './client.js';
import { newFakeFetch } from './testutil.js';
import { XkmsApiError } from './errors.js';
import type { SigningKeyBinding } from './types/signingKey.js';

const BASE = 'https://xkms.example.com';
const COLLECTION = `${BASE}/api/v1/attestation/signing-keys`;

function make(fake: ReturnType<typeof newFakeFetch>) {
  return createClient({ baseURL: BASE, fetch: fake.fetch, token: () => 'tk' });
}

const binding: SigningKeyBinding = {
  repository: 'acme/app',
  key_id: 'app-release',
  updated_at: '2026-01-01T00:00:00Z',
};

describe('SigningKeyClient (wire contract)', () => {
  it('binds a repository with a PUT of the request', async () => {
    const fake = newFakeFetch({ body: binding });
    const bound = await make(fake).signingKeys.set({ repository: 'acme/app', key_id: 'app-release' });
    expect(fake.calls[0]?.method).toBe('PUT');
    expect(fake.calls[0]?.url).toBe(COLLECTION);
    expect(fake.calls[0]?.body).toEqual({ repository: 'acme/app', key_id: 'app-release' });
    expect(bound.key_id).toBe('app-release');
  });

  it('gets, deletes and resolves by the repository query, escaping its slash', async () => {
    const fake = newFakeFetch({ body: binding });
    const c = make(fake);

    await c.signingKeys.get('acme/app');
    expect(fake.calls[0]?.method).toBe('GET');
    expect(fake.calls[0]?.url).toBe(`${COLLECTION}/binding?repository=acme%2Fapp`);

    fake.respond({ status: 204 });
    await c.signingKeys.delete('acme/app');
    expect(fake.calls[1]?.method).toBe('DELETE');
    expect(fake.calls[1]?.url).toBe(`${COLLECTION}/binding?repository=acme%2Fapp`);

    fake.respond({ body: { repository: 'acme/app', key_id: 'release', default: true } });
    const resolved = await c.signingKeys.resolve('acme/app');
    expect(fake.calls[2]?.method).toBe('GET');
    expect(fake.calls[2]?.url).toBe(`${COLLECTION}/resolve?repository=acme%2Fapp`);
    expect(resolved.default).toBe(true);
  });

  it('lists the tenant\'s bindings', async () => {
    const fake = newFakeFetch({ body: { bindings: [binding] } });
    const list = await make(fake).signingKeys.list();
    expect(fake.calls[0]?.method).toBe('GET');
    expect(fake.calls[0]?.url).toBe(COLLECTION);
    expect(list.bindings[0]?.repository).toBe('acme/app');
  });

  it('rejects with the server\'s status and message', async () => {
    const fake = newFakeFetch({ status: 404, body: { error: 'record not found' } });
    const c = make(fake);
    const err = await c.signingKeys.get('acme/app').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(404);

    fake.respond({ status: 403, body: { error: 'forbidden' } });
    const delErr = await c.signingKeys.delete('acme/app').catch((e: unknown) => e);
    expect(delErr).toBeInstanceOf(XkmsApiError);
    expect((delErr as XkmsApiError).status).toBe(403);
  });
});
