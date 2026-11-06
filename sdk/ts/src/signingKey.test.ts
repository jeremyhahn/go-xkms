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
import { XkmsApiError, XkmsInsecureTransportError, XkmsNetworkError } from './errors.js';
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

  it('signs a CoRIM with a POST of the request', async () => {
    const key = { repository: 'acme/app', key_id: 'release', default: true };
    const fake = newFakeFetch({ body: { key, corim: '0g==' } });
    const req = { repository: 'acme/app', corim: '2QH1oA==', signer_name: 'Acme' };
    const signed = await make(fake).signingKeys.signCoRIM(req);
    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(`${COLLECTION}/sign-corim`);
    expect(fake.calls[0]?.body).toEqual(req);
    expect(signed.key.key_id).toBe('release');
    expect(signed.corim).toBe('0g==');
  });

  it('rejects a refused CoRIM signing with the server\'s status', async () => {
    const fake = newFakeFetch({ status: 400, body: { error: 'malformed corim' } });
    const err = await make(fake)
      .signingKeys.signCoRIM({ repository: 'acme/app', corim: '/w==', signer_name: 'Acme' })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(400);
  });

  it('signs an image with a POST of the reference and registry credentials', async () => {
    const key = { repository: 'acme/app', key_id: 'release', default: true };
    const fake = newFakeFetch({
      body: {
        key,
        digest: 'sha256:abc',
        envelope: 'e30=',
        certificate: 'UEVN',
        referrer: 'sha256:def',
        referrer_indexed: true,
        attestation_tag: 'sha256-abc.att',
      },
    });
    const req = {
      reference: 'registry.example.com/acme/app:v1',
      registry: { username: 'ci', password: 'registry-password' },
    };
    const signed = await make(fake).signingKeys.signImage(req);
    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(`${COLLECTION}/sign-image`);
    expect(fake.calls[0]?.body).toEqual(req);
    expect(signed.key.key_id).toBe('release');
    expect(signed.digest).toBe('sha256:abc');
    expect(signed.referrer_indexed).toBe(true);
  });

  // Registry credentials cross only TLS (ruling 152), as in the Go transports.
  describe('signImage with registry credentials', () => {
    const credentialed = {
      reference: 'registry.example.com/acme/app:v1',
      registry: { username: 'ci', password: 'registry-password' },
    };
    const signedBody = {
      key: binding.key,
      digest: 'sha256:abc',
      referrer_indexed: true,
    };

    it('sends them to an https base URL and refuses redirects', async () => {
      const fake = newFakeFetch({ status: 200, body: signedBody });
      const signed = await make(fake).signingKeys.signImage(credentialed);
      expect(signed.digest).toBe('sha256:abc');
      expect(fake.calls).toHaveLength(1);
      expect(fake.calls[0]?.redirect).toBe('error');
    });

    it('refuses an http base URL before any request is sent', async () => {
      const fake = newFakeFetch({ status: 200, body: signedBody });
      const client = createClient({ baseURL: 'http://xkms.example.com', fetch: fake.fetch });
      const err = await client.signingKeys.signImage(credentialed).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(XkmsInsecureTransportError);
      expect((err as XkmsInsecureTransportError).url).toBe(
        'http://xkms.example.com/api/v1/attestation/signing-keys/sign-image',
      );
      expect(fake.calls).toHaveLength(0);
    });

    it('fails a redirect to http rather than replay them', async () => {
      const fake = newFakeFetch({
        status: 200,
        body: signedBody,
        redirectTo: 'http://attacker.example.com/sign-image',
      });
      const err = await make(fake).signingKeys.signImage(credentialed).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(XkmsNetworkError);
      expect(fake.calls.map((c) => c.url)).toEqual([`${COLLECTION}/sign-image`]);
    });

    it('goes to http and follows redirects only when allowInsecureTransport is set', async () => {
      const fake = newFakeFetch({ status: 200, body: signedBody });
      const client = createClient({
        baseURL: 'http://127.0.0.1:8080',
        fetch: fake.fetch,
        allowInsecureTransport: true,
      });
      await client.signingKeys.signImage(credentialed);
      expect(fake.calls[0]?.url).toBe('http://127.0.0.1:8080/api/v1/attestation/signing-keys/sign-image');
      expect(fake.calls[0]?.redirect).toBeUndefined();
    });

    it('leaves a request without credentials unrestricted', async () => {
      const fake = newFakeFetch({ status: 200, body: signedBody });
      const client = createClient({ baseURL: 'http://xkms.example.com', fetch: fake.fetch });
      await client.signingKeys.signImage({ reference: credentialed.reference });
      expect(fake.calls).toHaveLength(1);
      expect(fake.calls[0]?.redirect).toBeUndefined();
    });
  });

  it('rejects a refused image signing with the server\'s status', async () => {
    const fake = newFakeFetch({ status: 503, body: { error: 'service unavailable' } });
    const err = await make(fake)
      .signingKeys.signImage({ reference: 'registry.example.com/acme/app:v1' })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(503);
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
