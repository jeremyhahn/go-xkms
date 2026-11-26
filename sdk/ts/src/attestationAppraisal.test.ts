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
 * Wire-contract coverage for AttestationAppraisalClient (the attestation
 * Verifier, pkg/api/rest/handlers_attestation_appraisal.go): every method's
 * verb, path, query and body, and error propagation.
 */

import { describe, it, expect } from 'vitest';
import { createClient } from './client.js';
import { newFakeFetch } from './testutil.js';
import { XkmsApiError } from './errors.js';
import { encodePathSegment } from './http.js';
import { AttestationNameError } from './clients/attestationAppraisal.js';
import type { AppraiseAttestationQuoteRequest, AttestationEndorsement } from './types/attestationAppraisal.js';

const BASE = 'https://xkms.example.com';
const ENDORSEMENTS = `${BASE}/api/v1/attestation/endorsements`;
const REFERENCE_VALUES = `${BASE}/api/v1/attestation/reference-values`;

function make(fake: ReturnType<typeof newFakeFetch>) {
  return createClient({ baseURL: BASE, fetch: fake.fetch, token: () => 'tk' });
}

const endorsement: AttestationEndorsement = {
  name: 'ak-ca',
  kind: 'ak-root',
  certificate_pem: 'LS0tLS1CRUdJTg==',
  created_at: '2026-01-01T00:00:00Z',
};

describe('AttestationAppraisalClient (wire contract)', () => {
  it('stores, lists and deletes endorsements', async () => {
    const fake = newFakeFetch({ body: endorsement });
    const c = make(fake);

    const stored = await c.attestation.putEndorsement({
      name: 'ak-ca',
      kind: 'ak-root',
      certificate_pem: 'LS0tLS1CRUdJTg==',
    });
    expect(fake.calls[0]?.method).toBe('PUT');
    expect(fake.calls[0]?.url).toBe(ENDORSEMENTS);
    expect(fake.calls[0]?.body).toEqual({ name: 'ak-ca', kind: 'ak-root', certificate_pem: 'LS0tLS1CRUdJTg==' });
    expect(stored.kind).toBe('ak-root');

    fake.respond({ body: { endorsements: [endorsement] } });
    const roots = await c.attestation.listEndorsements('ak-root');
    expect(fake.calls[1]?.method).toBe('GET');
    expect(fake.calls[1]?.url).toBe(`${ENDORSEMENTS}?kind=ak-root`);
    expect(roots.endorsements[0]?.name).toBe('ak-ca');

    fake.respond({ body: { endorsements: [] } });
    await c.attestation.listEndorsements();
    expect(fake.calls[2]?.url).toBe(ENDORSEMENTS);

    fake.respond({ status: 204 });
    await c.attestation.deleteEndorsement('ak ca/1');
    expect(fake.calls[3]?.method).toBe('DELETE');
    expect(fake.calls[3]?.url).toBe(`${ENDORSEMENTS}/ak%20ca%2F1`);
  });

  it('stores, gets, lists and deletes reference values', async () => {
    const golden = { name: 'golden', manifest_id: 'm-1', pcr_indices: [0, 4, 7], stored_at: '2026-01-01T00:00:00Z' };
    const fake = newFakeFetch({ body: golden });
    const c = make(fake);

    await c.attestation.putReferenceValues({ name: 'golden', signed_corim: 'AAEC', repository: 'acme/app' });
    expect(fake.calls[0]?.method).toBe('PUT');
    expect(fake.calls[0]?.url).toBe(REFERENCE_VALUES);
    expect(fake.calls[0]?.body).toEqual({ name: 'golden', signed_corim: 'AAEC', repository: 'acme/app' });

    const got = await c.attestation.getReferenceValues('golden');
    expect(fake.calls[1]?.method).toBe('GET');
    expect(fake.calls[1]?.url).toBe(`${REFERENCE_VALUES}/golden`);
    expect(got.pcr_indices).toEqual([0, 4, 7]);

    fake.respond({ body: { reference_values: [golden] } });
    const listed = await c.attestation.listReferenceValues();
    expect(fake.calls[2]?.url).toBe(REFERENCE_VALUES);
    expect(listed.reference_values[0]?.manifest_id).toBe('m-1');

    fake.respond({ status: 204 });
    await c.attestation.deleteReferenceValues('golden');
    expect(fake.calls[3]?.method).toBe('DELETE');
    expect(fake.calls[3]?.url).toBe(`${REFERENCE_VALUES}/golden`);
  });

  it('refuses the names "." and ".." before any fetch', async () => {
    // Request normalizes dot segments, so an encoded ".." would leave the
    // record collection and address /api/v1/attestation/ instead.
    expect(new Request(`${ENDORSEMENTS}/${encodePathSegment('..')}`).url).toBe(`${BASE}/api/v1/attestation/`);
    expect(new Request(`${REFERENCE_VALUES}/${encodePathSegment('.')}`).url).toBe(`${REFERENCE_VALUES}/`);

    const fake = newFakeFetch({ status: 204 });
    const c = make(fake);
    for (const name of ['.', '..']) {
      for (const call of [
        () => c.attestation.deleteEndorsement(name),
        () => c.attestation.getReferenceValues(name),
        () => c.attestation.deleteReferenceValues(name),
      ]) {
        const err = await call().catch((e: unknown) => e);
        expect(err).toBeInstanceOf(AttestationNameError);
        expect((err as AttestationNameError).recordName).toBe(name);
      }
    }
    expect(fake.calls).toHaveLength(0);
  });

  it('appraises a quote with a POST of the evidence', async () => {
    const quote: AppraiseAttestationQuoteRequest = {
      ak_certificate_pem: 'LS0t',
      quote: '/1RDRw==',
      signature: 'AAE=',
      nonce: 'bm9uY2U=',
      pcrs: { '0': 'AA==', '7': 'Bw==' },
      reference_values: 'golden',
    };
    const fake = newFakeFetch({
      body: {
        verified: true,
        cryptographic_failure: false,
        checks: [{ name: 'quote-signature', outcome: 'pass' }],
        reference_values: 'golden',
        appraised_at: '2026-01-01T00:00:00Z',
      },
    });
    const result = await make(fake).attestation.appraiseQuote(quote);
    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/attestation/appraise`);
    expect(fake.calls[0]?.body).toEqual(quote);
    expect(result.verified).toBe(true);
    expect(result.checks[0]?.outcome).toBe('pass');
  });

  it('rejects with the server\'s status and message', async () => {
    const fake = newFakeFetch({ status: 404, body: { error: 'record not found' } });
    const c = make(fake);
    const err = await c.attestation.getReferenceValues('absent').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(404);

    fake.respond({ status: 503, body: { error: 'attestation verifier unavailable' } });
    const appraiseErr = await c.attestation
      .appraiseQuote({ ak_certificate_pem: '', quote: '', signature: '', nonce: '', pcrs: {}, reference_values: 'golden' })
      .catch((e: unknown) => e);
    expect(appraiseErr).toBeInstanceOf(XkmsApiError);
    expect((appraiseErr as XkmsApiError).status).toBe(503);
  });
});
