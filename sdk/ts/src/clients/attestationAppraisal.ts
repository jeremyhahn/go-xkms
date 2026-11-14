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

import type { HttpCore } from '../http.js';
import { encodePathSegment } from '../http.js';
import type {
  AppraiseAttestationQuoteRequest,
  AttestationEndorsement,
  AttestationReferenceValues,
  AttestationResult,
  EndorsementKind,
  ListAttestationEndorsementsResponse,
  ListAttestationReferenceValuesResponse,
  PutAttestationEndorsementRequest,
  PutAttestationReferenceValuesRequest,
} from '../types/attestationAppraisal.js';

const ENDORSEMENTS = '/api/v1/attestation/endorsements';
const REFERENCE_VALUES = '/api/v1/attestation/reference-values';
const APPRAISE = '/api/v1/attestation/appraise';

/**
 * The attestation Verifier of the caller's tenant (go-xkms#1608): trust
 * anchors, signed reference values and quote appraisal. Mirrors
 * pkg/api/rest/handlers_attestation_appraisal.go.
 */
export class AttestationAppraisalClient {
  constructor(private readonly http: HttpCore) {}

  /** PUT /api/v1/attestation/endorsements — stores a trust anchor. */
  putEndorsement(req: PutAttestationEndorsementRequest): Promise<AttestationEndorsement> {
    return this.http.request('PUT', ENDORSEMENTS, { body: req });
  }

  /** GET /api/v1/attestation/endorsements?kind= — the tenant's trust anchors, of one kind when given. */
  listEndorsements(kind?: EndorsementKind): Promise<ListAttestationEndorsementsResponse> {
    return this.http.request('GET', ENDORSEMENTS, { query: { kind } });
  }

  /** DELETE /api/v1/attestation/endorsements/{name} (204). */
  async deleteEndorsement(name: string): Promise<void> {
    await this.http.request<void>('DELETE', `${ENDORSEMENTS}/${encodePathSegment(name)}`);
  }

  /** PUT /api/v1/attestation/reference-values — verifies and stores a signed CoRIM. */
  putReferenceValues(req: PutAttestationReferenceValuesRequest): Promise<AttestationReferenceValues> {
    return this.http.request('PUT', REFERENCE_VALUES, { body: req });
  }

  /** GET /api/v1/attestation/reference-values/{name}. */
  getReferenceValues(name: string): Promise<AttestationReferenceValues> {
    return this.http.request('GET', `${REFERENCE_VALUES}/${encodePathSegment(name)}`);
  }

  /** GET /api/v1/attestation/reference-values — the tenant's reference values. */
  listReferenceValues(): Promise<ListAttestationReferenceValuesResponse> {
    return this.http.request('GET', REFERENCE_VALUES);
  }

  /** DELETE /api/v1/attestation/reference-values/{name} (204). */
  async deleteReferenceValues(name: string): Promise<void> {
    await this.http.request<void>('DELETE', `${REFERENCE_VALUES}/${encodePathSegment(name)}`);
  }

  /** POST /api/v1/attestation/appraise — appraises a TPM quote against stored reference values. */
  appraiseQuote(req: AppraiseAttestationQuoteRequest): Promise<AttestationResult> {
    return this.http.request('POST', APPRAISE, { body: req });
  }
}
