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
 * The attestation Verifier (go-xkms#1608): a tenant's trust anchors, its
 * signed reference values, and the appraisal of a TPM quote against them.
 * Mirrors pkg/attestation/appraisal/verifier.go.
 */

import type { Base64, RFC3339 } from './common.js';

/**
 * What an endorsement anchors: "ak-root" for attestation-key certificate
 * chains, "reference-signer" for reference-value signers.
 */
export type EndorsementKind = 'ak-root' | 'reference-signer';

/** Mirrors transport.AttestationEndorsement: a stored trust anchor. */
export interface AttestationEndorsement {
  name: string;
  kind: EndorsementKind;
  certificate_pem?: Base64;
  public_key_pem?: Base64;
  created_at: RFC3339;
}

/** Mirrors transport.PutAttestationEndorsementRequest: a certificate or a public key. */
export interface PutAttestationEndorsementRequest {
  name: string;
  kind: EndorsementKind;
  certificate_pem?: Base64;
  public_key_pem?: Base64;
}

/** Mirrors transport.ListAttestationEndorsementsResponse. */
export interface ListAttestationEndorsementsResponse {
  endorsements: AttestationEndorsement[];
}

/** Mirrors transport.AttestationReferenceValues: a stored, verified CoRIM. */
export interface AttestationReferenceValues {
  name: string;
  manifest_id: string;
  profile?: string;
  signer?: string;
  /** The repository whose signing key verified the CoRIM, when it has one. */
  repository?: string;
  not_before?: RFC3339;
  not_after?: RFC3339;
  /** The PCR indices the reference values cover, ascending. */
  pcr_indices: number[];
  stored_at: RFC3339;
  /** The COSE_Sign1 signed CoRIM as stored. */
  signed_corim?: Base64;
}

/** Mirrors transport.PutAttestationReferenceValuesRequest. */
export interface PutAttestationReferenceValuesRequest {
  name: string;
  /** A COSE_Sign1 signed CoRIM. */
  signed_corim: Base64;
  /**
   * The OCI repository the reference values belong to. They then verify
   * under its signing key rather than the reference-signer endorsements.
   */
  repository?: string;
}

/** Mirrors transport.ListAttestationReferenceValuesResponse. */
export interface ListAttestationReferenceValuesResponse {
  reference_values: AttestationReferenceValues[];
}

/** Mirrors transport.AppraiseAttestationQuoteRequest: a TPM quote and its context. */
export interface AppraiseAttestationQuoteRequest {
  /** The attestation-key certificate, leaf first, then any intermediates. */
  ak_certificate_pem: Base64;
  /** The marshaled TPMS_ATTEST. */
  quote: Base64;
  /** The attestation key's signature over quote. */
  signature: Base64;
  /** The verifier-issued qualifying data the quote must carry. */
  nonce: Base64;
  /** The PCR values the attester read, keyed by PCR index. */
  pcrs: Record<string, Base64>;
  /** The TCG crypto-agile event log. */
  event_log?: Base64;
  /** The name of the stored reference values to compare against. */
  reference_values: string;
}

/** Mirrors appraisal.AppraisalOutcome. */
export type AppraisalOutcome = 'pass' | 'forged' | 'absent' | 'skipped';

/** Mirrors transport.AppraisalCheck: one check's outcome. */
export interface AppraisalCheck {
  name: string;
  outcome: AppraisalOutcome;
  reason?: string;
}

/** Mirrors transport.AttestationResult: the outcome of an appraisal. */
export interface AttestationResult {
  /** True only when every check that ran passed and none was absent. */
  verified: boolean;
  /** True when a check found evidence that was present and wrong. */
  cryptographic_failure: boolean;
  /** Each check's outcome, in evaluation order. */
  checks: AppraisalCheck[];
  reference_values?: string;
  manifest_id?: string;
  signer?: string;
  baseline_source?: string;
  appraised_at: RFC3339;
}
