// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

import type { PageResponse } from './common.js';

/** Mirrors pkg/api/rest/types.go SaveCertRequest. */
export interface SaveCertRequest {
  backend?: string;
  certificate_pem: string;
}

/** Mirrors pkg/api/rest/types.go GetCertResponse. */
export interface GetCertResponse {
  key_id: string;
  certificate_pem: string;
}

/** Mirrors pkg/api/rest/types.go CertificateInfo. */
export interface CertificateInfo {
  key_id: string;
  subject?: string;
  issuer?: string;
  not_before?: string;
  not_after?: string;
  serial_number?: string;
  certificate_pem?: string;
}

/** Mirrors pkg/api/rest/types.go ListCertsResponse. */
export interface ListCertsResponse {
  certificates: CertificateInfo[];
  pagination: PageResponse;
}

/** Mirrors pkg/api/rest/types.go SaveCertChainRequest. */
export interface SaveCertChainRequest {
  backend?: string;
  cert_chain_pem: string[];
}

/** Mirrors pkg/api/rest/types.go GetCertChainResponse. */
export interface GetCertChainResponse {
  key_id: string;
  cert_chain_pem: string[];
}

/** Mirrors pkg/api/rest/types.go GetTLSCertificateResponse (GET /api/v1/tls/{id}). */
export interface GetTLSCertificateResponse {
  key_id: string;
  certificate_pem: string;
  chain_pem?: string[];
}
