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

/** PIV smart-card DTOs. Mirrors pkg/api/transport/types.go PIV shapes. */

import type { Base64 } from './common.js';

export interface PIVSlotStatus {
  slot: string;
  name: string;
  description: string;
  has_cert: boolean;
  has_key: boolean;
  subject?: string;
  issuer?: string;
  algorithm?: string;
  key_size?: number;
  not_after?: string;
  fingerprint?: string;
  backend?: string;
}

export interface ListPIVSlotsResponse {
  slots: PIVSlotStatus[];
  page: number;
  page_size: number;
  total: number;
  has_more: boolean;
}

export interface GetPIVCertificateResponse {
  slot: string;
  certificate: Base64;
  format: string;
}

/** Body for POST /piv/slots/{slot}/certificate and /import. */
export interface StorePIVCertificateRequest {
  backend?: string;
  slot?: string;
  certificate: Base64;
  format: string;
  tenant_id?: string;
}

export interface GeneratePIVKeyRequest {
  backend?: string;
  slot?: string;
  algorithm: string;
  subject: string;
  organization?: string;
  country?: string;
  output_format?: string;
  validity_days?: number;
  tenant_id?: string;
}

export interface GeneratePIVKeyResponse {
  slot: string;
  certificate: Base64;
  public_key: Base64;
  csr?: Base64;
  chain_pem?: Base64;
}

export interface GeneratePIVCSRRequest {
  backend?: string;
  slot?: string;
  subject: string;
  organization?: string;
  organizational_unit?: string;
  country?: string;
  state?: string;
  locality?: string;
  tenant_id?: string;
}

export interface GeneratePIVCSRResponse {
  slot: string;
  csr: Base64;
}
