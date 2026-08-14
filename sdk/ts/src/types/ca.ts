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

/**
 * CA and TCG DTOs. The REST CA handlers (pkg/api/rest/handlers_ca.go,
 * handlers_ca_tcg.go) decode and encode pkg/api/transport/types.go shapes
 * directly.
 */

import type { Base64 } from './common.js';

export interface GetCABundleResponse {
  bundle_pem: Base64;
  certificates: Base64[];
  content_type: string;
}

export interface GetCACertificateResponse {
  certificate_pem: Base64;
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  is_ca: boolean;
}

export interface SignCSRRequest {
  csr_pem: Base64;
  profile?: string;
  validity_days?: number;
  tenant_id?: string;
  attestation_format?: string;
  attestation_chain?: Base64[];
  attestation_data?: Base64;
  attestation_sig?: Base64;
  attestation_nonce?: Base64;
}

export interface SignCSRResponse {
  certificate_pem: Base64;
  chain_pem: Base64;
  serial_number: string;
}

export interface IssueCertificateRequest {
  profile: string;
  common_name: string;
  organization?: string;
  sans?: string[];
  validity_days?: number;
  algorithm?: string;
  tenant_id?: string;
}

export interface IssueCertificateResponse {
  certificate_pem: Base64;
  chain_pem: Base64;
  private_key_pem?: Base64;
  serial_number: string;
}

export interface RevokeCertificateRequest {
  serial_number: string;
  reason: number;
  tenant_id?: string;
}

export interface RevokeCertificateResponse {
  success: boolean;
  message?: string;
}

export interface GenerateCRLRequest {
  tenant_id?: string;
}

export interface GenerateCRLResponse {
  crl_pem: Base64;
}

export interface IsRevokedResponse {
  revoked: boolean;
  reason?: number;
  message?: string;
}

export interface IssueEKCertificateRequest {
  common_name: string;
  organization?: string;
  ek_public_key: Base64;
  tenant_id?: string;
}

export interface IssueEKCertificateResponse {
  certificate_der: Base64;
  certificate_pem: Base64;
  serial_number: string;
}

export interface IssueAKCertificateRequest {
  common_name: string;
  organization?: string;
  public_key: Base64;
  tenant_id?: string;
}

export interface IssueAKCertificateResponse {
  certificate_der: Base64;
  certificate_pem: Base64;
  serial_number: string;
}

export interface SignTCGCSRRequest {
  common_name: string;
  organization?: string;
  tcg_csr: Base64;
  tenant_id?: string;
}

export interface SignTCGCSRResponse {
  iak_cert_der: Base64;
  idevid_cert_der: Base64;
}

export interface EnrollDeviceRequest {
  common_name: string;
  organization?: string;
  packed_csr: Base64;
  tenant_id?: string;
}

export interface EnrollDeviceResponse {
  iak_cert_der: Base64;
  idevid_cert_der: Base64;
  credential_blob: Base64;
  encrypted_secret: Base64;
  plain_secret: Base64;
}
