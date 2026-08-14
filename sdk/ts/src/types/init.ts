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

/** Init-ceremony DTOs. Mirrors pkg/api/rest/handlers_init.go. */

import type { Base64, RFC3339 } from './common.js';

export interface InitStatusResponse {
  state: string;
}

export interface ClaimCertBeginRequest {
  username: string;
}

export interface ClaimCertBeginResponse {
  nonce: string;
  username: string;
  expires_at: RFC3339;
}

export interface ClaimCertCompleteRequest {
  username: string;
  nonce: string;
  /** base64-encoded signature over the nonce */
  signature: Base64;
}

export interface ClaimCertCompleteResponse {
  cert_pem: string;
  ca_cert_pem: string;
}

export interface ClaimShareBeginRequest {
  username: string;
}

export interface ClaimShareBeginResponse {
  nonce: string;
  username: string;
  expires_at: RFC3339;
}

export interface ClaimShareCompleteRequest {
  username: string;
  nonce: string;
  /** base64-encoded signature over the nonce */
  signature: Base64;
}

export interface ClaimShareCompleteResponse {
  share_index: number;
  /** Opaque JSON share payload (json.RawMessage server-side). */
  share: unknown;
}

export interface SignCSRInitRequest {
  username: string;
  so_pin: string;
  csr_pem: string;
  role: string;
}

export interface SignCSRInitResponse {
  cert_pem: string;
}
