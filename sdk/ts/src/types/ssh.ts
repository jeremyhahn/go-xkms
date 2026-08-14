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
 * SSH DTOs for the REST routes under /xkms/v1/ssh. Mirrors
 * sdk/go/client/ssh/types.go and the REST-local wire shapes in
 * pkg/api/rest/handlers_ssh.go.
 */

import type { Base64, RFC3339 } from './common.js';

/** Mirrors sdk/go/client/ssh types.go Key. */
export interface SSHKey {
  scope: string;
  owner: string;
  name: string;
  algorithm: string;
  public_key: string;
  fingerprint: string;
  created_at: RFC3339;
  comment?: string;
  backend?: string;
  backend_key_id?: string;
}

/** Mirrors sdk/go/client/ssh types.go PublicKey (export-public response). */
export interface SSHPublicKey {
  algorithm: string;
  line: string;
  fingerprint: string;
}

/** Mirrors sdk/go/client/ssh types.go Pin (known-host pin). */
export interface SSHPin {
  scope: string;
  owner: string;
  host: string;
  fingerprint: string;
  algorithm?: string;
  added_at: RFC3339;
  source?: string;
}

/** Mirrors sdk/go/client/ssh types.go AuthorizedEntry. */
export interface SSHAuthorizedEntry {
  scope: string;
  owner: string;
  name: string;
  line: string;
  options?: string[];
  comment?: string;
}

/** Mirrors sdk/go/client/ssh types.go GenerateRequest. */
export interface SSHGenerateKeyRequest {
  scope: string;
  owner: string;
  name: string;
  algorithm: string;
  rsa_bits?: number;
  comment?: string;
  backend?: string;
}

/** Mirrors pkg/api/rest/handlers_ssh.go restImportDTO. */
export interface SSHImportKeyRequest {
  scope: string;
  owner: string;
  name: string;
  comment?: string;
  /** base64-encoded PEM bytes */
  pem: Base64;
  /** base64-encoded passphrase (decoded server-side into a secure buffer) */
  passphrase_b64?: Base64;
}

/** Mirrors pkg/api/rest/handlers_ssh.go restSignRequestDTO. */
export interface SSHSignRequest {
  /** base64-encoded digest bytes */
  digest: Base64;
}

/** Mirrors pkg/api/rest/handlers_ssh.go restSignResponseDTO. */
export interface SSHSignResponse {
  format: string;
  blob: Base64;
  rest?: Base64;
}

/** Mirrors sdk/go/client/ssh types.go AddKnownHostRequest. */
export interface SSHAddKnownHostRequest {
  scope: string;
  owner: string;
  host: string;
  fingerprint: string;
  algorithm?: string;
  source?: string;
}

/** Mirrors pkg/api/rest/handlers_ssh.go restVerifyRequestDTO. */
export interface SSHVerifyKnownHostRequest {
  scope: string;
  owner: string;
  fingerprint: string;
  algorithm?: string;
}

/** Mirrors sdk/go/client/ssh types.go AddAuthorizedKeyRequest. */
export interface SSHAddAuthorizedKeyRequest {
  scope: string;
  owner: string;
  name: string;
  line: string;
  options?: string[];
}

/** Mirrors sdk/go/client/ssh types.go EmitRequest. */
export interface SSHEmitRequest {
  public_key: string;
  options?: string[];
  comment?: string;
}

/** Mirrors pkg/api/rest/handlers_ssh.go restEmitResponseDTO. */
export interface SSHEmitResponse {
  line: string;
}

/** Mirrors pkg/api/rest/handlers_ssh.go restAuthVerifyRequestDTO. */
export interface SSHVerifyAuthorizedRequest {
  scope: string;
  owner: string;
  fingerprint: string;
  algorithm?: string;
}

/** List envelopes ({items: [...]}) used by the SSH list routes. */
export interface SSHKeyListResponse {
  items: SSHKey[];
}
export interface SSHPinListResponse {
  items: SSHPin[];
}
export interface SSHAuthorizedListResponse {
  items: SSHAuthorizedEntry[];
}

