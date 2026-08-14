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

/** Credential-service DTOs. Mirrors pkg/api/rest/handlers_credentials.go. */

import type { Base64 } from './common.js';

export interface CredentialSubmitRequest {
  name: string;
  /** base64-encoded credential value */
  value: Base64;
}

export interface CredentialSubmitResponse {
  status: string;
}

export interface CredentialStrategyResponse {
  strategy: string;
  auto_unseal: boolean;
}
