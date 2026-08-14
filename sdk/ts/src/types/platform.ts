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

/** Sealed platform store DTOs. Mirrors pkg/api/rest/seal_store_handlers.go. */

import type { Base64 } from './common.js';

export interface SealStorePutRequest {
  name: string;
  /** base64-encoded secret bytes */
  secret: Base64;
}

export interface SealStorePutResponse {
  name: string;
  message: string;
}

export interface SealStoreGetResponse {
  name: string;
  /** base64-encoded secret bytes */
  secret: Base64;
}

export interface SealStoreListResponse {
  names: string[];
  total: number;
}

export interface SealStoreDeleteResponse {
  message: string;
}

export interface SealStoreResealResponse {
  name: string;
  message: string;
}

export interface SealStoreStatusResponse {
  available: boolean;
  names: string[];
  total: number;
}
