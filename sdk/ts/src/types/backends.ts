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

/**
 * Mirrors pkg/types/types.go Capabilities. The Go struct has no json tags,
 * so members marshal under their exported (PascalCase) field names.
 */
export interface BackendCapabilities {
  Keys: boolean;
  HardwareBacked: boolean;
  Signing: boolean;
  Decryption: boolean;
  KeyRotation: boolean;
  SymmetricEncryption: boolean;
  Sealing: boolean;
  Import: boolean;
  Export: boolean;
  KeyAgreement: boolean;
  ECIES: boolean;
  Attestation: boolean;
  QuantumSigning: boolean;
  KeyEncapsulation: boolean;
}

/** Mirrors pkg/api/rest/types.go BackendInfo. */
export interface BackendInfo {
  id: string;
  type: string;
  hardware_backed: boolean;
  capabilities: BackendCapabilities;
}

/** Mirrors pkg/api/rest/types.go ListBackendsResponse. */
export interface ListBackendsResponse {
  backends: BackendInfo[];
  pagination: PageResponse;
}
