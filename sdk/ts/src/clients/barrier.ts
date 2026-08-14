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

import type { HttpCore } from '../http.js';
import type { SuccessResponse } from '../types/common.js';
import type {
  BarrierEnableEncryptionRequest,
  BarrierEnableEncryptionResponse,
  BarrierGenerateRecoveryKeysRequest,
  BarrierGenerateRootTokenRequest,
  BarrierInitializeRequest,
  BarrierInitializeShamirRequest,
  BarrierRecoverWithKeysRequest,
  BarrierRekeyRequest,
  BarrierStatusResponse,
  BarrierUnsealRequest,
  BarrierUnsealShareRequest,
  BarrierUnsealSharesRequest,
  QuorumProgress,
  RecoveryKeyResult,
  RootToken,
  ShamirInitParams,
  ShamirInitResult,
} from '../types/barrier.js';

const BASE = '/api/v1/barrier';

/** System barrier lifecycle (initialize / seal / unseal / Shamir / recovery). */
export class BarrierClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/barrier/initialize */
  initialize(req: BarrierInitializeRequest): Promise<SuccessResponse> {
    return this.http.request('POST', `${BASE}/initialize`, { body: req });
  }

  /** POST /api/v1/barrier/unseal */
  unseal(req: BarrierUnsealRequest): Promise<SuccessResponse> {
    return this.http.request('POST', `${BASE}/unseal`, { body: req });
  }

  /** POST /api/v1/barrier/seal */
  seal(): Promise<SuccessResponse> {
    return this.http.request('POST', `${BASE}/seal`);
  }

  /** GET /api/v1/barrier/status */
  status(): Promise<BarrierStatusResponse> {
    return this.http.request('GET', `${BASE}/status`);
  }

  /** POST /api/v1/barrier/shamir/initialize */
  shamirInitialize(req: BarrierInitializeShamirRequest): Promise<ShamirInitResult> {
    return this.http.request('POST', `${BASE}/shamir/initialize`, { body: req });
  }

  /** POST /api/v1/barrier/shamir/unseal-share (stateful quorum accumulation). */
  shamirUnsealShare(req: BarrierUnsealShareRequest): Promise<QuorumProgress> {
    return this.http.request('POST', `${BASE}/shamir/unseal-share`, { body: req });
  }

  /** POST /api/v1/barrier/shamir/unseal-shares (stateless batch unseal). */
  shamirUnsealShares(req: BarrierUnsealSharesRequest): Promise<SuccessResponse> {
    return this.http.request('POST', `${BASE}/shamir/unseal-shares`, { body: req });
  }

  /** POST /api/v1/barrier/rekey */
  rekey(req: BarrierRekeyRequest): Promise<ShamirInitParams> {
    return this.http.request('POST', `${BASE}/rekey`, { body: req });
  }

  /** POST /api/v1/barrier/recovery/generate */
  generateRecoveryKeys(req: BarrierGenerateRecoveryKeysRequest): Promise<RecoveryKeyResult> {
    return this.http.request('POST', `${BASE}/recovery/generate`, { body: req });
  }

  /** POST /api/v1/barrier/recovery/recover */
  recoverWithKeys(req: BarrierRecoverWithKeysRequest): Promise<SuccessResponse> {
    return this.http.request('POST', `${BASE}/recovery/recover`, { body: req });
  }

  /** DELETE /api/v1/barrier/recovery/keys */
  deleteRecoveryKeys(): Promise<SuccessResponse> {
    return this.http.request('DELETE', `${BASE}/recovery/keys`);
  }

  /** POST /api/v1/barrier/recovery/root-token */
  generateRootToken(req: BarrierGenerateRootTokenRequest): Promise<RootToken> {
    return this.http.request('POST', `${BASE}/recovery/root-token`, { body: req });
  }

  /** POST /api/v1/barrier/enable-encryption (async migration; poll status). */
  enableEncryption(
    req: BarrierEnableEncryptionRequest,
  ): Promise<BarrierEnableEncryptionResponse> {
    return this.http.request('POST', `${BASE}/enable-encryption`, { body: req });
  }
}
