/**
 * Copyright (C) 2024 Trusted CA Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0, or alternatively, under the terms of the
 * GNU Affero General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any
 * later version. A commercial license is available from the authors.
 *
 * API client methods for the barrier administration endpoints.
 * All methods delegate to the shared apiClient singleton.
 */

import { apiClient } from './client';
import type {
  BarrierStatusResponse,
  BarrierInitializeRequest,
  BarrierUnsealRequest,
  BarrierInitializeShamirRequest,
  BarrierInitializeShamirResponse,
  BarrierUnsealShareRequest,
  BarrierUnsealShareResponse,
  BarrierRekeyRequest,
  BarrierRekeyResponse,
  BarrierGenerateRecoveryKeysRequest,
  BarrierRecoveryKeysResponse,
  BarrierRecoverWithKeysRequest,
  BarrierGenerateRootTokenRequest,
  BarrierRootTokenResponse,
} from './barrier-types';

/** barrierApi provides typed access to all barrier administration endpoints. */
export const barrierApi = {
  /** status fetches the current barrier seal/unseal status. */
  status(): Promise<BarrierStatusResponse> {
    return apiClient.get<BarrierStatusResponse>('/admin/barrier/status');
  },

  /** initialize performs a single-secret barrier initialization. */
  initialize(req: BarrierInitializeRequest): Promise<void> {
    return apiClient.post<void>('/admin/barrier/initialize', req);
  },

  /** seal seals the barrier, requiring unseal before further operations. */
  seal(): Promise<void> {
    return apiClient.post<void>('/admin/barrier/seal');
  },

  /** unseal unseals the barrier with a single secret. */
  unseal(req: BarrierUnsealRequest): Promise<void> {
    return apiClient.post<void>('/admin/barrier/unseal', req);
  },

  /** initializeShamir initializes the barrier using Shamir secret sharing. */
  initializeShamir(req: BarrierInitializeShamirRequest): Promise<BarrierInitializeShamirResponse> {
    return apiClient.post<BarrierInitializeShamirResponse>('/admin/barrier/shamir/initialize', req);
  },

  /** unsealWithShare submits one Shamir share toward unsealing. */
  unsealWithShare(req: BarrierUnsealShareRequest): Promise<BarrierUnsealShareResponse> {
    return apiClient.post<BarrierUnsealShareResponse>('/admin/barrier/shamir/unseal-share', req);
  },

  /** rekey rotates the Shamir key shares to new threshold/total parameters. */
  rekey(req: BarrierRekeyRequest): Promise<BarrierRekeyResponse> {
    return apiClient.post<BarrierRekeyResponse>('/admin/barrier/rekey', req);
  },

  /** generateRecoveryKeys generates a new set of recovery keys. */
  generateRecoveryKeys(req: BarrierGenerateRecoveryKeysRequest): Promise<BarrierRecoveryKeysResponse> {
    return apiClient.post<BarrierRecoveryKeysResponse>('/admin/barrier/recovery/generate', req);
  },

  /** recoverWithKeys uses recovery keys to restore access. */
  recoverWithKeys(req: BarrierRecoverWithKeysRequest): Promise<void> {
    return apiClient.post<void>('/admin/barrier/recovery/recover', req);
  },

  /** hasRecoveryKeys reports whether recovery keys have been generated. */
  hasRecoveryKeys(): Promise<boolean> {
    return apiClient.get<boolean>('/admin/barrier/recovery/status');
  },

  /** generateRootToken generates a new root token using Shamir shares. */
  generateRootToken(req: BarrierGenerateRootTokenRequest): Promise<BarrierRootTokenResponse> {
    return apiClient.post<BarrierRootTokenResponse>('/admin/barrier/root-token', req);
  },
};
