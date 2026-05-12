/**
 * Copyright (C) 2024 Trusted CA Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0, or alternatively, under the terms of the
 * GNU Affero General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any
 * later version. A commercial license is available from the authors.
 *
 * API client methods for the first-run setup wizard endpoints.
 * All methods delegate to the shared apiClient singleton.
 */

import { apiClient } from './client';

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/** SetupStatusResponse describes the current initialization state of the server. */
export interface SetupStatusResponse {
  status: 'pending' | 'complete';
  mode: 'embedded' | 'remote';
  ca_initialized: boolean;
}

/** SetupBarrierRequest configures the encryption barrier for the CA. */
export interface SetupBarrierRequest {
  strategy: string;
  secret: string;
  shamir?: { threshold: number; total: number };
}

/** SetupBarrierResponse returns Shamir shares when the shamir strategy is used. */
export interface SetupBarrierResponse {
  shares?: string[];
  threshold?: number;
  total?: number;
}

/** SetupCARequest configures the root and intermediate CA hierarchy. */
export interface SetupCARequest {
  root_ca_name: string;
  intermediate_ca_name: string;
  key_algorithm: string;
  validity_years: number;
  organization?: string;
  organizational_unit?: string;
  country?: string;
  state?: string;
  locality?: string;
}

/** SetupDefaultsResponse contains pre-populated values from the server configuration. */
export interface SetupDefaultsResponse {
  organization?: string;
  organizational_unit?: string;
  country?: string;
  state?: string;
  locality?: string;
}

/** AlgorithmEntry describes a single supported key algorithm. */
export interface AlgorithmEntry {
  algorithm: string;
  curve?: string;
  key_size?: number;
}

/** AlgorithmsResponse lists algorithms supported by the server. */
export interface AlgorithmsResponse {
  signing: AlgorithmEntry[];
}

// ---------------------------------------------------------------------------
// API namespace
// ---------------------------------------------------------------------------

/** setupApi provides typed access to all first-run setup endpoints. */
export const setupApi = {
  /** status fetches the current setup initialization state. */
  status(): Promise<SetupStatusResponse> {
    return apiClient.get<SetupStatusResponse>('/admin/setup/status');
  },

  /** configureBarrier configures the encryption barrier strategy. */
  configureBarrier(req: SetupBarrierRequest): Promise<SetupBarrierResponse> {
    return apiClient.post<SetupBarrierResponse>('/admin/setup/barrier', req);
  },

  /** configureCA initializes the root and intermediate CA hierarchy. */
  configureCA(req: SetupCARequest): Promise<void> {
    return apiClient.post<void>('/admin/setup/ca', req);
  },

  /** complete finalizes setup and brings the server into operational state. */
  complete(): Promise<void> {
    return apiClient.post<void>('/admin/setup/complete');
  },

  /** getDefaults fetches pre-populated defaults from the server configuration. */
  getDefaults(): Promise<SetupDefaultsResponse> {
    return apiClient.get<SetupDefaultsResponse>('/admin/setup/defaults');
  },

  /** getAlgorithms fetches the list of key algorithms supported by the server. */
  getAlgorithms(): Promise<AlgorithmsResponse> {
    return apiClient.get<AlgorithmsResponse>('/admin/algorithms');
  },
};
