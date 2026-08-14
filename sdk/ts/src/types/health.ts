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

/** Mirrors pkg/api/rest/types.go HealthResponse (GET /health). */
export interface HealthResponse {
  status: string;
  version?: string;
}

/** One health-check probe result (qrdb sdk HealthCheckResult). */
export interface HealthCheckResult {
  name: string;
  status: string;
  message?: string;
  [key: string]: unknown;
}

/**
 * Mirrors pkg/api/rest/health_handlers.go HealthCheckResponse
 * (GET /health/live | /health/ready | /health/startup).
 */
export interface HealthCheckResponse {
  status: string;
  message?: string;
  checks?: HealthCheckResult[];
}

/** Mirrors pkg/types/algorithm_discovery.go AlgorithmInfo. */
export interface AlgorithmInfo {
  algorithm: string;
  curves?: string[];
  key_sizes?: number[];
  backends: string[];
  post_quantum?: boolean;
}

/** Mirrors pkg/types/algorithm_discovery.go AlgorithmsResponse (GET /api/v1/algorithms). */
export interface AlgorithmsResponse {
  signing: AlgorithmInfo[];
  key_encapsulation: AlgorithmInfo[];
}
