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
import type {
  AlgorithmsResponse,
  HealthCheckResponse,
  HealthResponse,
} from '../types/health.js';

/** Health probes and public algorithm discovery (no auth required). */
export class HealthClient {
  constructor(private readonly http: HttpCore) {}

  /** GET /health */
  health(): Promise<HealthResponse> {
    return this.http.request('GET', '/health', { auth: false });
  }

  /** GET /health/live */
  live(): Promise<HealthCheckResponse> {
    return this.http.request('GET', '/health/live', { auth: false });
  }

  /** GET /health/ready */
  ready(): Promise<HealthCheckResponse> {
    return this.http.request('GET', '/health/ready', { auth: false });
  }

  /** GET /health/startup */
  startup(): Promise<HealthCheckResponse> {
    return this.http.request('GET', '/health/startup', { auth: false });
  }

  /** GET /api/v1/algorithms */
  algorithms(): Promise<AlgorithmsResponse> {
    return this.http.request('GET', '/api/v1/algorithms', { auth: false });
  }
}
