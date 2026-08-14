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

import type { AuthPaths } from '../config.js';
import type { HttpCore } from '../http.js';

/**
 * Deployment capability flags: which optional subsystems (webauthn, ca,
 * tenants, ssh, ...) this server wired. The canonical source is the
 * `capabilities` member of GET /api/v1/auth/me (handlers_auth.go
 * capabilityFlags); deployments that expose a dedicated capabilities
 * endpoint serve the same map at the configured `authPaths.capabilities`
 * path (default /api/v1/capabilities).
 */
export class CapabilitiesClient {
  constructor(
    private readonly http: HttpCore,
    private readonly paths: AuthPaths,
  ) {}

  /** GET {authPaths.capabilities} -> { "<capability>": boolean, ... } */
  get(): Promise<Record<string, boolean>> {
    return this.http.request('GET', this.paths.capabilities);
  }
}
