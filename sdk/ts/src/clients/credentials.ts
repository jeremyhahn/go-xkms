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
  CredentialStrategyResponse,
  CredentialSubmitRequest,
  CredentialSubmitResponse,
} from '../types/credentials.js';

const BASE = '/api/v1/credentials';

/** Boot-credential submission (unseal secrets, PINs). */
export class CredentialsClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/credentials/submit */
  submit(req: CredentialSubmitRequest): Promise<CredentialSubmitResponse> {
    return this.http.request('POST', `${BASE}/submit`, { body: req });
  }

  /** GET /api/v1/credentials/strategy */
  strategy(): Promise<CredentialStrategyResponse> {
    return this.http.request('GET', `${BASE}/strategy`);
  }
}
