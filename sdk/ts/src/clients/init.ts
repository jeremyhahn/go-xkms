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
  ClaimCertBeginRequest,
  ClaimCertBeginResponse,
  ClaimCertCompleteRequest,
  ClaimCertCompleteResponse,
  ClaimShareBeginRequest,
  ClaimShareBeginResponse,
  ClaimShareCompleteRequest,
  ClaimShareCompleteResponse,
  InitStatusResponse,
  SignCSRInitRequest,
  SignCSRInitResponse,
} from '../types/init.js';

const BASE = '/api/v1/init';

/** First-boot init ceremony (officer cert + share claims). */
export class InitClient {
  constructor(private readonly http: HttpCore) {}

  /** GET /api/v1/init/status */
  status(): Promise<InitStatusResponse> {
    return this.http.request('GET', `${BASE}/status`);
  }

  /** POST /api/v1/init/claim-cert/begin */
  claimCertBegin(req: ClaimCertBeginRequest): Promise<ClaimCertBeginResponse> {
    return this.http.request('POST', `${BASE}/claim-cert/begin`, { body: req });
  }

  /** POST /api/v1/init/claim-cert/complete */
  claimCertComplete(req: ClaimCertCompleteRequest): Promise<ClaimCertCompleteResponse> {
    return this.http.request('POST', `${BASE}/claim-cert/complete`, { body: req });
  }

  /** POST /api/v1/init/claim-share/begin (requires the officer's mTLS cert). */
  claimShareBegin(req: ClaimShareBeginRequest): Promise<ClaimShareBeginResponse> {
    return this.http.request('POST', `${BASE}/claim-share/begin`, { body: req });
  }

  /** POST /api/v1/init/claim-share/complete (requires the officer's mTLS cert). */
  claimShareComplete(req: ClaimShareCompleteRequest): Promise<ClaimShareCompleteResponse> {
    return this.http.request('POST', `${BASE}/claim-share/complete`, { body: req });
  }

  /** POST /api/v1/init/sign-csr (authenticated; RBAC ceremony:sign_csr). */
  signCSR(req: SignCSRInitRequest): Promise<SignCSRInitResponse> {
    return this.http.request('POST', `${BASE}/sign-csr`, { body: req });
  }
}
