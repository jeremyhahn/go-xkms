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
  PasswordAddRequest,
  PasswordAddResponse,
  PasswordDeleteResponse,
  PasswordDetailResponse,
  PasswordGenerateRequest,
  PasswordGenerateResponse,
  PasswordListResponse,
  PasswordStoreAccessModeRequest,
  PasswordStoreAccessModeResponse,
  PasswordStoreStatusResponse,
  PasswordStoreUnlockRequest,
  PasswordUpdateRequest,
  PasswordUpdateResponse,
} from '../types/passwords.js';

const BASE = '/api/v1/passwords';

/** Password store management. */
export class PasswordsClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/passwords/ */
  add(req: PasswordAddRequest): Promise<PasswordAddResponse> {
    return this.http.request('POST', `${BASE}/`, { body: req });
  }

  /** GET /api/v1/passwords/?folder=&scope= */
  list(folder?: string, scope?: string): Promise<PasswordListResponse> {
    return this.http.request('GET', `${BASE}/`, { query: { folder, scope } });
  }

  /** GET /api/v1/passwords/{id} */
  get(id: string): Promise<PasswordDetailResponse> {
    return this.http.request('GET', `${BASE}/${encodeURIComponent(id)}`);
  }

  /** PUT /api/v1/passwords/{id} */
  update(id: string, req: PasswordUpdateRequest): Promise<PasswordUpdateResponse> {
    return this.http.request('PUT', `${BASE}/${encodeURIComponent(id)}`, { body: req });
  }

  /** DELETE /api/v1/passwords/{id} */
  delete(id: string): Promise<PasswordDeleteResponse> {
    return this.http.request('DELETE', `${BASE}/${encodeURIComponent(id)}`);
  }

  /** POST /api/v1/passwords/unlock */
  unlock(req: PasswordStoreUnlockRequest): Promise<PasswordStoreStatusResponse> {
    return this.http.request('POST', `${BASE}/unlock`, { body: req });
  }

  /** POST /api/v1/passwords/lock */
  lock(): Promise<PasswordStoreStatusResponse> {
    return this.http.request('POST', `${BASE}/lock`);
  }

  /** GET /api/v1/passwords/status */
  status(): Promise<PasswordStoreStatusResponse> {
    return this.http.request('GET', `${BASE}/status`);
  }

  /** POST /api/v1/passwords/access-mode */
  setAccessMode(req: PasswordStoreAccessModeRequest): Promise<PasswordStoreAccessModeResponse> {
    return this.http.request('POST', `${BASE}/access-mode`, { body: req });
  }

  /** POST /api/v1/passwords/generate */
  generate(req: PasswordGenerateRequest): Promise<PasswordGenerateResponse> {
    return this.http.request('POST', `${BASE}/generate`, { body: req });
  }
}
