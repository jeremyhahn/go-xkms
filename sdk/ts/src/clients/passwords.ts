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
  PasswordVaultEnrollRequest,
  PasswordVaultEnrollResponse,
  PasswordVaultRecoverRequest,
  PasswordVaultRotateRequest,
  PasswordVaultStatusResponse,
} from '../types/passwords.js';

const BASE = '/api/v1/passwords';

/**
 * The caller's personal vault and its session. It lives beside the entries,
 * not under them, so every entry name is fetchable by `get(name)`.
 */
const VAULT = '/api/v1/password-vault';

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

  /** POST /api/v1/password-vault/unlock -- opens the caller's session with one of their vault factors. */
  unlock(req: PasswordStoreUnlockRequest): Promise<PasswordStoreStatusResponse> {
    return this.http.request('POST', `${VAULT}/unlock`, { body: req });
  }

  /** GET /api/v1/password-vault */
  vaultStatus(): Promise<PasswordVaultStatusResponse> {
    return this.http.request('GET', VAULT);
  }

  /**
   * POST /api/v1/password-vault/factors -- the first enrollment initializes
   * the vault, opens the session and returns the one-time recovery code.
   */
  vaultEnroll(req: PasswordVaultEnrollRequest): Promise<PasswordVaultEnrollResponse> {
    return this.http.request('POST', `${VAULT}/factors`, { body: req });
  }

  /** PUT /api/v1/password-vault/factors/{id} */
  vaultRotate(factorId: string, req: PasswordVaultRotateRequest): Promise<PasswordVaultEnrollResponse> {
    return this.http.request('PUT', `${VAULT}/factors/${encodeURIComponent(factorId)}`, { body: req });
  }

  /** DELETE /api/v1/password-vault/factors/{id} (204 No Content) */
  async vaultRemoveFactor(factorId: string): Promise<void> {
    await this.http.request<void>('DELETE', `${VAULT}/factors/${encodeURIComponent(factorId)}`);
  }

  /** POST /api/v1/password-vault/recover -- returns the replacement recovery code. */
  vaultRecover(req: PasswordVaultRecoverRequest): Promise<PasswordVaultEnrollResponse> {
    return this.http.request('POST', `${VAULT}/recover`, { body: req });
  }

  /** POST /api/v1/password-vault/lock */
  lock(): Promise<PasswordStoreStatusResponse> {
    return this.http.request('POST', `${VAULT}/lock`);
  }

  /** GET /api/v1/password-vault/session -- the caller's session and the entries it can read now. */
  status(): Promise<PasswordStoreStatusResponse> {
    return this.http.request('GET', `${VAULT}/session`);
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
