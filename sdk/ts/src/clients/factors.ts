// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
  AuthFactorAddRequest,
  AuthFactorAddResponse,
  AuthFactorGetResponse,
  AuthFactorListResponse,
  AuthFactorLoginRequest,
  AuthFactorLoginResponse,
  AuthFactorRelabelRequest,
  AuthFactorRelabelResponse,
  AuthFactorRemoveResponse,
  AuthFactorRotateRequest,
  AuthFactorRotateResponse,
} from '../types/factors.js';

const BASE = '/api/v1/factors';

/**
 * User N-factor management. Factor state is owned by the embedded go-qrdb
 * node; xkmsd proxies it so identity is reachable on the same endpoint as
 * everything else.
 */
export class FactorsClient {
  constructor(private readonly http: HttpCore) {}

  /**
   * GET /api/v1/factors?user_id=N
   *
   * The owner is a QUERY parameter, not a path segment — the server parses
   * `user_id` off the query string and rejects a missing or zero value.
   */
  list(userID: number): Promise<AuthFactorListResponse> {
    return this.http.request('GET', `${BASE}/`, { query: { user_id: userID } });
  }

  /** POST /api/v1/factors — the owning user comes from the BODY. */
  add(req: AuthFactorAddRequest): Promise<AuthFactorAddResponse> {
    return this.http.request('POST', `${BASE}/`, { body: req });
  }

  /** GET /api/v1/factors/{factorID} */
  get(factorID: string): Promise<AuthFactorGetResponse> {
    return this.http.request('GET', `${BASE}/${encodeURIComponent(factorID)}`);
  }

  /**
   * DELETE /api/v1/factors/{factorID}
   *
   * qrdb refuses to revoke a user's last active factor; `force` asks it to
   * stand down, which also moves the user to inactive.
   */
  remove(factorID: string, force = false): Promise<AuthFactorRemoveResponse> {
    return this.http.request('DELETE', `${BASE}/${encodeURIComponent(factorID)}`, {
      query: force ? { force: 'true' } : {},
    });
  }

  /**
   * PATCH /api/v1/factors/{factorID}
   *
   * The server takes the factor id from the path and overwrites whatever the
   * body carries, so only the label needs sending.
   */
  relabel(factorID: string, req: AuthFactorRelabelRequest): Promise<AuthFactorRelabelResponse> {
    return this.http.request('PATCH', `${BASE}/${encodeURIComponent(factorID)}`, { body: req });
  }

  /**
   * POST /api/v1/factors/{factorID}/rotate — atomically revoke and replace.
   * The old factor id comes from the path; the body carries only new_factor.
   */
  rotate(factorID: string, req: AuthFactorRotateRequest): Promise<AuthFactorRotateResponse> {
    return this.http.request('POST', `${BASE}/${encodeURIComponent(factorID)}/rotate`, {
      body: req,
    });
  }

  /**
   * POST /api/v1/factors/login
   *
   * Resolves a (type, lookup_key) pair to a principal and NOTHING more. This
   * is not proof of possession: the hardware challenge must already have been
   * verified before the result is treated as an authenticated identity.
   */
  login(req: AuthFactorLoginRequest): Promise<AuthFactorLoginResponse> {
    return this.http.request('POST', `${BASE}/login`, { body: req });
  }
}
