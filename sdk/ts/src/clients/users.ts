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
  BindUserCertRequest,
  CreateUserRequest,
  ListUserCredentialsResponse,
  ListUsersResponse,
  UpdateUserRequest,
  UserInfo,
  UserStatusResponse,
} from '../types/users.js';

const BASE = '/api/v1/users';

function userPath(username: string, suffix = ''): string {
  return `${BASE}/${encodeURIComponent(username)}${suffix}`;
}

/** User management (backed by the embedded qrdb node). */
export class UsersClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/users/ */
  create(req: CreateUserRequest): Promise<UserInfo> {
    return this.http.request('POST', `${BASE}/`, { body: req });
  }

  /** GET /api/v1/users/ */
  list(): Promise<ListUsersResponse> {
    return this.http.request('GET', `${BASE}/`);
  }

  /** GET /api/v1/users/{username} */
  get(username: string): Promise<UserInfo> {
    return this.http.request('GET', userPath(username));
  }

  /** PUT /api/v1/users/{username} (enable/disable). */
  update(username: string, req: UpdateUserRequest): Promise<UserInfo> {
    return this.http.request('PUT', userPath(username), { body: req });
  }

  /** DELETE /api/v1/users/{username} */
  delete(username: string): Promise<UserStatusResponse> {
    return this.http.request('DELETE', userPath(username));
  }

  /** POST /api/v1/users/{username}/cert-bindings */
  bindCert(username: string, req: BindUserCertRequest): Promise<UserStatusResponse> {
    return this.http.request('POST', userPath(username, '/cert-bindings'), { body: req });
  }

  /** GET /api/v1/users/{username}/credentials */
  credentials(username: string): Promise<ListUserCredentialsResponse> {
    return this.http.request('GET', userPath(username, '/credentials'));
  }
}
