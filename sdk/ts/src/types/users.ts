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

/**
 * User management DTOs. Mirrors pkg/api/rest/user_handlers.go and
 * pkg/api/transport/types.go UserInfo / ListUsersResponse.
 */

import type { RFC3339 } from './common.js';

/** Mirrors pkg/api/transport/types.go UserInfo. */
export interface UserInfo {
  /**
   * Numeric qrdb user id, carried as a STRING: the Go DTO tags it
   * `json:"id,string"` because a uint64 exceeds the range JSON numbers
   * represent exactly. Convert with Number() only when the id is known to be
   * within Number.MAX_SAFE_INTEGER — the N-factor endpoints key on it.
   */
  id: string;
  username: string;
  display_name?: string;
  role?: string;
  enabled: boolean;
  created_at: RFC3339;
  last_login?: RFC3339;
}

/** Mirrors pkg/api/rest/user_handlers.go createUserBody. */
export interface CreateUserRequest {
  username: string;
  display_name: string;
  role: string;
  tenant_id: string;
}

/** Mirrors pkg/api/transport/types.go ListUsersResponse (PageResponse embedded flat). */
export interface ListUsersResponse {
  users: UserInfo[];
  page: number;
  page_size: number;
  total: number;
  has_more: boolean;
}

/** Mirrors pkg/api/rest/user_handlers.go bindUserCertBody. */
export interface BindUserCertRequest {
  thumbprint: string;
  not_after_unix: number;
}

/** Status response for delete / cert-bind ({username, status}). */
export interface UserStatusResponse {
  username: string;
  status: string;
}

/** Mirrors pkg/api/rest/user_handlers.go userCredentialItem. */
export interface UserCredentialItem {
  id: string;
  name: string;
}

/** Response envelope for GET /api/v1/users/{username}/credentials. */
export interface ListUserCredentialsResponse {
  credentials: UserCredentialItem[];
}
