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

/** Password store DTOs. Mirrors pkg/api/rest/password_handlers.go. */

export interface PasswordAddRequest {
  name: string;
  title?: string;
  username?: string;
  password: string;
  url?: string;
  notes?: string;
  folder_path?: string;
  shared?: boolean;
}

export interface PasswordAddResponse {
  id: string;
  name: string;
  message: string;
}

export interface PasswordInfo {
  id: string;
  name: string;
  title?: string;
  username?: string;
  url?: string;
  folder_path?: string;
  owner_id?: string;
  shared?: boolean;
  created_at: string;
  updated_at: string;
}

export interface PasswordListResponse {
  passwords: PasswordInfo[];
  total: number;
}

export interface PasswordDetailResponse {
  id: string;
  name: string;
  title?: string;
  username?: string;
  password: string;
  url?: string;
  notes?: string;
  folder_path?: string;
  owner_id?: string;
  shared?: boolean;
  read_only?: boolean;
  created_at: string;
  updated_at: string;
}

/** All members optional: only supplied fields are updated (Go *string semantics). */
export interface PasswordUpdateRequest {
  name?: string;
  title?: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
  folder_path?: string;
}

export interface PasswordUpdateResponse {
  id: string;
  name: string;
  message: string;
}

export interface PasswordDeleteResponse {
  message: string;
}

export interface PasswordStoreUnlockRequest {
  pin: string;
}

export interface PasswordStoreAccessModeRequest {
  mode: string;
}

export interface PasswordStoreAccessModeResponse {
  mode: string;
  message: string;
}

export interface PasswordStoreStatusResponse {
  available: boolean;
  is_locked: boolean;
  barrier_sealed: boolean;
  password_count: number;
  message: string;
}

export interface PasswordGenerateRequest {
  length?: number;
  charset?: string;
}

export interface PasswordGenerateResponse {
  password: string;
  length: number;
}
