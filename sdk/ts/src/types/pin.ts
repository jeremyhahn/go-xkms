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

/** PIN management DTOs. Mirrors pkg/api/rest/handlers_barrier_pin.go. */

import type { RFC3339 } from './common.js';

export interface SetSOPINRequest {
  current_so_pin: string;
  new_so_pin: string;
}

export interface SetUserPINRequest {
  so_pin: string;
  new_user_pin: string;
}

export interface ChangeSOPINRequest {
  current_so_pin: string;
  new_so_pin: string;
}

export interface ChangeUserPINRequest {
  current_user_pin: string;
  new_user_pin: string;
}

/** Mirrors pkg/api/rest/handlers_barrier_pin.go VerifyPINRequest. */
export interface VerifyPINRequest {
  pin: string;
}

export interface ResetLockoutRequest {
  so_pin: string;
}

/** Mirrors pkg/api/rest/handlers_barrier_pin.go LockoutStatusResponse. */
export interface LockoutStatusResponse {
  failed_attempts: number;
  max_attempts: number;
  is_locked: boolean;
  lockout_until?: RFC3339;
  recovery_seconds: number;
}
