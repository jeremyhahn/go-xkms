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
import type { SuccessResponse } from '../types/common.js';
import type {
  ChangeSOPINRequest,
  ChangeUserPINRequest,
  LockoutStatusResponse,
  ResetLockoutRequest,
  SetSOPINRequest,
  SetUserPINRequest,
  VerifyPINRequest,
} from '../types/pin.js';

const BASE = '/api/v1/pin';

/** SO / User PIN management. */
export class PinClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/pin/so/set */
  setSO(req: SetSOPINRequest): Promise<SuccessResponse> {
    return this.http.request('POST', `${BASE}/so/set`, { body: req });
  }

  /** POST /api/v1/pin/user/set */
  setUser(req: SetUserPINRequest): Promise<SuccessResponse> {
    return this.http.request('POST', `${BASE}/user/set`, { body: req });
  }

  /** POST /api/v1/pin/so/change */
  changeSO(req: ChangeSOPINRequest): Promise<SuccessResponse> {
    return this.http.request('POST', `${BASE}/so/change`, { body: req });
  }

  /** POST /api/v1/pin/user/change */
  changeUser(req: ChangeUserPINRequest): Promise<SuccessResponse> {
    return this.http.request('POST', `${BASE}/user/change`, { body: req });
  }

  /** POST /api/v1/pin/so/verify */
  verifySO(req: VerifyPINRequest): Promise<SuccessResponse> {
    return this.http.request('POST', `${BASE}/so/verify`, { body: req });
  }

  /** POST /api/v1/pin/user/verify */
  verifyUser(req: VerifyPINRequest): Promise<SuccessResponse> {
    return this.http.request('POST', `${BASE}/user/verify`, { body: req });
  }

  /** GET /api/v1/pin/lockout */
  lockoutStatus(): Promise<LockoutStatusResponse> {
    return this.http.request('GET', `${BASE}/lockout`);
  }

  /** POST /api/v1/pin/lockout/reset */
  resetLockout(req: ResetLockoutRequest): Promise<SuccessResponse> {
    return this.http.request('POST', `${BASE}/lockout/reset`, { body: req });
  }
}
