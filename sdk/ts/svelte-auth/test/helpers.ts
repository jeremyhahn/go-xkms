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

/** Shared test fixtures for @go-xkms/svelte-auth. */

import { vi } from 'vitest';
import type { TokenResponse } from '@go-xkms/sdk';
import type { AuthApi, AuthClientHost } from '../src/config.ts';

/**
 * FakeApiError mimics the SDK's XkmsApiError: an Error carrying the numeric
 * HTTP status the server answered with. The store treats any error with a
 * numeric `status` as a definitive rejection.
 */
export class FakeApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'XkmsApiError';
    this.status = status;
  }
}

/** Build an unsigned JWT whose exp is `secondsFromNow` in the future. */
export function jwtExpiringIn(secondsFromNow: number): string {
  const header = btoa(JSON.stringify({ alg: 'none', typ: 'at+jwt' }));
  const payload = btoa(
    JSON.stringify({ sub: 'user-1', exp: Math.floor(Date.now() / 1000) + secondsFromNow }),
  );
  return `${header}.${payload}.sig`;
}

/** A full TokenResponse pair as the server returns it. */
export function tokenPair(access: string, refresh: string): TokenResponse {
  return {
    access_token: access,
    refresh_token: refresh,
    token_type: 'Bearer',
    expires_in: 900,
  };
}

/** Vitest mocks for every AuthApi method. */
export interface FakeAuthMocks {
  refresh: ReturnType<typeof vi.fn>;
  validate: ReturnType<typeof vi.fn>;
  logout: ReturnType<typeof vi.fn>;
  me: ReturnType<typeof vi.fn>;
  webAuthnBeginLogin: ReturnType<typeof vi.fn>;
  webAuthnFinishLogin: ReturnType<typeof vi.fn>;
  webAuthnRegisterBegin: ReturnType<typeof vi.fn>;
  webAuthnRegisterFinish: ReturnType<typeof vi.fn>;
  loginCert: ReturnType<typeof vi.fn>;
}

/**
 * makeFakeClient builds an AuthClientHost whose every method is a vi.fn().
 * Individual tests override the mocks they exercise.
 */
export function makeFakeClient(): { client: AuthClientHost; mocks: FakeAuthMocks } {
  const mocks: FakeAuthMocks = {
    refresh: vi.fn(async () => tokenPair('access-fresh', 'refresh-fresh')),
    validate: vi.fn(async () => ({ subject: 'user-1' })),
    logout: vi.fn(async () => undefined),
    me: vi.fn(async () => ({
      subject: 'user-1',
      permissions: {},
      capabilities: {},
    })),
    webAuthnBeginLogin: vi.fn(),
    webAuthnFinishLogin: vi.fn(),
    webAuthnRegisterBegin: vi.fn(),
    webAuthnRegisterFinish: vi.fn(),
    loginCert: vi.fn(async () => tokenPair('cert-access', 'cert-refresh')),
  };
  const client = { auth: mocks as unknown as AuthApi };
  return { client, mocks };
}
