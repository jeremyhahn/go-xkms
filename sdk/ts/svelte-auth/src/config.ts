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

/**
 * Package configuration for @go-xkms/svelte-auth.
 *
 * Everything in this package is driven by ONE injected client rather than a
 * hardcoded fetch: the token store refreshes through it, the components run
 * their WebAuthn ceremonies through it, and the BrowserCredentialProvider
 * exchanges the TLS client certificate through it. The client is typed
 * structurally (AuthClientHost) so anything shaped like the @go-xkms/sdk
 * XkmsClient satisfies it — including test fakes and downstream adapters.
 */

import type {
  AuthMeResponse,
  AuthValidateResponse,
  TokenResponse,
  WebAuthnAuthResponse,
  WebAuthnBeginLoginRequest,
  WebAuthnBeginRegistrationRequest,
  WebAuthnCeremonyStart,
  AssertionCredentialJSON,
  AttestationCredentialJSON,
} from '@go-xkms/sdk';

/** Token-lifecycle surface the auth store depends on. */
export interface AuthSessionApi {
  /** Rotate a refresh token into a new access/refresh pair. */
  refresh(refreshToken: string): Promise<TokenResponse>;
  /** Lightweight session probe; rejects when the bearer is invalid. */
  validate(): Promise<AuthValidateResponse>;
  /** Revoke the refresh-token family server-side. */
  logout(refreshToken?: string): Promise<void>;
  /** Identity + effective permissions for the signed-in principal. */
  me(): Promise<AuthMeResponse>;
}

/** WebAuthn ceremony + certificate-login surface the components depend on. */
export interface AuthCeremonyApi {
  webAuthnBeginLogin(req?: WebAuthnBeginLoginRequest): Promise<WebAuthnCeremonyStart>;
  webAuthnFinishLogin(
    sessionId: string,
    credential: AssertionCredentialJSON,
  ): Promise<WebAuthnAuthResponse>;
  webAuthnRegisterBegin(
    req: WebAuthnBeginRegistrationRequest,
  ): Promise<WebAuthnCeremonyStart>;
  webAuthnRegisterFinish(
    sessionId: string,
    credential: AttestationCredentialJSON,
  ): Promise<WebAuthnAuthResponse>;
  /** POST the TLS-verified client certificate for a bearer token pair. */
  loginCert(): Promise<TokenResponse>;
}

/** The complete auth API this package consumes. */
export interface AuthApi extends AuthSessionApi, AuthCeremonyApi {}

/**
 * AuthClientHost is anything exposing `.auth` — the @go-xkms/sdk XkmsClient
 * satisfies it structurally.
 */
export interface AuthClientHost {
  auth: AuthApi;
  /**
   * Optional coarse deployment capabilities (GET /api/v1/capabilities). The
   * login panel intersects these with what the credential provider can do, so
   * a method the server has disabled is never offered. Optional because a
   * host that predates the endpoint — or a test fake — still satisfies the
   * interface; when absent, every provider method is offered.
   */
  capabilities?: { get(): Promise<Record<string, boolean>> };
}

/** Default localStorage key prefix ("xkms" → xkms_token / xkms_refresh_token). */
export const DEFAULT_STORAGE_PREFIX = 'xkms';

/** Default same-origin path prefixes treated as API calls by the 401 layer. */
export const DEFAULT_API_PREFIXES: readonly string[] = ['/api/', '/xkms/'];

/** Default renewal endpoint path — never intercepted by the 401 layer. */
export const DEFAULT_REFRESH_PATH = '/api/v1/auth/refresh';

/** AuthPackageConfig wires the package to a deployment. */
export interface AuthPackageConfig {
  /** The SDK client (or anything auth-shaped) all network calls go through. */
  client: AuthClientHost;
  /** localStorage key prefix; default "xkms" → `xkms_token`, `xkms_refresh_token`. */
  storagePrefix?: string;
  /** Same-origin path prefixes the 401 interceptor treats as API calls. */
  apiPrefixes?: string[];
  /** Renewal endpoint path the 401 interceptor must never intercept. */
  refreshPath?: string;
}

/** ResolvedAuthConfig is AuthPackageConfig with every default applied. */
export interface ResolvedAuthConfig {
  client: AuthClientHost;
  storagePrefix: string;
  apiPrefixes: string[];
  refreshPath: string;
}

/** resolveAuthConfig applies the package defaults over a partial config. */
export function resolveAuthConfig(config: AuthPackageConfig): ResolvedAuthConfig {
  return {
    client: config.client,
    storagePrefix: config.storagePrefix ?? DEFAULT_STORAGE_PREFIX,
    apiPrefixes: config.apiPrefixes ?? [...DEFAULT_API_PREFIXES],
    refreshPath: config.refreshPath ?? DEFAULT_REFRESH_PATH,
  };
}

/** AuthNotConfiguredError is thrown when the store is used before initAuth(). */
export class AuthNotConfiguredError extends Error {
  constructor() {
    super(
      '@go-xkms/svelte-auth is not configured — call initAuth() (or configureAuthStore()) before using the auth store',
    );
    this.name = 'AuthNotConfiguredError';
  }
}
