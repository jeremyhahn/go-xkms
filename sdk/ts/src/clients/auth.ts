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

import type { AuthPaths } from '../config.js';
import type { HttpCore } from '../http.js';
import type {
  AuthMeResponse,
  AuthValidateResponse,
  TokenResponse,
  WebAuthnAuthResponse,
  WebAuthnBeginLoginRequest,
  WebAuthnBeginRegistrationRequest,
  WebAuthnCeremonyStart,
  WebAuthnRegistrationStatusResponse,
} from '../types/auth.js';
import type {
  AssertionCredentialJSON,
  AttestationCredentialJSON,
} from '../webauthn.js';

/** WebAuthn session correlation headers (pkg/webauthn/http/types.go). */
export const HEADER_SESSION_ID = 'X-Session-Id';
export const HEADER_USER_ID = 'X-User-Id';

const WEBAUTHN_BASE = '/api/v1/webauthn';

/**
 * Session and WebAuthn authentication client.
 *
 * The token-pair endpoints (loginCert, refresh) ARE the authentication, so
 * they never send a bearer token; loginCert additionally sends
 * `credentials: 'include'` so the browser presents the TLS client
 * certificate / ambient cookies for the mTLS exchange. The introspection
 * endpoints (me, validate, logout) ride the configured TokenProvider.
 */
export class AuthClient {
  constructor(
    private readonly http: HttpCore,
    private readonly paths: AuthPaths,
  ) {}

  // -------------------------------------------------------------------
  // Token-pair session endpoints (pkg/api/rest/handlers_auth.go)
  // -------------------------------------------------------------------

  /**
   * POST {authPaths.loginCert} — exchange the TLS-verified client
   * certificate (PIV / mTLS identity) for a bearer token pair.
   */
  loginCert(): Promise<TokenResponse> {
    return this.http.request('POST', this.paths.loginCert, {
      auth: false,
      credentials: 'include',
    });
  }

  /** POST {authPaths.refresh} — rotate a refresh token into a new pair. */
  refresh(refreshToken: string): Promise<TokenResponse> {
    return this.http.request('POST', this.paths.refresh, {
      auth: false,
      body: { refresh_token: refreshToken },
    });
  }

  /** GET {authPaths.me} — identity, effective UI permissions, capability flags. */
  me(): Promise<AuthMeResponse> {
    return this.http.request('GET', this.paths.me);
  }

  /** GET {authPaths.validate} — lightweight boot-time session probe. */
  validate(): Promise<AuthValidateResponse> {
    return this.http.request('GET', this.paths.validate);
  }

  /** POST {authPaths.logout} — revoke the refresh-token family (204). */
  async logout(refreshToken?: string): Promise<void> {
    await this.http.request<void>('POST', this.paths.logout, {
      body: { refresh_token: refreshToken ?? '' },
      parse: 'void',
    });
  }

  // -------------------------------------------------------------------
  // WebAuthn browser ceremonies (pkg/webauthn/http mounted at
  // /api/v1/webauthn; session correlation via X-Session-Id / X-User-Id)
  // -------------------------------------------------------------------

  /**
   * POST /api/v1/webauthn/registration/begin — returns the raw
   * go-webauthn creation options envelope plus the session ID from the
   * X-Session-Id response header. Feed `options` to parseCreationOptions.
   */
  async webAuthnRegisterBegin(
    req: WebAuthnBeginRegistrationRequest,
  ): Promise<WebAuthnCeremonyStart> {
    const { data, response } = await this.http.requestRaw<unknown>(
      'POST',
      `${WEBAUTHN_BASE}/registration/begin`,
      { auth: false, body: req },
    );
    return {
      options: data,
      sessionId: response.headers.get(HEADER_SESSION_ID) ?? '',
    };
  }

  /**
   * POST /api/v1/webauthn/registration/finish — submit the encoded
   * attestation (encodeAttestationResponse) under the session's
   * X-Session-Id header.
   */
  webAuthnRegisterFinish(
    sessionId: string,
    credential: AttestationCredentialJSON,
  ): Promise<WebAuthnAuthResponse> {
    return this.http.request('POST', `${WEBAUTHN_BASE}/registration/finish`, {
      auth: false,
      body: credential,
      headers: { [HEADER_SESSION_ID]: sessionId },
    });
  }

  /** GET /api/v1/webauthn/registration/status?user_id=&email= */
  webAuthnRegistrationStatus(query: {
    user_id?: string;
    email?: string;
  }): Promise<WebAuthnRegistrationStatusResponse> {
    return this.http.request('GET', `${WEBAUTHN_BASE}/registration/status`, {
      auth: false,
      query: { user_id: query.user_id, email: query.email },
    });
  }

  /**
   * POST /api/v1/webauthn/login/begin — returns the raw go-webauthn
   * request options envelope plus X-Session-Id (and X-User-Id when the
   * server resolved the account). Feed `options` to parseRequestOptions.
   * Omit the request body for the discoverable-credential flow.
   */
  async webAuthnBeginLogin(req?: WebAuthnBeginLoginRequest): Promise<WebAuthnCeremonyStart> {
    const { data, response } = await this.http.requestRaw<unknown>(
      'POST',
      `${WEBAUTHN_BASE}/login/begin`,
      { auth: false, body: req ?? {} },
    );
    const userId = response.headers.get(HEADER_USER_ID);
    return {
      options: data,
      sessionId: response.headers.get(HEADER_SESSION_ID) ?? '',
      ...(userId !== null && userId !== '' ? { userId } : {}),
    };
  }

  /**
   * POST /api/v1/webauthn/login/finish — submit the encoded assertion
   * (encodeAssertionResponse) under the session's X-Session-Id header,
   * echoing X-User-Id when login/begin returned one.
   */
  webAuthnFinishLogin(
    sessionId: string,
    credential: AssertionCredentialJSON,
    userId?: string,
  ): Promise<WebAuthnAuthResponse> {
    const headers: Record<string, string> = { [HEADER_SESSION_ID]: sessionId };
    if (userId !== undefined && userId !== '') {
      headers[HEADER_USER_ID] = userId;
    }
    return this.http.request('POST', `${WEBAUTHN_BASE}/login/finish`, {
      auth: false,
      body: credential,
      headers,
    });
  }
}
