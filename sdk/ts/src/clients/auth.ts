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
} from '../types/auth.js';
import type {
  AssertionCredentialJSON,
  AttestationCredentialJSON,
} from '../webauthn.js';

/** WebAuthn session correlation header (pkg/webauthn/http/types.go). */
export const HEADER_SESSION_ID = 'X-Session-Id';

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
  // /api/v1/webauthn; session correlation via X-Session-Id)
  // -------------------------------------------------------------------

  /**
   * POST /api/v1/webauthn/registration/begin — enrolls an account's FIRST
   * passkey without a session. Returns the raw go-webauthn creation options
   * envelope plus the session ID from the X-Session-Id response header.
   * Feed `options` to parseCreationOptions. An account that already has a
   * passkey is refused with 403 `registration_refused`; add further passkeys
   * with webAuthnAddCredentialBegin.
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
   * POST /api/v1/webauthn/credentials/begin — start adding a passkey to the
   * signed-in account. Rides the configured TokenProvider: the account is the
   * session's own, never one named in the request. Complete the ceremony with
   * webAuthnRegisterFinish under the returned session ID.
   */
  async webAuthnAddCredentialBegin(): Promise<WebAuthnCeremonyStart> {
    const { data, response } = await this.http.requestRaw<unknown>(
      'POST',
      `${WEBAUTHN_BASE}/credentials/begin`,
      {},
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

  /**
   * POST /api/v1/webauthn/login/begin — returns the raw go-webauthn
   * request options envelope plus X-Session-Id. Feed `options` to
   * parseRequestOptions. Omit the request body for the discoverable-credential
   * flow. The response never reveals whether the account exists; the user ID
   * arrives only with a successful webAuthnFinishLogin.
   */
  async webAuthnBeginLogin(req?: WebAuthnBeginLoginRequest): Promise<WebAuthnCeremonyStart> {
    const { data, response } = await this.http.requestRaw<unknown>(
      'POST',
      `${WEBAUTHN_BASE}/login/begin`,
      { auth: false, body: req ?? {} },
    );
    return {
      options: data,
      sessionId: response.headers.get(HEADER_SESSION_ID) ?? '',
    };
  }

  /**
   * POST /api/v1/webauthn/login/finish — submit the encoded assertion
   * (encodeAssertionResponse) under the session's X-Session-Id header.
   */
  webAuthnFinishLogin(
    sessionId: string,
    credential: AssertionCredentialJSON,
  ): Promise<WebAuthnAuthResponse> {
    return this.http.request('POST', `${WEBAUTHN_BASE}/login/finish`, {
      auth: false,
      body: credential,
      headers: { [HEADER_SESSION_ID]: sessionId },
    });
  }
}
