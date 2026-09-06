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
 * Session / WebAuthn DTOs. Mirrors pkg/api/rest/handlers_auth.go and
 * pkg/webauthn/http/types.go.
 */

/** Mirrors handlers_auth.go authTokenResponse (login/piv, refresh). */
export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

/** Mirrors handlers_auth.go authRefreshRequest (refresh, logout). */
export interface RefreshRequest {
  refresh_token: string;
}

/** Mirrors handlers_auth.go authMeResponse (GET /api/v1/auth/me). */
export interface AuthMeResponse {
  subject: string;
  tenant_id?: string;
  username?: string;
  /** Canonical tenant-unique login key; absent for principals without one. */
  email?: string;
  display_name?: string;
  auth_method?: string;
  roles?: string[];
  /** "resource:action" -> allowed */
  permissions: Record<string, boolean>;
  /** capability flag -> wired */
  capabilities: Record<string, boolean>;
}

/** Mirrors handlers_auth.go authValidateResponse (GET /api/v1/auth/validate). */
export interface AuthValidateResponse {
  subject: string;
  tenant_id?: string;
}

/** Mirrors pkg/webauthn/http/types.go BeginRegistrationRequest. */
export interface WebAuthnBeginRegistrationRequest {
  email: string;
  display_name?: string;
}

/** Mirrors pkg/webauthn/http/types.go BeginLoginRequest. */
export interface WebAuthnBeginLoginRequest {
  /** base64-encoded user ID (optional; omit for discoverable-credential flow) */
  user_id?: string;
  /** email alternative to user_id */
  email?: string;
}

/** Mirrors pkg/webauthn/http/types.go RegistrationStatusResponse. */
export interface WebAuthnRegistrationStatusResponse {
  registered: boolean;
}

/** Mirrors pkg/webauthn/http/types.go AuthResponse (finish registration/login). */
export interface WebAuthnAuthResponse {
  token: string;
  refresh_token?: string;
  user_id: string;
}

/**
 * A begin-ceremony result: the raw go-webauthn options envelope (feed it to
 * parseCreationOptions / parseRequestOptions) plus the session correlation
 * values the server returned via the X-Session-Id / X-User-Id headers.
 */
export interface WebAuthnCeremonyStart {
  /** Raw options envelope ({ publicKey: { challenge, ... } }). */
  options: unknown;
  /** X-Session-Id header value; echo it back on the finish call. */
  sessionId: string;
  /** X-User-Id header value (login/begin only, when resolvable). */
  userId?: string;
}
