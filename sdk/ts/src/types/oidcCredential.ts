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
 * Server-side OIDC credential DTOs. Mirrors
 * pkg/api/transport/types_oidc_credential.go — served over REST at
 * /api/v1/oidc/credentials and /api/v1/oidc/credentials/{scope}/{name}.
 *
 * A credential is a named OAuth/OIDC login xkmsd holds on the tenant barrier
 * and refreshes itself. Consumers ask for a current access token by
 * reference; the server never hands out the refresh token.
 */

import type { RFC3339 } from './common.js';

/** Credential scope: "tenant" (shared) or "user" (personal, owner-only). */
export type OIDCCredentialScope = 'tenant' | 'user';

/** Credential status (pkg/api/transport OIDCCredentialStatus*). */
export type OIDCCredentialStatus = 'pending' | 'active' | 'relogin_required' | 'expired';

/** Mirrors transport.OIDCCredentialRef: names a credential. */
export interface OIDCCredentialRef {
  /** The tenant holding the credential; empty is the caller's. */
  tenant_id?: string;
  scope: OIDCCredentialScope;
  /** The owning subject of a personal credential; empty is the caller. */
  owner?: string;
  name: string;
}

/**
 * Mirrors transport.OIDCCredentialConfig: a credential's provider
 * configuration. A template fills every field left empty; endpoints left
 * empty are discovered from the issuer at creation.
 */
export interface OIDCCredentialConfig {
  template?: string;
  issuer?: string;
  client_id?: string;
  /** Write-only: never returned on a credential's public view. */
  client_secret?: string;
  scopes?: string[];
  authorization_endpoint?: string;
  token_endpoint?: string;
  device_authorization_endpoint?: string;
  /** "form" (default) or "json". */
  token_encoding?: 'form' | 'json';
  /** "rfc8628" (default) or "openai". */
  device_style?: 'rfc8628' | 'openai';
  /** A provider whose tokens cannot be refreshed. */
  no_refresh?: boolean;
  /** Dates an imported opaque token of a no_refresh provider. */
  token_lifetime_seconds?: number;
  /** How long before expiry the server refreshes; 0 is five minutes. */
  refresh_margin_seconds?: number;
}

/** Mirrors transport.OIDCCredentialTokens: tokens imported into a credential. */
export interface OIDCCredentialTokens {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type?: string;
  scope?: string;
  /** Absent: read from a JWT access token or the template's token lifetime. */
  expires_at?: RFC3339;
}

/** Mirrors transport.OIDCCredentialCreateRequest. */
export interface OIDCCredentialCreateRequest extends OIDCCredentialRef {
  config: OIDCCredentialConfig;
  /** Present for an import-at-create; absent leaves the credential pending. */
  tokens?: OIDCCredentialTokens;
}

/** Mirrors transport.OIDCDeviceLogin: what the user needs to approve a device login. */
export interface OIDCDeviceLogin {
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  interval_seconds: number;
  expires_at: RFC3339;
}

/** Mirrors transport.OIDCCredential: a credential's public view (no tokens, no client secret). */
export interface OIDCCredential extends OIDCCredentialRef {
  config: OIDCCredentialConfig;
  status: OIDCCredentialStatus;
  status_reason?: string;
  expires_at?: RFC3339;
  refreshable: boolean;
  last_refresh?: RFC3339;
  last_error?: string;
  device_login?: OIDCDeviceLogin;
  created_at: RFC3339;
  updated_at: RFC3339;
  created_by?: string;
}

/** Mirrors transport.OIDCCredentialListResponse. */
export interface OIDCCredentialListResponse {
  credentials: OIDCCredential[];
}

/** Mirrors transport.OIDCAccessToken: a current access token of a credential. */
export interface OIDCAccessToken {
  access_token: string;
  token_type: string;
  expires_at?: RFC3339;
  /** The login's ID token, when it has one. */
  id_token?: string;
  scope?: string;
}
