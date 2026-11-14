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
 * TokenProvider yields the current bearer token. It runs once per request so
 * a refreshing session store can always hand out the newest access token.
 * Return an empty string (or undefined-equivalent empty value) to send the
 * request without an Authorization header.
 */
export type TokenProvider = () => string | Promise<string>;

/** Session/auth endpoint paths, overridable per deployment. */
export interface AuthPaths {
  loginCert: string;
  refresh: string;
  validate: string;
  logout: string;
  me: string;
  capabilities: string;
}

/** The default auth endpoint paths served by xkmsd's REST transport. */
export const DEFAULT_AUTH_PATHS: AuthPaths = {
  loginCert: '/api/v1/auth/login/piv',
  refresh: '/api/v1/auth/refresh',
  validate: '/api/v1/auth/validate',
  logout: '/api/v1/auth/logout',
  me: '/api/v1/auth/me',
  capabilities: '/api/v1/capabilities',
};

/** XkmsClientConfig configures the XkmsClient facade and every domain client. */
export interface XkmsClientConfig {
  /** Server origin, e.g. `https://xkms.example.com:8443`. */
  baseURL: string;
  /** Optional bearer token source, resolved per request. */
  token?: TokenProvider;
  /** Injectable fetch (tests, Node polyfills). Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
  /** Auth endpoint path overrides; missing members use DEFAULT_AUTH_PATHS. */
  authPaths?: Partial<AuthPaths>;
  /**
   * Lets a call that carries a credential (image signing with registry
   * credentials) go to a base URL that is not https://, and follow its
   * redirects. Unsafe: loopback tests and dev setups only, never production.
   * Mirrors the Go transports' AllowInsecureTransport (ruling 152).
   */
  allowInsecureTransport?: boolean;
}

/** resolveAuthPaths merges configured overrides over the defaults. */
export function resolveAuthPaths(overrides?: Partial<AuthPaths>): AuthPaths {
  return { ...DEFAULT_AUTH_PATHS, ...(overrides ?? {}) };
}
