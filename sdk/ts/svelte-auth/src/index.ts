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
 * @go-xkms/svelte-auth — reusable Svelte 5 passwordless-login surface for
 * go-xkms deployments: reactive token store, 401-recovery fetch layer,
 * CredentialProvider seam, and LoginPanel / RegisterPanel components.
 */

// Configuration
export {
  DEFAULT_API_PREFIXES,
  DEFAULT_REFRESH_PATH,
  DEFAULT_STORAGE_PREFIX,
  AuthNotConfiguredError,
  resolveAuthConfig,
  type AuthApi,
  type AuthCeremonyApi,
  type AuthClientHost,
  type AuthPackageConfig,
  type AuthSessionApi,
  type ResolvedAuthConfig,
} from './config.ts';

// Token store
export {
  authStore,
  authConfig,
  configureAuthStore,
  endSession,
  getValidAccessToken,
  handleStorageEvent,
  installCrossTabSync,
  isAuthStoreConfigured,
  readAuthToken,
  readRefreshToken,
  refreshAccessToken,
  refreshTokenKey,
  setAuthStatus,
  setAuthenticated,
  tokenKey,
  validateSession,
  type AuthStatus,
  type AuthTokens,
} from './stores/auth.svelte.ts';

// 401-recovery fetch layer
export {
  installAuthFetch,
  uninstallAuthFetch,
  type AuthFetchOptions,
} from './authFetch.ts';

// Credential provider seam
export {
  BrowserCredentialProvider,
  CredentialCeremonyError,
  isNetworkFailure,
  isUserDeclined,
  type AuthMethod,
  type CredentialProvider,
  type TokenPairResponse,
} from './provider.ts';

// One-time wiring
export {
  initAuth,
  resetAuth,
  type AuthContext,
  type InitAuthOptions,
} from './context.ts';

// Components
export { default as LoginPanel } from './components/LoginPanel.svelte';
export { default as RegisterPanel } from './components/RegisterPanel.svelte';
