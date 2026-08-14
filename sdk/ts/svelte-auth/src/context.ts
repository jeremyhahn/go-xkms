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
 * One-time package wiring. Call initAuth(config) once at app bootstrap:
 * it configures the token store, installs the 401-recovery fetch layer,
 * subscribes to cross-tab storage sync, and hands back the reactive store
 * plus the CredentialProvider the panels should use.
 */

import type { AuthPackageConfig } from './config.ts';
import {
  authStore,
  configureAuthStore,
  installCrossTabSync,
} from './stores/auth.svelte.ts';
import { installAuthFetch, uninstallAuthFetch } from './authFetch.ts';
import { BrowserCredentialProvider, type CredentialProvider } from './provider.ts';

/** Options accepted by initAuth beyond the base package config. */
export interface InitAuthOptions extends AuthPackageConfig {
  /**
   * Credential source for the panels. Defaults to BrowserCredentialProvider
   * (navigator.credentials + SDK loginCert); a desktop shell injects its own.
   */
  provider?: CredentialProvider;
  /** Set false to skip the global window.fetch 401 interceptor. */
  installFetchInterceptor?: boolean;
}

/** What initAuth returns: the reactive store and the active provider. */
export interface AuthContext {
  authStore: typeof authStore;
  provider: CredentialProvider;
}

let _context: AuthContext | null = null;
let _uninstallCrossTab: (() => void) | null = null;

/**
 * initAuth wires the package once and returns the shared context. Subsequent
 * calls return the existing context unchanged (one-time wiring by design).
 */
export function initAuth(options: InitAuthOptions): AuthContext {
  if (_context !== null) return _context;

  configureAuthStore(options);
  if (options.installFetchInterceptor !== false) {
    installAuthFetch();
  }
  _uninstallCrossTab = installCrossTabSync();

  const provider = options.provider ?? new BrowserCredentialProvider(options.client);
  _context = { authStore, provider };
  return _context;
}

/**
 * resetAuth tears the wiring down (fetch interceptor, cross-tab listener,
 * cached context). Intended for tests; a real app never calls it.
 */
export function resetAuth(): void {
  uninstallAuthFetch();
  if (_uninstallCrossTab !== null) {
    _uninstallCrossTab();
    _uninstallCrossTab = null;
  }
  _context = null;
}
