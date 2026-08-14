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
 * Auth store behaviour BEFORE configureAuthStore() has ever run.
 *
 * Deliberately its own test file: `config` is a module-level singleton in
 * src/stores/auth.svelte.ts and every other suite configures it in a
 * beforeEach, so the only way to observe the pre-configuration state is a
 * fresh module instance that never calls configureAuthStore — which is what
 * a separate vitest test file (isolated module registry) gives us.
 */

import { describe, it, expect } from 'vitest';

import { authConfig, handleStorageEvent, tokenKey } from '../src/stores/auth.svelte.ts';
import { AuthNotConfiguredError } from '../src/config.ts';

describe('auth store before configureAuthStore has run', () => {
  it('authConfig throws AuthNotConfiguredError', () => {
    expect(() => authConfig()).toThrow(AuthNotConfiguredError);
  });

  it('tokenKey (and anything else deriving a storage key) surfaces the same error', () => {
    expect(() => tokenKey()).toThrow(AuthNotConfiguredError);
  });

  it('handleStorageEvent is a silent no-op instead of throwing', () => {
    // A cross-tab storage event can arrive before this tab's own bootstrap
    // has called configureAuthStore; it must be ignored, not crash the tab.
    expect(() =>
      handleStorageEvent(
        new StorageEvent('storage', { key: 'xkms_token', newValue: 'access-1' }),
      ),
    ).not.toThrow();
  });
});
