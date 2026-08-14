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

/** initAuth wiring tests: one-time setup, provider injection, teardown. */

import { describe, it, expect, afterEach, vi } from 'vitest';

import { initAuth, resetAuth } from '../src/context.ts';
import { BrowserCredentialProvider, type CredentialProvider } from '../src/provider.ts';
import { authStore, isAuthStoreConfigured } from '../src/stores/auth.svelte.ts';
import { makeFakeClient, tokenPair } from './helpers.ts';

describe('initAuth', () => {
  afterEach(() => {
    resetAuth();
    vi.unstubAllGlobals();
  });

  it('configures the store, installs the fetch layer, and returns the context', () => {
    const { client } = makeFakeClient();
    const nativeFetch = window.fetch;

    const ctx = initAuth({ client });

    expect(isAuthStoreConfigured()).toBe(true);
    expect(ctx.authStore).toBe(authStore);
    expect(ctx.provider).toBeInstanceOf(BrowserCredentialProvider);
    // The 401 interceptor replaced window.fetch.
    expect(window.fetch).not.toBe(nativeFetch);
  });

  it('is one-time: a second call returns the same context', () => {
    const { client } = makeFakeClient();
    const first = initAuth({ client });
    const second = initAuth({ client: makeFakeClient().client });

    expect(second).toBe(first);
  });

  it('honors an injected desktop provider and skips the interceptor on request', () => {
    const { client } = makeFakeClient();
    const nativeFetch = window.fetch;
    const desktop: CredentialProvider = {
      methods: vi.fn(async () => ['passkey'] as const),
      getAssertion: vi.fn(),
      createCredential: vi.fn(),
      loginCertificate: vi.fn(async () => tokenPair('a', 'r')),
    } as unknown as CredentialProvider;

    const ctx = initAuth({ client, provider: desktop, installFetchInterceptor: false });

    expect(ctx.provider).toBe(desktop);
    expect(window.fetch).toBe(nativeFetch);
  });
});
