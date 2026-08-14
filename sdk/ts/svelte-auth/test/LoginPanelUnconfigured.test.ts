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
 * LoginPanel rendered BEFORE configureAuthStore() has run.
 *
 * Deliberately its own test file (see authStoreUnconfigured.test.ts for why):
 * `initialTenant()` consults the store's tenant-memory key only when
 * isAuthStoreConfigured() is true, and every other LoginPanel test configures
 * the store in a beforeEach. A fresh, never-configured module instance is the
 * only way to exercise the raw-defaultTenant fallback.
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';

import LoginPanel from '../src/components/LoginPanel.svelte';
import type { CredentialProvider } from '../src/provider.ts';
import { makeFakeClient } from './helpers.ts';

describe('LoginPanel before the auth store is configured', () => {
  it('falls back to the raw defaultTenant prop when there is no store to consult for a remembered value', async () => {
    const { client } = makeFakeClient();
    const provider: CredentialProvider = {
      methods: vi.fn(async () => ['passkey'] as const),
      getAssertion: vi.fn(),
      createCredential: vi.fn(),
      loginCertificate: vi.fn(),
    } as unknown as CredentialProvider;

    render(LoginPanel, {
      props: {
        provider,
        client,
        defaultTenant: 'unconfigured-org',
        onSuccess: vi.fn(),
      },
    });

    const tenantInput = (await screen.findByLabelText(
      'Organization',
    )) as HTMLInputElement;
    expect(tenantInput.value).toBe('unconfigured-org');
  });
});
