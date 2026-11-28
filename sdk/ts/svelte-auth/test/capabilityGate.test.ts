/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of go-xkms.
 *
 * go-xkms is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

// Ruling 972 (1): no control may lead to a 501 / "not configured" state.
// RegisterPanel and LoginPanel read /api/v1/capabilities through the same
// helper and show the same disabled state, naming the setting to turn on.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/svelte';

import RegisterPanel from '../src/components/RegisterPanel.svelte';
import LoginPanel from '../src/components/LoginPanel.svelte';
import {
  AUTH_CAPABILITY,
  REGISTRATION_DISABLED_MESSAGE,
  SIGN_IN_DISABLED_MESSAGE,
  methodOff,
  readAuthCapabilities,
} from '../src/capabilities.ts';
import { configureAuthStore, setAuthStatus } from '../src/stores/auth.svelte.ts';
import type { CredentialProvider } from '../src/provider.ts';
import type { AuthClientHost } from '../src/config.ts';
import { makeFakeClient } from './helpers.ts';

function provider(): CredentialProvider {
  return {
    methods: vi.fn(async () => ['passkey', 'certificate'] as const),
    createCredential: vi.fn(),
    getAssertion: vi.fn(),
  } as unknown as CredentialProvider;
}

function withCapabilities(caps: Record<string, unknown>) {
  const fake = makeFakeClient();
  const get = vi.fn(async () => caps);
  const client = { ...fake.client, capabilities: { get } } as unknown as AuthClientHost;
  return { client, mocks: fake.mocks, get };
}

describe('capability gate (ruling 972 (1))', () => {
  beforeEach(() => {
    cleanup();
    window.localStorage.clear();
    configureAuthStore({ client: makeFakeClient().client });
    setAuthStatus('pending');
  });

  it('RegisterPanel with webauthn off names webauthn.enabled and never calls registration/begin', async () => {
    const { client, mocks, get } = withCapabilities({ webauthn_enabled: false });
    render(RegisterPanel, { props: { provider: provider(), client, onSuccess: vi.fn() } });

    const note = await screen.findByTestId('svelte-auth-register-disabled');
    expect(note.textContent).toContain('webauthn.enabled');
    expect(note.textContent).toBe(REGISTRATION_DISABLED_MESSAGE);
    expect(screen.queryByLabelText('Create account with passkey')).toBeNull();
    expect(get).toHaveBeenCalledTimes(1);
    expect(mocks.webAuthnRegisterBegin).not.toHaveBeenCalled();
  });

  it('RegisterPanel with webauthn on shows the form', async () => {
    const { client } = withCapabilities({ webauthn_enabled: true });
    render(RegisterPanel, { props: { provider: provider(), client, onSuccess: vi.fn() } });

    expect(await screen.findByLabelText('Create account with passkey')).toBeTruthy();
    expect(screen.queryByTestId('svelte-auth-register-disabled')).toBeNull();
  });

  it('LoginPanel with webauthn and PIV login off names both settings', async () => {
    const { client } = withCapabilities({ webauthn_enabled: false, piv_login_enabled: false });
    render(LoginPanel, { props: { provider: provider(), client, onSuccess: vi.fn() } });

    const passkey = await screen.findByTestId('svelte-auth-login-disabled-passkey');
    expect(passkey.textContent).toBe(SIGN_IN_DISABLED_MESSAGE.passkey);
    expect(passkey.textContent).toContain('webauthn.enabled');
    const cert = await screen.findByTestId('svelte-auth-login-disabled-certificate');
    expect(cert.textContent).toContain('auth.piv_login.enabled');
    expect(screen.queryByLabelText('Sign in with passkey')).toBeNull();
  });

  it('both panels gate passkeys on the same capability key', () => {
    expect(AUTH_CAPABILITY.passkey).toBe('webauthn_enabled');
    expect(AUTH_CAPABILITY.certificate).toBe('piv_login_enabled');
    expect(REGISTRATION_DISABLED_MESSAGE).toContain('webauthn.enabled');
  });

  it('methodOff is true only for an explicit false; a missing key or failed probe leaves it on', async () => {
    expect(methodOff({ webauthn_enabled: false }, 'passkey')).toBe(true);
    expect(methodOff({ webauthn_enabled: true }, 'passkey')).toBe(false);
    expect(methodOff({}, 'passkey')).toBe(false);
    expect(methodOff(null, 'passkey')).toBe(false);

    const failing = {
      ...makeFakeClient().client,
      capabilities: { get: vi.fn(async () => Promise.reject(new Error('down'))) },
    } as unknown as AuthClientHost;
    expect(await readAuthCapabilities(failing)).toBeNull();
    expect(await readAuthCapabilities(makeFakeClient().client)).toBeNull();
  });

  it('LoginPanel with webauthn on shows no disabled note', async () => {
    const { client } = withCapabilities({ webauthn_enabled: true, piv_login_enabled: true });
    render(LoginPanel, { props: { provider: provider(), client, onSuccess: vi.fn() } });
    await waitFor(() => expect(screen.queryByLabelText('Sign in with passkey')).toBeTruthy());
    expect(screen.queryByTestId('svelte-auth-login-disabled-passkey')).toBeNull();
  });
});
