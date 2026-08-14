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
 * RegisterPanel tests: the attestation ceremony happy path through the
 * injected provider + client, and failure surfacing back to the form.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/svelte';

import RegisterPanel from '../src/components/RegisterPanel.svelte';
import {
  configureAuthStore,
  setAuthStatus,
  tokenKey,
} from '../src/stores/auth.svelte.ts';
import type { CredentialProvider } from '../src/provider.ts';
import type { AttestationCredentialJSON } from '@go-xkms/sdk';
import { FakeApiError, makeFakeClient, tokenPair } from './helpers.ts';

const attestationJSON: AttestationCredentialJSON = {
  id: 'new-cred',
  rawId: 'bmV3LWNyZWQ',
  type: 'public-key',
  response: {
    clientDataJSON: 'Y2Q',
    attestationObject: 'YW8',
  },
  clientExtensionResults: {},
};

function makeProvider(overrides?: Partial<CredentialProvider>): CredentialProvider {
  return {
    methods: vi.fn(async () => ['passkey'] as const),
    getAssertion: vi.fn(async () => {
      throw new Error('not used in registration');
    }),
    createCredential: vi.fn(async () => attestationJSON),
    loginCertificate: vi.fn(async () => tokenPair('x', 'y')),
    ...overrides,
  } as CredentialProvider;
}

/** Fill the form and click Create account. */
async function submitRegistration(email: string, displayName: string): Promise<void> {
  const emailInput = await screen.findByLabelText('Email');
  await fireEvent.input(emailInput, { target: { value: email } });
  const displayInput = screen.getByLabelText('Display name');
  await fireEvent.input(displayInput, { target: { value: displayName } });
  const submit = screen.getByRole('button', { name: 'Create account with passkey' });
  await fireEvent.click(submit);
}

describe('RegisterPanel', () => {
  let fake = makeFakeClient();

  beforeEach(() => {
    window.localStorage.clear();
    fake = makeFakeClient();
    configureAuthStore({ client: fake.client });
    setAuthStatus('pending');
  });

  it('completes the registration ceremony and reports tokens to onSuccess', async () => {
    const provider = makeProvider();
    fake.mocks.webAuthnRegisterBegin.mockResolvedValue({
      options: { publicKey: { challenge: 'cmVnLWNoYWxsZW5nZQ' } },
      sessionId: 'reg-sess-1',
    });
    fake.mocks.webAuthnRegisterFinish.mockResolvedValue({
      token: 'reg-acc',
      refresh_token: 'reg-ref',
      user_id: 'user-9',
    });
    const me = { subject: 'user-9', permissions: {}, capabilities: {} };
    fake.mocks.me.mockResolvedValue(me);
    const onSuccess = vi.fn();

    render(RegisterPanel, {
      props: { provider, client: fake.client, onSuccess },
    });
    await submitRegistration('jane@example.com', 'Jane Smith');

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(onSuccess).toHaveBeenCalledWith(
      { access_token: 'reg-acc', refresh_token: 'reg-ref' },
      me,
    );
    expect(fake.mocks.webAuthnRegisterBegin).toHaveBeenCalledWith({
      email: 'jane@example.com',
      display_name: 'Jane Smith',
    });
    expect(provider.createCredential).toHaveBeenCalledWith({
      publicKey: { challenge: 'cmVnLWNoYWxsZW5nZQ' },
    });
    expect(fake.mocks.webAuthnRegisterFinish).toHaveBeenCalledWith(
      'reg-sess-1',
      attestationJSON,
    );
    // Tokens landed in the shared store and the done stage is shown.
    expect(window.localStorage.getItem(tokenKey())).toBe('reg-acc');
    expect(await screen.findByText('Account created')).toBeTruthy();
  });

  it('surfaces a registration-disabled rejection and returns to the form', async () => {
    const provider = makeProvider();
    fake.mocks.webAuthnRegisterBegin.mockRejectedValue(
      new FakeApiError(403, 'self-service registration disabled'),
    );
    const onSuccess = vi.fn();

    render(RegisterPanel, {
      props: { provider, client: fake.client, onSuccess },
    });
    await submitRegistration('jane@example.com', 'Jane Smith');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('not enabled on this server');
    expect(onSuccess).not.toHaveBeenCalled();
    // Back on the form for another attempt.
    expect(screen.getByLabelText('Email')).toBeTruthy();
    expect(window.localStorage.getItem(tokenKey())).toBeNull();
  });

  it('surfaces a declined authenticator ceremony', async () => {
    const provider = makeProvider({
      createCredential: vi.fn(async () => {
        throw new DOMException('cancelled', 'NotAllowedError');
      }),
    });
    fake.mocks.webAuthnRegisterBegin.mockResolvedValue({
      options: { publicKey: { challenge: 'Yw' } },
      sessionId: 'reg-sess-2',
    });

    render(RegisterPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    await submitRegistration('jane@example.com', '');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('declined or cancelled');
    // display_name was blank, so it was omitted from the begin request.
    expect(fake.mocks.webAuthnRegisterBegin).toHaveBeenCalledWith({
      email: 'jane@example.com',
    });
  });

  // -------------------------------------------------------------------------
  // Identifier validation
  // -------------------------------------------------------------------------

  it('the Enter key on the display-name field submits the form too', async () => {
    fake.mocks.webAuthnRegisterBegin.mockResolvedValue({
      options: { publicKey: { challenge: 'Yw' } },
      sessionId: 'reg-sess-enter',
    });
    fake.mocks.webAuthnRegisterFinish.mockResolvedValue({ token: 'acc-1', user_id: 'u1' });

    render(RegisterPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    const emailInput = await screen.findByLabelText('Email');
    await fireEvent.input(emailInput, { target: { value: 'jane@example.com' } });
    const displayInput = screen.getByLabelText('Display name');
    await fireEvent.input(displayInput, { target: { value: 'Jane' } });
    await fireEvent.keyDown(displayInput, { key: 'Enter' });

    await vi.waitFor(() =>
      expect(fake.mocks.webAuthnRegisterBegin).toHaveBeenCalledWith({
        email: 'jane@example.com',
        display_name: 'Jane',
      }),
    );
    await waitFor(() => expect(screen.getByText('Account created')).toBeTruthy());
  });

  it('rejects an empty identifier submitted via Enter without calling the server', async () => {
    render(RegisterPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    const emailInput = await screen.findByLabelText('Email');

    // The submit button is disabled while empty; the Enter-key handler on
    // the input calls handleSubmit() directly regardless.
    await fireEvent.keyDown(emailInput, { key: 'Enter' });

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Please enter your email.');
    expect(fake.mocks.webAuthnRegisterBegin).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // begin() failure branches beyond 403
  // -------------------------------------------------------------------------

  it('surfaces the server message for a 400/409 (invalid request) rejection', async () => {
    fake.mocks.webAuthnRegisterBegin.mockRejectedValue(
      new FakeApiError(409, 'email already registered'),
    );

    render(RegisterPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    await submitRegistration('jane@example.com', '');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('email already registered');
  });

  it('surfaces the network-failure message when begin cannot reach the server', async () => {
    fake.mocks.webAuthnRegisterBegin.mockRejectedValue(new TypeError('Failed to fetch'));

    render(RegisterPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    await submitRegistration('jane@example.com', '');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain("Can't reach the server right now.");
  });

  it('surfaces the message of an unrecognized Error, and a fallback for a non-Error throw', async () => {
    fake.mocks.webAuthnRegisterBegin.mockRejectedValue(new Error('unexpected server fault'));

    render(RegisterPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    await submitRegistration('jane@example.com', '');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('unexpected server fault');
    cleanup();

    const fakeB = makeFakeClient();
    configureAuthStore({ client: fakeB.client });
    fakeB.mocks.webAuthnRegisterBegin.mockRejectedValue('not an Error instance');

    render(RegisterPanel, {
      props: { provider: makeProvider(), client: fakeB.client, onSuccess: vi.fn() },
    });
    await submitRegistration('jane@example.com', '');

    const alertB = await screen.findByRole('alert');
    expect(alertB.textContent).toContain('Registration failed. Please try again.');
  });

  // -------------------------------------------------------------------------
  // createCredential failure beyond decline
  // -------------------------------------------------------------------------

  it('surfaces the underlying message when the authenticator ceremony fails without a decline', async () => {
    const provider = makeProvider({
      createCredential: vi.fn(async () => {
        throw new Error('authenticator hardware fault');
      }),
    });
    fake.mocks.webAuthnRegisterBegin.mockResolvedValue({
      options: { publicKey: { challenge: 'Yw' } },
      sessionId: 'reg-sess-3',
    });

    render(RegisterPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    await submitRegistration('jane@example.com', '');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('authenticator hardware fault');
  });

  // -------------------------------------------------------------------------
  // finish() failure branches
  // -------------------------------------------------------------------------

  it('surfaces the network-failure message when finish cannot reach the server', async () => {
    const provider = makeProvider();
    fake.mocks.webAuthnRegisterBegin.mockResolvedValue({
      options: { publicKey: { challenge: 'Yw' } },
      sessionId: 'reg-sess-4',
    });
    fake.mocks.webAuthnRegisterFinish.mockRejectedValue(new TypeError('Failed to fetch'));

    render(RegisterPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    await submitRegistration('jane@example.com', '');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain("Can't reach the server right now.");
  });

  it('surfaces the underlying message when finish is rejected for a non-network reason', async () => {
    const provider = makeProvider();
    fake.mocks.webAuthnRegisterBegin.mockResolvedValue({
      options: { publicKey: { challenge: 'Yw' } },
      sessionId: 'reg-sess-5',
    });
    fake.mocks.webAuthnRegisterFinish.mockRejectedValue(
      new FakeApiError(500, 'attestation verification failed'),
    );

    render(RegisterPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    await submitRegistration('jane@example.com', '');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('attestation verification failed');
  });

  it('surfaces a server contract violation when finish returns no token', async () => {
    const provider = makeProvider();
    fake.mocks.webAuthnRegisterBegin.mockResolvedValue({
      options: { publicKey: { challenge: 'Yw' } },
      sessionId: 'reg-sess-6',
    });
    fake.mocks.webAuthnRegisterFinish.mockResolvedValue({ token: '', user_id: 'user-1' });

    render(RegisterPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    await submitRegistration('jane@example.com', '');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain(
      'Registration did not return a session token',
    );
  });

  // -------------------------------------------------------------------------
  // /me failing after a successful registration
  // -------------------------------------------------------------------------

  it('surfaces the fallback message when a begin rejection carries no message', async () => {
    fake.mocks.webAuthnRegisterBegin.mockRejectedValue({ status: 409 });

    render(RegisterPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    await submitRegistration('jane@example.com', '');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain(
      'Invalid registration request. Check your inputs and try again.',
    );
  });

  it('falls back to the generic authenticator message for a non-Error, non-decline throw', async () => {
    const provider = makeProvider({
      createCredential: vi.fn(async () => {
        throw { reason: 'unexpected' };
      }),
    });
    fake.mocks.webAuthnRegisterBegin.mockResolvedValue({
      options: { publicKey: { challenge: 'Yw' } },
      sessionId: 'reg-sess-8',
    });

    render(RegisterPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    await submitRegistration('jane@example.com', '');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Authenticator interaction failed.');
  });

  it('falls back to the generic registration-failed message for a non-Error finish rejection', async () => {
    const provider = makeProvider();
    fake.mocks.webAuthnRegisterBegin.mockResolvedValue({
      options: { publicKey: { challenge: 'Yw' } },
      sessionId: 'reg-sess-9',
    });
    fake.mocks.webAuthnRegisterFinish.mockRejectedValue({ reason: 'unexpected' });

    render(RegisterPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    await submitRegistration('jane@example.com', '');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Registration failed. Please try again.');
  });

  it('ignores a second submission (and shows the spinner) while one is already in flight', async () => {
    let releaseBegin: (v: unknown) => void = () => {};
    fake.mocks.webAuthnRegisterBegin.mockImplementation(
      () =>
        new Promise((resolve) => {
          releaseBegin = resolve;
        }),
    );

    render(RegisterPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    const emailInput = await screen.findByLabelText('Email');
    await fireEvent.input(emailInput, { target: { value: 'jane@example.com' } });

    // Two Enter keydowns dispatched back to back, without letting Svelte
    // flush a re-render in between: handleSubmit() sets `busy` and flips the
    // stage synchronously (before its first await), so the SECOND call —
    // still landing on the not-yet-torn-down form — must be caught by the
    // `if (busy) return` guard rather than starting a second begin() call.
    fireEvent.keyDown(emailInput, { key: 'Enter' });
    fireEvent.keyDown(emailInput, { key: 'Enter' });
    await vi.waitFor(() => expect(fake.mocks.webAuthnRegisterBegin).toHaveBeenCalled());
    expect(fake.mocks.webAuthnRegisterBegin).toHaveBeenCalledTimes(1);
    expect(
      screen.getByText('Touch your hardware security key when prompted by the browser…'),
    ).toBeTruthy();

    fake.mocks.webAuthnRegisterFinish.mockResolvedValue({ token: 'acc-1', user_id: 'u1' });
    releaseBegin({
      options: { publicKey: { challenge: 'Yw' } },
      sessionId: 'reg-sess-10',
    });
    await waitFor(() => expect(screen.getByText('Account created')).toBeTruthy());
  });

  it('reports onSuccess with a null identity when /me fails after a successful registration', async () => {
    const provider = makeProvider();
    fake.mocks.webAuthnRegisterBegin.mockResolvedValue({
      options: { publicKey: { challenge: 'Yw' } },
      sessionId: 'reg-sess-7',
    });
    fake.mocks.webAuthnRegisterFinish.mockResolvedValue({
      token: 'reg-acc',
      refresh_token: 'reg-ref',
      user_id: 'user-9',
    });
    fake.mocks.me.mockRejectedValue(new FakeApiError(500, 'me unavailable'));
    const onSuccess = vi.fn();

    render(RegisterPanel, {
      props: { provider, client: fake.client, onSuccess },
    });
    await submitRegistration('jane@example.com', 'Jane Smith');

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(onSuccess).toHaveBeenCalledWith(
      { access_token: 'reg-acc', refresh_token: 'reg-ref' },
      null,
    );
    // The session is still established even though /me failed.
    expect(window.localStorage.getItem(tokenKey())).toBe('reg-acc');
    expect(await screen.findByText('Account created')).toBeTruthy();
  });
});
