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
 * LoginPanel tests: method chooser rendering, the passkey happy path through
 * an injected provider + client, the SINGLE generic anti-enumeration failure
 * message, and the certificate path.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/svelte';

import LoginPanel from '../src/components/LoginPanel.svelte';
import {
  configureAuthStore,
  setAuthStatus,
  tokenKey,
} from '../src/stores/auth.svelte.ts';
import type { CredentialProvider } from '../src/provider.ts';
import type { AssertionCredentialJSON } from '@go-xkms/sdk';
import { FakeApiError, makeFakeClient, tokenPair } from './helpers.ts';

const assertionJSON: AssertionCredentialJSON = {
  id: 'cred-1',
  rawId: 'Y3JlZC0x',
  type: 'public-key',
  response: {
    clientDataJSON: 'Y2Q',
    authenticatorData: 'YWQ',
    signature: 'c2ln',
  },
  clientExtensionResults: {},
};

function makeProvider(overrides?: Partial<CredentialProvider>): CredentialProvider {
  return {
    methods: vi.fn(async () => ['passkey', 'certificate'] as const),
    getAssertion: vi.fn(async () => assertionJSON),
    createCredential: vi.fn(async () => {
      throw new Error('not used in login');
    }),
    loginCertificate: vi.fn(async () => tokenPair('cert-acc', 'cert-ref')),
    ...overrides,
  } as CredentialProvider;
}

/** Drive the passkey flow up to (and including) the Authenticate click. */
async function submitPasskey(email: string): Promise<void> {
  const passkeyBtn = await screen.findByRole('button', { name: 'Sign in with passkey' });
  await fireEvent.click(passkeyBtn);
  const input = await screen.findByLabelText('Email');
  await fireEvent.input(input, { target: { value: email } });
  const authBtn = screen.getByRole('button', { name: 'Authenticate with passkey' });
  await fireEvent.click(authBtn);
}

describe('LoginPanel', () => {
  let fake = makeFakeClient();

  beforeEach(() => {
    window.localStorage.clear();
    fake = makeFakeClient();
    configureAuthStore({ client: fake.client });
    setAuthStatus('pending');
  });

  it('renders both method buttons reported by the provider', async () => {
    render(LoginPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });

    expect(
      await screen.findByRole('button', { name: 'Sign in with passkey' }),
    ).toBeTruthy();
    expect(
      await screen.findByRole('button', { name: 'Sign in with certificate' }),
    ).toBeTruthy();
  });

  it('renders only the methods the provider offers', async () => {
    const provider = makeProvider({ methods: vi.fn(async () => ['passkey']) });
    render(LoginPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });

    await screen.findByRole('button', { name: 'Sign in with passkey' });
    expect(
      screen.queryByRole('button', { name: 'Sign in with certificate' }),
    ).toBeNull();
  });

  it('completes the passkey happy path and reports tokens to onSuccess', async () => {
    const provider = makeProvider();
    fake.mocks.webAuthnBeginLogin.mockResolvedValue({
      options: { publicKey: { challenge: 'Y2hhbGxlbmdl' } },
      sessionId: 'sess-1',
      userId: 'user-1',
    });
    fake.mocks.webAuthnFinishLogin.mockResolvedValue({
      token: 'acc-1',
      refresh_token: 'ref-1',
      user_id: 'user-1',
    });
    const me = { subject: 'user-1', permissions: {}, capabilities: {} };
    fake.mocks.me.mockResolvedValue(me);
    const onSuccess = vi.fn();

    render(LoginPanel, {
      props: { provider, client: fake.client, onSuccess },
    });
    await submitPasskey('jane@example.com');

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(onSuccess).toHaveBeenCalledWith(
      { access_token: 'acc-1', refresh_token: 'ref-1' },
      me,
    );
    // The ceremony ran through the injected seams end to end.
    expect(fake.mocks.webAuthnBeginLogin).toHaveBeenCalledWith({
      email: 'jane@example.com',
    });
    expect(provider.getAssertion).toHaveBeenCalledWith({
      publicKey: { challenge: 'Y2hhbGxlbmdl' },
    });
    expect(fake.mocks.webAuthnFinishLogin).toHaveBeenCalledWith(
      'sess-1',
      assertionJSON,
      'user-1',
    );
    // Tokens landed in the shared store.
    expect(window.localStorage.getItem(tokenKey())).toBe('acc-1');
  });

  it('collapses every identity-resolution failure into ONE generic message', async () => {
    // Failure A: the server rejects at begin ("unknown tenant" style).
    const providerA = makeProvider();
    fake.mocks.webAuthnBeginLogin.mockRejectedValue(
      new FakeApiError(401, 'tenant not found'),
    );
    render(LoginPanel, {
      props: { provider: providerA, client: fake.client, onSuccess: vi.fn() },
    });
    await submitPasskey('probe@example.com');
    const alertA = await screen.findByRole('alert');
    const messageA = alertA.textContent ?? '';
    cleanup();

    // Failure B: the server rejects at finish ("unknown user" style).
    const fakeB = makeFakeClient();
    configureAuthStore({ client: fakeB.client });
    fakeB.mocks.webAuthnBeginLogin.mockResolvedValue({
      options: { publicKey: { challenge: 'Y2hhbGxlbmdl' } },
      sessionId: 'sess-2',
    });
    fakeB.mocks.webAuthnFinishLogin.mockRejectedValue(
      new FakeApiError(401, 'user not found'),
    );
    render(LoginPanel, {
      props: { provider: makeProvider(), client: fakeB.client, onSuccess: vi.fn() },
    });
    await submitPasskey('probe@example.com');
    const alertB = await screen.findByRole('alert');
    const messageB = alertB.textContent ?? '';

    // The two very different server-side causes produce the IDENTICAL copy —
    // the panel cannot be used as an enumeration oracle.
    expect(messageA).toContain('Sign-in failed. Check your details and try again.');
    expect(messageB).toContain('Sign-in failed. Check your details and try again.');
    // And neither leaks the server's distinct reason.
    expect(messageA).not.toContain('tenant');
    expect(messageB).not.toContain('user');
  });

  it('shows a distinct message when the user declines the ceremony', async () => {
    const provider = makeProvider({
      getAssertion: vi.fn(async () => {
        throw new DOMException('cancelled', 'NotAllowedError');
      }),
    });
    fake.mocks.webAuthnBeginLogin.mockResolvedValue({
      options: { publicKey: { challenge: 'Y2hhbGxlbmdl' } },
      sessionId: 'sess-1',
    });

    render(LoginPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    await submitPasskey('jane@example.com');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('declined or canceled');
  });

  it('runs the certificate path through provider.loginCertificate', async () => {
    const provider = makeProvider();
    const me = { subject: 'piv-user', permissions: {}, capabilities: {} };
    fake.mocks.me.mockResolvedValue(me);
    const onSuccess = vi.fn();

    render(LoginPanel, {
      props: { provider, client: fake.client, onSuccess },
    });
    const certBtn = await screen.findByRole('button', {
      name: 'Sign in with certificate',
    });
    await fireEvent.click(certBtn);

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(provider.loginCertificate).toHaveBeenCalledTimes(1);
    expect(onSuccess).toHaveBeenCalledWith(
      { access_token: 'cert-acc', refresh_token: 'cert-ref' },
      me,
    );
    expect(window.localStorage.getItem(tokenKey())).toBe('cert-acc');
  });

  it('surfaces a certificate rejection without ending in a silent reset', async () => {
    const provider = makeProvider({
      loginCertificate: vi.fn(async () => {
        throw new FakeApiError(401, 'piv_login_disabled');
      }),
    });

    render(LoginPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    const certBtn = await screen.findByRole('button', {
      name: 'Sign in with certificate',
    });
    await fireEvent.click(certBtn);

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain("certificate isn't recognized");
  });

  it('remembers the organization only after a SUCCESSFUL login', async () => {
    const provider = makeProvider();
    fake.mocks.webAuthnBeginLogin.mockRejectedValue(new FakeApiError(401, 'nope'));

    render(LoginPanel, {
      props: {
        provider,
        client: fake.client,
        defaultTenant: 'system',
        onSuccess: vi.fn(),
      },
    });

    // The organization field is shown and prefilled with the default.
    const tenantInput = (await screen.findByLabelText(
      'Organization',
    )) as HTMLInputElement;
    expect(tenantInput.value).toBe('system');
    await fireEvent.input(tenantInput, { target: { value: 'acme-typo' } });

    await submitPasskey('jane@example.com');
    await screen.findByRole('alert');

    // The failed attempt did NOT make the typo sticky.
    expect(window.localStorage.getItem('xkms_login_tenant')).toBeNull();

    // Now let the ceremony succeed: the typed organization is both sent to
    // the server and remembered for the next visit.
    fake.mocks.webAuthnBeginLogin.mockResolvedValue({
      options: { publicKey: { challenge: 'Y2hhbGxlbmdl' } },
      sessionId: 'sess-1',
    });
    fake.mocks.webAuthnFinishLogin.mockResolvedValue({
      token: 'acc-1',
      user_id: 'user-1',
    });
    const authBtn = screen.getByRole('button', { name: 'Authenticate with passkey' });
    await fireEvent.click(authBtn);

    await waitFor(() =>
      expect(window.localStorage.getItem('xkms_login_tenant')).toBe('acme-typo'),
    );
    expect(fake.mocks.webAuthnBeginLogin).toHaveBeenLastCalledWith({
      email: 'jane@example.com',
      tenant_id: 'acme-typo',
    });
  });

  // -------------------------------------------------------------------------
  // Provider / capability discovery fallbacks
  // -------------------------------------------------------------------------

  it('falls back to passkey-only when the provider fails to report its methods', async () => {
    const provider = makeProvider({
      methods: vi.fn(async () => {
        throw new Error('provider probe failed');
      }),
    });
    render(LoginPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });

    await screen.findByRole('button', { name: 'Sign in with passkey' });
    expect(
      screen.queryByRole('button', { name: 'Sign in with certificate' }),
    ).toBeNull();
  });

  it('leaves the provider method list untouched when the capabilities probe fails', async () => {
    const capsGet = vi.fn(async () => {
      throw new Error('capabilities unreachable');
    });
    const clientWithFailingCaps = { ...fake.client, capabilities: { get: capsGet } };
    const provider = makeProvider();

    render(LoginPanel, {
      props: { provider, client: clientWithFailingCaps, onSuccess: vi.fn() },
    });

    // A failed capabilities probe must not lock the operator out: both
    // provider-offered methods stay visible.
    await screen.findByRole('button', { name: 'Sign in with passkey' });
    await screen.findByRole('button', { name: 'Sign in with certificate' });
    expect(capsGet).toHaveBeenCalledTimes(1);
  });

  it('hides a method the deployment capabilities report as disabled', async () => {
    const clientWithCaps = {
      ...fake.client,
      capabilities: { get: vi.fn(async () => ({ piv_login_enabled: false })) },
    };
    render(LoginPanel, {
      props: { provider: makeProvider(), client: clientWithCaps, onSuccess: vi.fn() },
    });

    await screen.findByRole('button', { name: 'Sign in with passkey' });
    await waitFor(() =>
      expect(
        screen.queryByRole('button', { name: 'Sign in with certificate' }),
      ).toBeNull(),
    );
  });

  // -------------------------------------------------------------------------
  // /me failing after a successful login
  // -------------------------------------------------------------------------

  it('reports onSuccess with a null identity when /me fails after a successful login', async () => {
    const provider = makeProvider();
    fake.mocks.webAuthnBeginLogin.mockResolvedValue({
      options: { publicKey: { challenge: 'Y2hhbGxlbmdl' } },
      sessionId: 'sess-1',
    });
    fake.mocks.webAuthnFinishLogin.mockResolvedValue({
      token: 'acc-1',
      refresh_token: 'ref-1',
      user_id: 'user-1',
    });
    fake.mocks.me.mockRejectedValue(new FakeApiError(500, 'me unavailable'));
    const onSuccess = vi.fn();

    render(LoginPanel, {
      props: { provider, client: fake.client, onSuccess },
    });
    await submitPasskey('jane@example.com');

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(onSuccess).toHaveBeenCalledWith(
      { access_token: 'acc-1', refresh_token: 'ref-1' },
      null,
    );
    // The session is still established even though /me failed.
    expect(window.localStorage.getItem(tokenKey())).toBe('acc-1');
  });

  // -------------------------------------------------------------------------
  // Passkey validation branches
  // -------------------------------------------------------------------------

  it('rejects an empty identifier submitted via Enter without calling the server', async () => {
    render(LoginPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    const passkeyBtn = await screen.findByRole('button', { name: 'Sign in with passkey' });
    await fireEvent.click(passkeyBtn);
    const input = await screen.findByLabelText('Email');

    // The Authenticate button is disabled while empty, but the Enter-key
    // handler on the input calls submitPasskey() directly.
    await fireEvent.keyDown(input, { key: 'Enter' });

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Please enter your email.');
    expect(fake.mocks.webAuthnBeginLogin).not.toHaveBeenCalled();
  });

  it('rejects a blanked-out organization field when one is required', async () => {
    render(LoginPanel, {
      props: {
        provider: makeProvider(),
        client: fake.client,
        defaultTenant: 'system',
        onSuccess: vi.fn(),
      },
    });
    const tenantInput = (await screen.findByLabelText(
      'Organization',
    )) as HTMLInputElement;
    expect(tenantInput.value).toBe('system');
    await fireEvent.input(tenantInput, { target: { value: '   ' } });

    await submitPasskey('jane@example.com');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Please enter your organization.');
    expect(fake.mocks.webAuthnBeginLogin).not.toHaveBeenCalled();
  });

  it('reports the network-failure message (not the generic one) when begin cannot reach the server', async () => {
    fake.mocks.webAuthnBeginLogin.mockRejectedValue(new TypeError('Failed to fetch'));

    render(LoginPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    await submitPasskey('jane@example.com');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain("Can't reach the server right now.");
    expect(alert.textContent).not.toContain('Sign-in failed');
  });

  it('reports the network-failure message (not the generic one) when finish cannot reach the server', async () => {
    fake.mocks.webAuthnBeginLogin.mockResolvedValue({
      options: { publicKey: { challenge: 'Y2hhbGxlbmdl' } },
      sessionId: 'sess-1',
    });
    fake.mocks.webAuthnFinishLogin.mockRejectedValue(new TypeError('Failed to fetch'));

    render(LoginPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    await submitPasskey('jane@example.com');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain("Can't reach the server right now.");
    expect(alert.textContent).not.toContain('Sign-in failed');
  });

  it('surfaces a server contract violation when finish returns no token', async () => {
    fake.mocks.webAuthnBeginLogin.mockResolvedValue({
      options: { publicKey: { challenge: 'Y2hhbGxlbmdl' } },
      sessionId: 'sess-1',
    });
    fake.mocks.webAuthnFinishLogin.mockResolvedValue({ token: '', user_id: 'user-1' });

    render(LoginPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    await submitPasskey('jane@example.com');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Sign-in did not return a session token');
  });

  it('the Enter key on the passkey identifier field submits (keydown handler)', async () => {
    fake.mocks.webAuthnBeginLogin.mockResolvedValue({
      options: { publicKey: { challenge: 'Y2hhbGxlbmdl' } },
      sessionId: 'sess-1',
    });
    fake.mocks.webAuthnFinishLogin.mockResolvedValue({
      token: 'acc-1',
      user_id: 'user-1',
    });

    render(LoginPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    const passkeyBtn = await screen.findByRole('button', { name: 'Sign in with passkey' });
    await fireEvent.click(passkeyBtn);
    const input = await screen.findByLabelText('Email');
    await fireEvent.input(input, { target: { value: 'jane@example.com' } });
    await fireEvent.keyDown(input, { key: 'Enter' });

    await waitFor(() =>
      expect(fake.mocks.webAuthnBeginLogin).toHaveBeenCalledWith({
        email: 'jane@example.com',
      }),
    );
  });

  // -------------------------------------------------------------------------
  // Certificate error branches
  // -------------------------------------------------------------------------

  it('reports a distinct message for a 400 (no matching certificate identity)', async () => {
    const provider = makeProvider({
      loginCertificate: vi.fn(async () => {
        throw new FakeApiError(400, 'no client certificate presented');
      }),
    });
    render(LoginPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    const certBtn = await screen.findByRole('button', { name: 'Sign in with certificate' });
    await fireEvent.click(certBtn);

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('No matching certificate identity');
  });

  it('reports the network-failure message when certificate login cannot reach the server', async () => {
    const provider = makeProvider({
      loginCertificate: vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }),
    });
    render(LoginPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    const certBtn = await screen.findByRole('button', { name: 'Sign in with certificate' });
    await fireEvent.click(certBtn);

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain("Can't reach the server right now.");
  });

  it('surfaces the underlying message for an unrecognized Error, and a fallback for a non-Error throw', async () => {
    const provider = makeProvider({
      loginCertificate: vi.fn(async () => {
        throw new Error('smartcard driver crashed');
      }),
    });
    render(LoginPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    const certBtn = await screen.findByRole('button', { name: 'Sign in with certificate' });
    await fireEvent.click(certBtn);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('smartcard driver crashed');
    cleanup();

    const fakeB = makeFakeClient();
    configureAuthStore({ client: fakeB.client });
    const providerB = makeProvider({
      loginCertificate: vi.fn(async () => {
        throw 'not an Error instance';
      }),
    });
    render(LoginPanel, {
      props: { provider: providerB, client: fakeB.client, onSuccess: vi.fn() },
    });
    const certBtnB = await screen.findByRole('button', { name: 'Sign in with certificate' });
    await fireEvent.click(certBtnB);
    const alertB = await screen.findByRole('alert');
    expect(alertB.textContent).toContain('Certificate authentication failed.');
  });

  // -------------------------------------------------------------------------
  // backToChooser (Try again / Back)
  // -------------------------------------------------------------------------

  it('the "Try again" link on the error alert resets mode, error, and identifier', async () => {
    render(LoginPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    const passkeyBtn = await screen.findByRole('button', { name: 'Sign in with passkey' });
    await fireEvent.click(passkeyBtn);
    const input = await screen.findByLabelText('Email');
    await fireEvent.input(input, { target: { value: 'partial@example.com' } });
    await fireEvent.keyDown(input, { key: 'Enter' });
    await screen.findByRole('alert');

    const tryAgain = screen.getByRole('button', { name: 'Try again' });
    await fireEvent.click(tryAgain);

    expect(screen.queryByRole('alert')).toBeNull();
    // Back on the chooser: the passkey option is visible again and the
    // identifier field (with its stale input) is gone.
    await screen.findByRole('button', { name: 'Sign in with passkey' });
    expect(screen.queryByLabelText('Email')).toBeNull();
  });

  // -------------------------------------------------------------------------
  // Re-entrancy guards / effect cleanup
  // -------------------------------------------------------------------------

  it('ignores a second passkey submission started while one is already in flight', async () => {
    let releaseBegin: (v: unknown) => void = () => {};
    fake.mocks.webAuthnBeginLogin.mockImplementation(
      () =>
        new Promise((resolve) => {
          releaseBegin = resolve;
        }),
    );

    render(LoginPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    const passkeyBtn = await screen.findByRole('button', { name: 'Sign in with passkey' });
    await fireEvent.click(passkeyBtn);
    const input = await screen.findByLabelText('Email');
    await fireEvent.input(input, { target: { value: 'jane@example.com' } });
    const authBtn = screen.getByRole('button', { name: 'Authenticate with passkey' });
    await fireEvent.click(authBtn);
    await vi.waitFor(() => expect(fake.mocks.webAuthnBeginLogin).toHaveBeenCalledTimes(1));

    // A second submission (Enter on the still-enabled input) while the first
    // is in flight must be a no-op — the busy guard short-circuits it.
    await fireEvent.keyDown(input, { key: 'Enter' });
    expect(fake.mocks.webAuthnBeginLogin).toHaveBeenCalledTimes(1);

    // Let the first attempt settle cleanly so it doesn't leak a rejection
    // into a later test.
    fake.mocks.webAuthnFinishLogin.mockResolvedValue({ token: 'acc-1', user_id: 'user-1' });
    releaseBegin({
      options: { publicKey: { challenge: 'Y2hhbGxlbmdl' } },
      sessionId: 'sess-1',
    });
    await vi.waitFor(() => expect(fake.mocks.webAuthnFinishLogin).toHaveBeenCalled());
  });

  it('ignores a second certificate submission started while one is already in flight', async () => {
    let releaseLogin: (v: unknown) => void = () => {};
    const provider = makeProvider({
      loginCertificate: vi.fn(
        () =>
          new Promise((resolve) => {
            releaseLogin = resolve;
          }),
      ),
    });

    render(LoginPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    const certBtn = await screen.findByRole('button', { name: 'Sign in with certificate' });

    // Two rapid clicks before either resolves: the second call re-enters
    // submitCertificate() while busy is already true.
    fireEvent.click(certBtn);
    fireEvent.click(certBtn);
    await vi.waitFor(() => expect(provider.loginCertificate).toHaveBeenCalled());

    expect(provider.loginCertificate).toHaveBeenCalledTimes(1);
    releaseLogin({ access_token: 'cert-acc', refresh_token: 'cert-ref' });
  });

  it('stops updating offered methods after the component unmounts mid capability-probe', async () => {
    let resolveMethods: (v: string[]) => void = () => {};
    const methodsPromise = new Promise<string[]>((resolve) => {
      resolveMethods = resolve;
    });
    const provider = makeProvider({
      methods: vi.fn(() => methodsPromise as unknown as Promise<('passkey' | 'certificate')[]>),
    });

    const { unmount } = render(LoginPanel, {
      props: { provider, client: fake.client, onSuccess: vi.fn() },
    });
    unmount();

    // Resolving after unmount must not throw or write to a torn-down
    // component — the effect's cleanup flips `cancelled` so the assignment
    // to `methods` is skipped.
    expect(() => resolveMethods(['passkey', 'certificate'])).not.toThrow();
    await methodsPromise;
    expect(provider.methods).toHaveBeenCalledTimes(1);
  });

  it('the "Back" button returns to the chooser without an error', async () => {
    render(LoginPanel, {
      props: { provider: makeProvider(), client: fake.client, onSuccess: vi.fn() },
    });
    const passkeyBtn = await screen.findByRole('button', { name: 'Sign in with passkey' });
    await fireEvent.click(passkeyBtn);
    await screen.findByLabelText('Email');

    const backBtn = screen.getByRole('button', { name: 'Back to login options' });
    await fireEvent.click(backBtn);

    await screen.findByRole('button', { name: 'Sign in with passkey' });
    expect(screen.queryByLabelText('Email')).toBeNull();
  });
});
