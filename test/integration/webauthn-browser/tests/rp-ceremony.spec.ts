// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// End-to-end WebAuthn ceremony tests that drive Chrome's built-in CDP virtual
// authenticator (WebAuthn.addVirtualAuthenticator) against the REAL running
// xkmsd Relying Party at /api/v1/webauthn/*.
//
// These cover the paths the Go-level tests cannot reach because they require a
// real browser credential produced by an authenticator:
//   - successful register + authenticate round-trip (same-origin and cross-origin)
//   - forged-signature rejection (401, not 500)
//   - excludeCredentials prevents re-registering the same authenticator
//   - usernameless / discoverable resident-key login
//   - login for an unregistered user is a clean 404
//   - a finish bound to an unknown session is rejected (400)
//
// The page is served SAME-ORIGIN with the API for most tests (Playwright
// fulfils the navigation) so clientData.origin matches rp_origins and the
// X-Session-Id header is readable without a CORS preflight. One test uses a
// different page origin to exercise the cross-origin CORS policy.

import { test, expect, type CDPSession, type Page } from '@playwright/test';

// The RP API origin.
const API_BASE = 'https://localhost:18443';
// Page origin for the same-origin ceremony (served from the API origin).
const SAME_ORIGIN_URL = 'https://localhost:18443/__rp_test';
// Page origin for the cross-origin ceremony (a DIFFERENT origin than the API,
// also listed in the server's rp_origins). Calling the RP from here forces the
// browser to run a real CORS preflight for the X-Session-Id request header and
// to honour Access-Control-Expose-Headers when reading it back.
const CROSS_ORIGIN_URL = 'https://localhost:18444/__rp_test';

// Minimal page. All ceremony logic runs via page.evaluate so the
// non-serializable PublicKeyCredential never crosses the evaluate boundary.
const RP_TEST_HTML =
  '<!doctype html><html><head><meta charset="utf-8"><title>xkms rp test</title></head><body></body></html>';

interface CeremonyResult {
  status: number;
  ok: boolean;
  body: any;
  credentialId?: string;
  // Populated when navigator.credentials.create/get throws in the browser
  // (e.g. InvalidStateError from excludeCredentials) instead of reaching finish.
  clientError?: string;
}

interface RegOpts {
  apiBase: string;
  email: string;
  displayName: string;
  // Session token of the account. When set, the ceremony adds a passkey to
  // that account through the session-authenticated /credentials/begin route
  // instead of the public first-passkey route (go-xkms#1294).
  token?: string;
}

interface AuthOpts {
  apiBase: string;
  email?: string;
  discoverable?: boolean;
  tamperSignature?: boolean;
  // When set, replaces the X-Session-Id sent to /finish (to test session binding).
  sessionOverride?: string;
}

// addVirtualAuthenticator wires a CTAP2 software authenticator into the page
// over the Chrome DevTools Protocol and returns its id for later removal.
async function addVirtualAuthenticator(cdp: CDPSession): Promise<string> {
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const result = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'usb',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return (result as { authenticatorId: string }).authenticatorId;
}

// prepare fulfils the RP test page at pageUrl (which sets the page's origin)
// and wires a virtual authenticator. Nothing needs to listen on pageUrl's port
// — Playwright fulfils the navigation directly.
async function prepare(page: Page, pageUrl: string): Promise<{ cdp: CDPSession; authId: string }> {
  await page.route(pageUrl, async (route) => {
    await route.fulfill({ status: 200, contentType: 'text/html', body: RP_TEST_HTML });
  });
  const cdp = await page.context().newCDPSession(page);
  const authId = await addVirtualAuthenticator(cdp);
  await page.goto(pageUrl);
  return { cdp, authId };
}

// runRegistration performs the full registration ceremony in the browser and
// returns the server's /registration/finish result. If the authenticator
// refuses to create the credential (e.g. excludeCredentials match), the thrown
// DOMException is returned as clientError and finish is never called.
async function runRegistration(page: Page, opts: RegOpts): Promise<CeremonyResult> {
  return page.evaluate(async ({ apiBase, email, displayName, token }) => {
    const b64urlToBuf = (s: string): ArrayBuffer => {
      s = s.replace(/-/g, '+').replace(/_/g, '/');
      const pad = s.length % 4;
      if (pad) s += '='.repeat(4 - pad);
      const bin = atob(s);
      const buf = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
      return buf.buffer;
    };
    const bufToB64url = (buf: ArrayBuffer): string => {
      const bytes = new Uint8Array(buf);
      let bin = '';
      for (const b of bytes) bin += String.fromCharCode(b);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };

    const beginResp = token
      ? await fetch(`${apiBase}/api/v1/webauthn/credentials/begin`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        })
      : await fetch(`${apiBase}/api/v1/webauthn/registration/begin`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, display_name: displayName }),
        });
    if (!beginResp.ok) {
      return { status: beginResp.status, ok: false, body: await beginResp.text() };
    }
    const sessionId = beginResp.headers.get('X-Session-Id') ?? '';
    const { publicKey } = await beginResp.json();

    publicKey.challenge = b64urlToBuf(publicKey.challenge);
    publicKey.user.id = b64urlToBuf(publicKey.user.id);
    if (Array.isArray(publicKey.excludeCredentials)) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map((c: any) => ({
        ...c,
        id: b64urlToBuf(c.id),
      }));
    }

    let cred: PublicKeyCredential;
    try {
      cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
    } catch (e: any) {
      return { status: 0, ok: false, body: null, clientError: `${e.name}: ${e.message}` };
    }
    const att = cred.response as AuthenticatorAttestationResponse;

    const attResp = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: bufToB64url(att.attestationObject),
        clientDataJSON: bufToB64url(att.clientDataJSON),
      },
      clientExtensionResults: cred.getClientExtensionResults(),
    };

    const finishResp = await fetch(`${apiBase}/api/v1/webauthn/registration/finish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify(attResp),
    });
    const text = await finishResp.text();
    let body: any;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    return { status: finishResp.status, ok: finishResp.ok, body, credentialId: cred.id };
  }, opts);
}

// runAuthentication performs the full authentication ceremony. discoverable
// omits the email (usernameless resident-key flow); tamperSignature corrupts
// the assertion signature; sessionOverride replaces the finish session id.
async function runAuthentication(page: Page, opts: AuthOpts): Promise<CeremonyResult> {
  return page.evaluate(
    async ({ apiBase, email, discoverable, tamperSignature, sessionOverride }) => {
      const b64urlToBuf = (s: string): ArrayBuffer => {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        const pad = s.length % 4;
        if (pad) s += '='.repeat(4 - pad);
        const bin = atob(s);
        const buf = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
        return buf.buffer;
      };
      const bufToB64url = (buf: ArrayBuffer): string => {
        const bytes = new Uint8Array(buf);
        let bin = '';
        for (const b of bytes) bin += String.fromCharCode(b);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      };

      const beginBody = discoverable ? {} : { email };
      const beginResp = await fetch(`${apiBase}/api/v1/webauthn/login/begin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(beginBody),
      });
      if (!beginResp.ok) {
        return { status: beginResp.status, ok: false, body: await beginResp.text() };
      }
      const sessionId = beginResp.headers.get('X-Session-Id') ?? '';
      const { publicKey } = await beginResp.json();

      publicKey.challenge = b64urlToBuf(publicKey.challenge);
      if (Array.isArray(publicKey.allowCredentials)) {
        publicKey.allowCredentials = publicKey.allowCredentials.map((c: any) => ({
          ...c,
          id: b64urlToBuf(c.id),
        }));
      }

      let assertion: PublicKeyCredential;
      try {
        assertion = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
      } catch (e: any) {
        return { status: 0, ok: false, body: null, clientError: `${e.name}: ${e.message}` };
      }
      const asr = assertion.response as AuthenticatorAssertionResponse;

      let signature = bufToB64url(asr.signature);
      if (tamperSignature) {
        const sigBytes = new Uint8Array(asr.signature.slice(0));
        sigBytes[0] ^= 0xff;
        signature = bufToB64url(sigBytes.buffer);
      }

      const asResp = {
        id: assertion.id,
        rawId: bufToB64url(assertion.rawId),
        type: assertion.type,
        response: {
          authenticatorData: bufToB64url(asr.authenticatorData),
          clientDataJSON: bufToB64url(asr.clientDataJSON),
          signature,
          userHandle: asr.userHandle ? bufToB64url(asr.userHandle) : null,
        },
        clientExtensionResults: assertion.getClientExtensionResults(),
      };

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-Session-Id': sessionOverride !== undefined ? sessionOverride : sessionId,
      };

      const finishResp = await fetch(`${apiBase}/api/v1/webauthn/login/finish`, {
        method: 'POST',
        headers,
        body: JSON.stringify(asResp),
      });
      const text = await finishResp.text();
      let body: any;
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
      return { status: finishResp.status, ok: finishResp.ok, body };
    },
    opts,
  );
}

test.describe('xkms WebAuthn RP — Chrome virtual authenticator (same-origin)', () => {
  test('registers and authenticates end-to-end against the real RP', async ({ page }) => {
    const email = `roundtrip-${Date.now()}@example.com`;
    await prepare(page, SAME_ORIGIN_URL);

    const reg = await runRegistration(page, { apiBase: '', email, displayName: 'Round Trip' });
    expect(reg.ok, `registration finish failed: ${JSON.stringify(reg.body ?? reg.clientError)}`).toBeTruthy();
    expect(reg.status).toBe(200);
    expect(reg.body).toHaveProperty('token');
    expect(typeof reg.body.token).toBe('string');
    expect(reg.body.token.length).toBeGreaterThan(0);
    expect(reg.credentialId && reg.credentialId.length).toBeGreaterThan(0);

    const auth = await runAuthentication(page, { apiBase: '', email });
    expect(auth.ok, `authentication finish failed: ${JSON.stringify(auth.body)}`).toBeTruthy();
    expect(auth.status).toBe(200);
    expect(auth.body).toHaveProperty('token');
    expect(typeof auth.body.token).toBe('string');
    expect(auth.body.token.length).toBeGreaterThan(0);
  });

  test('rejects an authentication with a tampered signature', async ({ page }) => {
    const email = `tamper-${Date.now()}@example.com`;
    await prepare(page, SAME_ORIGIN_URL);

    const reg = await runRegistration(page, { apiBase: '', email, displayName: 'Tamper Test' });
    expect(reg.ok, `registration finish failed: ${JSON.stringify(reg.body ?? reg.clientError)}`).toBeTruthy();

    const auth = await runAuthentication(page, { apiBase: '', email, tamperSignature: true });
    // A forged assertion is rejected, no auth token is ever issued, and the RP
    // classifies it as 401 Unauthorized (a client error) — not 500. The service
    // translates go-webauthn's *protocol.Error into ErrVerificationFailed.
    expect(auth.ok, 'RP accepted a tampered signature — verification is broken').toBeFalsy();
    expect(auth.status).toBe(401);
    expect(auth.body == null || typeof auth.body.token === 'undefined').toBeTruthy();
  });

  test('excludeCredentials prevents re-registering the same authenticator', async ({ page }) => {
    const email = `exclude-${Date.now()}@example.com`;
    await prepare(page, SAME_ORIGIN_URL);

    const first = await runRegistration(page, { apiBase: '', email, displayName: 'Exclude Test' });
    expect(first.ok, `first registration failed: ${JSON.stringify(first.body ?? first.clientError)}`).toBeTruthy();

    // The public route refuses an account that already has a passkey
    // (go-xkms#1294).
    const refused = await runRegistration(page, { apiBase: '', email, displayName: 'Exclude Test' });
    expect(refused.status).toBe(403);

    // Adding a passkey through the account's own session returns
    // excludeCredentials that include the credential already held by this
    // authenticator, so the CTAP2 authenticator refuses with InvalidStateError
    // and finish is never reached.
    const second = await runRegistration(page, {
      apiBase: '',
      email,
      displayName: 'Exclude Test',
      token: first.body.token,
    });
    expect(second.clientError, 'expected the authenticator to refuse re-registration').toBeTruthy();
    expect(second.clientError).toContain('InvalidStateError');
  });

  test('authenticates usernamelessly via a discoverable resident credential', async ({ page }) => {
    const email = `discoverable-${Date.now()}@example.com`;
    await prepare(page, SAME_ORIGIN_URL);

    const reg = await runRegistration(page, { apiBase: '', email, displayName: 'Discoverable' });
    expect(reg.ok, `registration failed: ${JSON.stringify(reg.body ?? reg.clientError)}`).toBeTruthy();

    // No email supplied: the RP issues a discoverable-login challenge and the
    // resident credential resolves the user via userHandle.
    const auth = await runAuthentication(page, { apiBase: '', discoverable: true });
    expect(auth.ok, `discoverable login failed: ${JSON.stringify(auth.body)}`).toBeTruthy();
    expect(auth.status).toBe(200);
    expect(auth.body).toHaveProperty('token');
  });

  test('login for an unregistered user is a clean 404', async ({ page }) => {
    await prepare(page, SAME_ORIGIN_URL);

    const auth = await runAuthentication(page, {
      apiBase: '',
      email: `nobody-${Date.now()}@example.com`,
    });
    expect(auth.ok).toBeFalsy();
    expect(auth.status).toBe(404);
  });

  test('rejects a finish bound to an unknown session', async ({ page }) => {
    const email = `badsession-${Date.now()}@example.com`;
    await prepare(page, SAME_ORIGIN_URL);

    const reg = await runRegistration(page, { apiBase: '', email, displayName: 'Bad Session' });
    expect(reg.ok, `registration failed: ${JSON.stringify(reg.body ?? reg.clientError)}`).toBeTruthy();

    // A well-formed assertion submitted with an unknown session id must be
    // rejected (the challenge/session correlation cannot be found): 400.
    const auth = await runAuthentication(page, {
      apiBase: '',
      email,
      sessionOverride: 'deadbeefdeadbeefdeadbeefdeadbeef',
    });
    expect(auth.ok, 'RP accepted a finish for an unknown session').toBeFalsy();
    expect(auth.status).toBe(400);
  });
});

test.describe('xkms WebAuthn RP — Chrome virtual authenticator (cross-origin)', () => {
  // The page is served from https://localhost:18444 while the RP API lives at
  // https://localhost:18443. Every /finish POST carries X-Session-Id, so the
  // browser runs a real CORS preflight (proves Access-Control-Allow-Headers),
  // and the X-Session-Id returned by /begin is only readable because the server
  // sets Access-Control-Expose-Headers. A regression in the CORS middleware
  // would fail this ceremony at the browser layer.
  test('completes a cross-origin ceremony through the hardened CORS policy', async ({ page }) => {
    const email = `xorigin-${Date.now()}@example.com`;
    await prepare(page, CROSS_ORIGIN_URL);

    const reg = await runRegistration(page, { apiBase: API_BASE, email, displayName: 'Cross Origin' });
    expect(reg.ok, `cross-origin registration failed: ${JSON.stringify(reg.body ?? reg.clientError)}`).toBeTruthy();
    expect(reg.status).toBe(200);
    expect(reg.body).toHaveProperty('token');

    const auth = await runAuthentication(page, { apiBase: API_BASE, email });
    expect(auth.ok, `cross-origin authentication failed: ${JSON.stringify(auth.body)}`).toBeTruthy();
    expect(auth.status).toBe(200);
    expect(auth.body).toHaveProperty('token');
    expect(typeof auth.body.token).toBe('string');
    expect(auth.body.token.length).toBeGreaterThan(0);
  });
});
