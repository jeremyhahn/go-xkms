// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

/**
 * Operator provisioning for the live web-console tier under ruling 602: an
 * enforcing node refuses anonymous sign-up (403 registration_refused, pending
 * #2202), so each operator is created by the administrator, redeems its
 * one-time invitation with a passkey, and then signs in through the real
 * LoginView with that passkey.
 *
 * The administrator is the credential `xkmsd init --admin-factor mtls` wrote
 * under .runtime/storage (run-server.sh); it is presented as a Playwright
 * client certificate, which config.yaml's tls.client_auth "verify" accepts.
 * The invitation ceremony runs in the page, same-origin with the daemon, so
 * the virtual authenticator installed on `page` creates the credential.
 */

import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test';
import { loginOperator, type Operator } from './operator.ts';

/** API origin of the daemon run-server.sh boots (playwright.config.ts baseURL). */
const API_ORIGIN = 'https://localhost:18463';

/**
 * adminCredential locates the init-ceremony admin certificate and key.
 * run-server.sh points `xkmsd init --data-dir` at <suite>/.runtime/storage,
 * and the suite's testDir is <suite>/tests.
 */
export function adminCredential(): { certPath: string; keyPath: string } {
  const storage = `${test.info().project.testDir}/../.runtime/storage`;
  return { certPath: `${storage}/admin-cert.pem`, keyPath: `${storage}/admin-key.pem` };
}

/** adminRequest opens an API context that authenticates as the administrator over mTLS. */
async function adminRequest(): Promise<APIRequestContext> {
  const { certPath, keyPath } = adminCredential();
  return request.newContext({
    baseURL: API_ORIGIN,
    ignoreHTTPSErrors: true,
    clientCertificates: [{ origin: API_ORIGIN, certPath, keyPath }],
  });
}

/** expectNoUser asserts the administrator's user list holds no account for email. */
export async function expectNoUser(email: string): Promise<void> {
  const admin = await adminRequest();
  try {
    const resp = await admin.get('/api/v1/users');
    expect(resp.status(), await resp.text()).toBe(200);
    const { users } = await resp.json();
    const emails = ((users ?? []) as Array<{ email?: string }>).map((u) => (u.email ?? '').toLowerCase());
    expect(emails, `a refused registration created an account for ${email}`).not.toContain(email.toLowerCase());
  } finally {
    await admin.dispose();
  }
}

/**
 * expectAnonymousSignUpRefused asserts that the public registration route the
 * SPA's /register screen calls answers 403 registration_refused and creates
 * no account.
 */
export async function expectAnonymousSignUpRefused(page: Page, op: Operator): Promise<void> {
  const refused = await page.evaluate(async ({ email, displayName }) => {
    const resp = await fetch('/api/v1/webauthn/registration/begin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, display_name: displayName }),
    });
    const text = await resp.text();
    let body: any;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    return { status: resp.status, body };
  }, op);
  expect(refused.status, `anonymous registration was not refused: ${JSON.stringify(refused.body)}`).toBe(403);
  expect(refused.body?.error).toBe('registration_refused');
  await expectNoUser(op.email);
}

/**
 * provisionInvite creates the operator as the administrator and returns the
 * tenant and token of its invitation (<base>/#/invite/<tenant>/<token>).
 */
export async function provisionInvite(op: Operator): Promise<{ tenant: string; token: string }> {
  const admin = await adminRequest();
  try {
    const resp = await admin.post('/api/v1/users', {
      data: { username: op.email.split('@')[0], email: op.email, display_name: op.displayName },
    });
    expect(resp.status(), await resp.text()).toBe(201);
    const { invite } = await resp.json();
    expect(invite?.token, 'POST /api/v1/users returned no invitation').toBeTruthy();
    const marker = '/#/invite/';
    const url: string = invite.url ?? '';
    expect(url, `invitation URL ${url} has no ${marker} segment`).toContain(marker);
    const tenant = decodeURIComponent(url.slice(url.indexOf(marker) + marker.length).split('/')[0]);
    expect(tenant, `invitation URL ${url} names no tenant`).toBeTruthy();
    return { tenant, token: invite.token };
  } finally {
    await admin.dispose();
  }
}

/**
 * redeemInvite runs the invitation's passkey ceremony in the page against
 * /api/v1/invites/{tenant}/{token}/fido2/begin and finish, and asserts the
 * account is activated.
 */
export async function redeemInvite(page: Page, invite: { tenant: string; token: string }): Promise<void> {
  const redeemed = await page.evaluate(async ({ tenant, token }) => {
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
    const base = `/api/v1/invites/${encodeURIComponent(tenant)}/${encodeURIComponent(token)}/fido2`;

    const beginResp = await fetch(`${base}/begin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    if (!beginResp.ok) {
      return { status: beginResp.status, ok: false, body: await beginResp.text() as any };
    }
    const begin = await beginResp.json();
    const { publicKey } = JSON.parse(begin.options_json);
    publicKey.challenge = b64urlToBuf(publicKey.challenge);
    publicKey.user.id = b64urlToBuf(publicKey.user.id);
    if (Array.isArray(publicKey.excludeCredentials)) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map((c: any) => ({ ...c, id: b64urlToBuf(c.id) }));
    }

    let cred: PublicKeyCredential;
    try {
      cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
    } catch (e: any) {
      return { status: 0, ok: false, body: `${e.name}: ${e.message}` as any };
    }
    const att = cred.response as AuthenticatorAttestationResponse;
    const attestation = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: bufToB64url(att.attestationObject),
        clientDataJSON: bufToB64url(att.clientDataJSON),
      },
      clientExtensionResults: cred.getClientExtensionResults(),
    };

    const finishResp = await fetch(`${base}/finish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: begin.session_id, attestation_json: JSON.stringify(attestation) }),
    });
    const text = await finishResp.text();
    let body: any;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    return { status: finishResp.status, ok: finishResp.ok, body };
  }, invite);
  expect(redeemed.ok, `invitation redemption failed: ${JSON.stringify(redeemed.body)}`).toBeTruthy();
  expect(redeemed.status).toBe(200);
  expect(redeemed.body).toHaveProperty('user_id');
}

/**
 * provisionOperator replaces open self-registration: it asserts anonymous
 * sign-up is refused for op, provisions op as admin, redeems its invitation
 * with the virtual authenticator installed on `page`, and signs in through
 * the real LoginView, which asserts the SPA lands on the authenticated
 * dashboard (heading "Dashboard" and the shell's aside) exactly as the old
 * registerOperator did.
 */
export async function provisionOperator(page: Page, op: Operator): Promise<void> {
  await page.goto('/ui/#/login');
  await expectAnonymousSignUpRefused(page, op);
  await redeemInvite(page, await provisionInvite(op));
  await loginOperator(page, op);
}
