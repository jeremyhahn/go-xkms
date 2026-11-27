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

// Account provisioning for the RP ceremony suite: an account is created by
// the administrator and redeems its one-time invitation with a passkey.
//
// The administrator is the credential `xkmsd init --admin-factor mtls` wrote
// under .runtime/storage (run-server.sh); it is presented as a Playwright
// client certificate, which config.yaml's tls.client_auth "verify" accepts.
// The invitation ceremony runs in the page, so the virtual authenticator
// prepare() installed creates the credential.

import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test';

// InviteRedemption is the outcome of the invitation's passkey ceremony.
export interface InviteRedemption {
  status: number;
  ok: boolean;
  body: any;
  credentialId?: string;
  clientError?: string;
}

// adminCredential locates the init-ceremony admin certificate and key.
// run-server.sh points `xkmsd init --data-dir` at <suite>/.runtime/storage,
// and the suite's testDir is <suite>/tests.
export function adminCredential(): { certPath: string; keyPath: string } {
  const storage = `${test.info().project.testDir}/../.runtime/storage`;
  return { certPath: `${storage}/admin-cert.pem`, keyPath: `${storage}/admin-key.pem` };
}

// adminRequest opens an API context that authenticates as the administrator
// over mTLS against apiOrigin.
async function adminRequest(apiOrigin: string): Promise<APIRequestContext> {
  const { certPath, keyPath } = adminCredential();
  return request.newContext({
    baseURL: apiOrigin,
    ignoreHTTPSErrors: true,
    clientCertificates: [{ origin: apiOrigin, certPath, keyPath }],
  });
}

// provisionInvite creates the account as the administrator and returns the
// tenant and token of its invitation (<base>/#/invite/<tenant>/<token>).
export async function provisionInvite(
  apiOrigin: string,
  email: string,
  displayName: string,
): Promise<{ tenant: string; token: string }> {
  const admin = await adminRequest(apiOrigin);
  try {
    const resp = await admin.post('/api/v1/users/', {
      data: { username: email.split('@')[0], email, display_name: displayName },
    });
    expect(resp.status(), await resp.text()).toBe(201);
    const { invite } = await resp.json();
    expect(invite?.token, 'POST /api/v1/users/ returned no invitation').toBeTruthy();
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

// redeemInvite runs the invitation's passkey ceremony in the page against
// /api/v1/invites/{tenant}/{token}/fido2/begin and finish.
export async function redeemInvite(
  page: Page,
  apiBase: string,
  invite: { tenant: string; token: string },
): Promise<InviteRedemption> {
  return page.evaluate(
    async ({ apiBase, tenant, token }) => {
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
      const base = `${apiBase}/api/v1/invites/${encodeURIComponent(tenant)}/${encodeURIComponent(token)}/fido2`;

      const beginResp = await fetch(`${base}/begin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      if (!beginResp.ok) {
        return { status: beginResp.status, ok: false, body: await beginResp.text() };
      }
      const begin = await beginResp.json();
      const { publicKey } = JSON.parse(begin.options_json);
      publicKey.challenge = b64urlToBuf(publicKey.challenge);

      // begin names the ceremony: "create" enrols the invitation's passkey,
      // "get" resumes an activation by asserting the passkey already enrolled.
      let cred: PublicKeyCredential;
      let attestation: any;
      if (begin.ceremony === 'create') {
        publicKey.user.id = b64urlToBuf(publicKey.user.id);
        if (Array.isArray(publicKey.excludeCredentials)) {
          publicKey.excludeCredentials = publicKey.excludeCredentials.map((c: any) => ({ ...c, id: b64urlToBuf(c.id) }));
        }
        try {
          cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
        } catch (e: any) {
          return { status: 0, ok: false, body: null, clientError: `${e.name}: ${e.message}` };
        }
        const att = cred.response as AuthenticatorAttestationResponse;
        attestation = {
          id: cred.id,
          rawId: bufToB64url(cred.rawId),
          type: cred.type,
          response: {
            attestationObject: bufToB64url(att.attestationObject),
            clientDataJSON: bufToB64url(att.clientDataJSON),
          },
          clientExtensionResults: cred.getClientExtensionResults(),
        };
      } else if (begin.ceremony === 'get') {
        if (Array.isArray(publicKey.allowCredentials)) {
          publicKey.allowCredentials = publicKey.allowCredentials.map((c: any) => ({ ...c, id: b64urlToBuf(c.id) }));
        }
        try {
          cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
        } catch (e: any) {
          return { status: 0, ok: false, body: null, clientError: `${e.name}: ${e.message}` };
        }
        const asr = cred.response as AuthenticatorAssertionResponse;
        attestation = {
          id: cred.id,
          rawId: bufToB64url(cred.rawId),
          type: cred.type,
          response: {
            authenticatorData: bufToB64url(asr.authenticatorData),
            clientDataJSON: bufToB64url(asr.clientDataJSON),
            signature: bufToB64url(asr.signature),
            userHandle: asr.userHandle ? bufToB64url(asr.userHandle) : undefined,
          },
          clientExtensionResults: cred.getClientExtensionResults(),
        };
      } else {
        return {
          status: 0,
          ok: false,
          body: null,
          clientError: `unknown invitation ceremony ${JSON.stringify(begin.ceremony)}`,
        };
      }

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
      return { status: finishResp.status, ok: finishResp.ok, body, credentialId: cred.id };
    },
    { apiBase, tenant: invite.tenant, token: invite.token },
  );
}

// provisionPasskeyAccount provisions the account for email as admin and
// redeems its invitation with the page's virtual authenticator. The caller signs in with that passkey.
export async function provisionPasskeyAccount(
  page: Page,
  apiBase: string,
  apiOrigin: string,
  email: string,
  displayName: string,
): Promise<InviteRedemption> {
  const invite = await provisionInvite(apiOrigin, email, displayName);
  const redeemed = await redeemInvite(page, apiBase, invite);
  expect(redeemed.ok, `invitation redemption failed: ${JSON.stringify(redeemed.body ?? redeemed.clientError)}`).toBeTruthy();
  expect(redeemed.status).toBe(200);
  expect(redeemed.body).toHaveProperty('user_id');
  return redeemed;
}
