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

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  bufferToBase64,
  enrollVaultPasskey,
  relyingPartyServes,
  unlockVaultPasskey,
  VaultPasskeyPrfUnsupportedError,
  VaultPasskeyUnavailableError,
  type VaultPasskeyPlatform,
} from './vaultPasskey.js';
import { bufferToBase64url, base64urlToBuffer } from './webauthn.js';
import type { PasswordVaultFactor } from './types/passwords.js';

const RP = 'kms.example.com';

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function unhex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function bytesOf(b64: string): Uint8Array {
  return new Uint8Array(base64urlToBuffer(b64));
}

async function prfOutput(credRandom: Uint8Array, first: Uint8Array): Promise<Uint8Array> {
  // The browser's transform, then the authenticator's hmac-secret.
  const label = new TextEncoder().encode('WebAuthn PRF');
  const msg = new Uint8Array(label.length + 1 + first.length);
  msg.set(label, 0);
  msg.set(first, label.length + 1);
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', msg));
  const key = await crypto.subtle.importKey('raw', credRandom, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, salt));
}

interface FakeOptions {
  prfEnabled?: boolean;
  prfAtCreate?: boolean;
  prfOnGet?: boolean;
}

/**
 * fakeBrowser is a browser with one platform authenticator: credentials are
 * scoped to their relying party, PRF is the WebAuthn transform plus
 * hmac-secret over a per-credential random, and every call is recorded.
 */
class FakeBrowser {
  readonly calls: { create: CredentialCreationOptions[]; get: CredentialRequestOptions[] } = { create: [], get: [] };
  readonly creds = new Map<string, { rpId: string; credRandom: Uint8Array }>();
  constructor(private readonly opts: FakeOptions = {}) {}

  seed(id: Uint8Array, rpId: string, credRandom: Uint8Array): void {
    this.creds.set(bufferToBase64url(id), { rpId, credRandom });
  }

  platform(hostname = RP): VaultPasskeyPlatform {
    let counter = 0;
    return {
      hostname,
      random: (n) => new Uint8Array(new ArrayBuffer(n)).fill(++counter),
      credentials: {
        create: async (o?: CredentialCreationOptions) => {
          this.calls.create.push(o!);
          const pk = o!.publicKey!;
          const id = new Uint8Array(16).fill(0xc0 + this.creds.size);
          const credRandom = new Uint8Array(32).fill(0x40 + this.creds.size);
          this.seed(id, pk.rp.id!, credRandom);
          const first = (pk.extensions as { prf?: { eval?: { first: Uint8Array } } }).prf?.eval?.first;
          const results = this.opts.prfAtCreate && first ? { first: await prfOutput(credRandom, first) } : undefined;
          return credential(id, { prf: { enabled: this.opts.prfEnabled ?? true, results } });
        },
        get: async (o?: CredentialRequestOptions) => {
          this.calls.get.push(o!);
          const pk = o!.publicKey!;
          for (const allowed of pk.allowCredentials ?? []) {
            const key = bufferToBase64url(allowed.id as ArrayBuffer);
            const cred = this.creds.get(key);
            if (!cred || cred.rpId !== pk.rpId) continue;
            const prf = (pk.extensions as { prf?: { evalByCredential?: Record<string, { first: Uint8Array }> } }).prf;
            const first = prf?.evalByCredential?.[key]?.first;
            const results = this.opts.prfOnGet === false || !first ? undefined : { first: await prfOutput(cred.credRandom, first) };
            return credential(new Uint8Array(base64urlToBuffer(key)), { prf: { results } });
          }
          return null;
        },
      } as unknown as Pick<CredentialsContainer, 'create' | 'get'>,
    };
  }
}

function credential(id: Uint8Array, ext: unknown): PublicKeyCredential {
  return { rawId: id.buffer.slice(id.byteOffset, id.byteOffset + id.byteLength), getClientExtensionResults: () => ext } as unknown as PublicKeyCredential;
}

function factorFrom(cred: { credential_id?: string; prf_salt?: string; rp_id?: string }): PasswordVaultFactor {
  return { id: 'f', factor: 'passkey', created_at: '', credential_id: cred.credential_id, prf_salt: cred.prf_salt, rp_id: cred.rp_id };
}

describe('enrollVaultPasskey', () => {
  it('creates a passkey for the server relying party, UV required, PRF over a fresh salt', async () => {
    const browser = new FakeBrowser();
    const cred = await enrollVaultPasskey({ status: { passkey_rp_id: RP }, label: 'laptop' }, browser.platform());

    const created = browser.calls.create[0]!.publicKey!;
    expect(created.rp.id).toBe(RP);
    expect(created.authenticatorSelection?.userVerification).toBe('required');
    const salt = bytesOf(cred.prf_salt!);
    expect(salt).toHaveLength(32);
    expect((created.extensions as { prf: { eval: { first: Uint8Array } } }).prf.eval.first).toEqual(salt);
    // No PRF result at creation: a get() over the new credential evaluates it.
    expect(browser.calls.get).toHaveLength(1);
    expect(browser.calls.get[0]!.publicKey!.userVerification).toBe('required');
    expect(cred).toMatchObject({ factor: 'passkey', rp_id: RP, label: 'laptop' });
    expect(bytesOf(cred.secret!)).toHaveLength(32);
  });

  it('uses the PRF result returned at creation without a second touch', async () => {
    const browser = new FakeBrowser({ prfAtCreate: true });
    const cred = await enrollVaultPasskey({ status: { passkey_rp_id: RP } }, browser.platform());
    expect(browser.calls.get).toHaveLength(0);
    expect(bytesOf(cred.secret!)).toHaveLength(32);
  });

  it('refuses an authenticator without PRF with a typed error, never a fallback', async () => {
    const browser = new FakeBrowser({ prfEnabled: false });
    await expect(enrollVaultPasskey({ status: { passkey_rp_id: RP } }, browser.platform())).rejects.toBeInstanceOf(
      VaultPasskeyPrfUnsupportedError,
    );
    const noResult = new FakeBrowser({ prfOnGet: false });
    await expect(enrollVaultPasskey({ status: { passkey_rp_id: RP } }, noResult.platform())).rejects.toBeInstanceOf(
      VaultPasskeyPrfUnsupportedError,
    );
  });

  it('refuses when the server offers no passkeys, or on another domain', async () => {
    const browser = new FakeBrowser();
    await expect(enrollVaultPasskey({ status: {} }, browser.platform())).rejects.toBeInstanceOf(VaultPasskeyUnavailableError);
    await expect(enrollVaultPasskey({ status: { passkey_rp_id: RP } }, browser.platform('evil.example.org'))).rejects.toBeInstanceOf(
      VaultPasskeyUnavailableError,
    );
    const noWebAuthn = { ...browser.platform(), credentials: undefined };
    await expect(enrollVaultPasskey({ status: { passkey_rp_id: RP } }, noWebAuthn)).rejects.toBeInstanceOf(VaultPasskeyUnavailableError);
    expect(browser.calls.create).toHaveLength(0);
  });
});

describe('unlockVaultPasskey', () => {
  it('reproduces the enrolled secret from the stored salt', async () => {
    const browser = new FakeBrowser();
    const platform = browser.platform();
    const enrolled = await enrollVaultPasskey({ status: { passkey_rp_id: RP } }, platform);
    const cred = await unlockVaultPasskey([factorFrom(enrolled)], platform);
    expect(cred.credential_id).toBe(enrolled.credential_id);
    expect(cred.secret).toBe(enrolled.secret);
    expect(cred.prf_salt).toBeUndefined();
  });

  it('evaluates every passkey of this domain in one ceremony, each over its own salt', async () => {
    const browser = new FakeBrowser();
    const platform = browser.platform();
    const a = await enrollVaultPasskey({ status: { passkey_rp_id: RP } }, platform);
    const b = await enrollVaultPasskey({ status: { passkey_rp_id: RP } }, platform);
    browser.calls.get.length = 0;
    const foreign: PasswordVaultFactor = { id: 'x', factor: 'passkey', created_at: '', credential_id: 'AAAA', prf_salt: 'AAAA', rp_id: 'other.example.org' };

    await unlockVaultPasskey([foreign, factorFrom(a), factorFrom(b)], platform);
    const req = browser.calls.get[0]!.publicKey!;
    expect(req.rpId).toBe(RP);
    expect(req.allowCredentials).toHaveLength(2);
    const byCred = (req.extensions as { prf: { evalByCredential: Record<string, { first: Uint8Array }> } }).prf.evalByCredential;
    expect(Object.values(byCred).map((v) => bufferToBase64(v.first))).toEqual([a.prf_salt, b.prf_salt]);
  });

  it('refuses with typed errors when no passkey can run here', async () => {
    const browser = new FakeBrowser();
    await expect(unlockVaultPasskey([], browser.platform())).rejects.toBeInstanceOf(VaultPasskeyUnavailableError);
    const elsewhere: PasswordVaultFactor = { id: 'x', factor: 'passkey', created_at: '', credential_id: 'AAAA', prf_salt: 'AAAA', rp_id: 'other.example.org' };
    await expect(unlockVaultPasskey([elsewhere], browser.platform())).rejects.toThrow(/other\.example\.org/);

    const noPrf = new FakeBrowser({ prfOnGet: false });
    const id = new Uint8Array(16).fill(9);
    noPrf.seed(id, RP, new Uint8Array(32));
    const factor: PasswordVaultFactor = { id: 'f', factor: 'passkey', created_at: '', credential_id: bufferToBase64(id), prf_salt: bufferToBase64(new Uint8Array(32)), rp_id: RP };
    await expect(unlockVaultPasskey([factor], noPrf.platform())).rejects.toBeInstanceOf(VaultPasskeyPrfUnsupportedError);
  });
});

describe('relyingPartyServes', () => {
  it('accepts the domain and its subdomains only', () => {
    expect(relyingPartyServes(RP, RP)).toBe(true);
    expect(relyingPartyServes(RP, 'console.kms.example.com')).toBe(true);
    expect(relyingPartyServes(RP, 'notkms.example.com')).toBe(false);
    expect(relyingPartyServes('', RP)).toBe(false);
  });
});

// The browser half of the vault passkey secret vectors: pkg/vaultpasskey
// proves the CLI/GUI half against the same file, so a passkey enrolled on
// either surface unlocks on the other.
describe('vault passkey secret vectors (browser path)', () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const file = resolve(here, '../../../pkg/fido2/testdata/vault_passkey_secret_vectors.json');
  const { vectors } = JSON.parse(readFileSync(file, 'utf8')) as { vectors: { cred_random: string; prf_salt: string; secret: string }[] };

  it('has vectors', () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  it.each(vectors)('cred_random $cred_random over salt $prf_salt', async ({ cred_random, prf_salt, secret }) => {
    const browser = new FakeBrowser();
    const id = new Uint8Array([0xc1, 0x01]);
    browser.seed(id, RP, unhex(cred_random));
    const factor: PasswordVaultFactor = {
      id: 'f', factor: 'passkey', created_at: '', rp_id: RP,
      credential_id: bufferToBase64(id), prf_salt: bufferToBase64(unhex(prf_salt)),
    };
    const cred = await unlockVaultPasskey([factor], browser.platform());
    expect(hex(bytesOf(cred.secret!))).toBe(secret);
  });
});
