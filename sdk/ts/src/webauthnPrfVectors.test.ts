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

// The browser half of the password-vault passkey cross-surface vector test.
//
// A browser evaluating the WebAuthn prf extension with eval.first = salt sends
// the authenticator the hmac-secret salt SHA-256(UTF8("WebAuthn PRF") || 0x00
// || salt) (WebAuthn Level 3). This test computes that with WebCrypto, exactly
// as a browser does, over the vectors in pkg/fido2/testdata; the Go tests
// (pkg/fido2 prf_test.go, pkg/vaultpasskey) prove the CLI/GUI path sends the
// same bytes for the same vectors. Together: a passkey enrolled on any
// surface evaluates identically on every other.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

interface Vectors {
  vectors: { salt: string; prf_input: string }[];
}

const here = dirname(fileURLToPath(import.meta.url));
const vectorFile = resolve(here, '../../../pkg/fido2/testdata/webauthn_prf_salt_vectors.json');

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function unhex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

// browserPrfInput is the browser's prf salt transform, written from the
// WebAuthn definition with the platform's WebCrypto.
async function browserPrfInput(salt: Uint8Array): Promise<Uint8Array> {
  const label = new TextEncoder().encode('WebAuthn PRF');
  const message = new Uint8Array(label.length + 1 + salt.length);
  message.set(label, 0);
  message[label.length] = 0x00;
  message.set(salt, label.length + 1);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', message));
}

describe('WebAuthn prf salt vectors (browser path)', () => {
  const { vectors } = JSON.parse(readFileSync(vectorFile, 'utf8')) as Vectors;

  it('has vectors', () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  it.each(vectors)('salt $salt maps to the vector the CLI path produces', async ({ salt, prf_input }) => {
    expect(hex(await browserPrfInput(unhex(salt)))).toBe(prf_input);
  });

  it('is not the identity', async () => {
    const salt = new Uint8Array(32);
    expect(hex(await browserPrfInput(salt))).not.toBe(hex(salt));
  });
});
