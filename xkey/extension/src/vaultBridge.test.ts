// Tests for the password-vault bridge (run: npm test -- node's test runner
// with type stripping, so they are not part of the extension build).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildVaultUnlockRequest, senderOrigin, VaultBridgeError, vaultUnlockResult } from './vaultBridge.ts';

const FP = 'a'.repeat(64);

test('the origin is the browser-attributed origin of the top-level frame', () => {
  assert.equal(senderOrigin({ frameId: 0, origin: 'https://kms.example.com' }), 'https://kms.example.com');
  assert.equal(senderOrigin({ frameId: 0, url: 'https://kms.example.com:8443/#/passwords' }), 'https://kms.example.com:8443');
});

test('a frame inside a page, or a sender without an origin, is refused', () => {
  assert.throws(() => senderOrigin({ frameId: 3, origin: 'https://kms.example.com' }), VaultBridgeError);
  assert.throws(() => senderOrigin({ frameId: 0 }), VaultBridgeError);
  assert.throws(() => senderOrigin({ frameId: 0, origin: 'null', url: 'data:text/html,x' }), VaultBridgeError);
});

test('the request carries the origin and validated fingerprints only', () => {
  assert.deepEqual(buildVaultUnlockRequest('https://kms.example.com', [FP]), {
    type: 'vault',
    vault: { action: 'unlock_key_factor', origin: 'https://kms.example.com', fingerprints: [FP] },
  });
  for (const bad of [undefined, [], ['xyz'], [FP.toUpperCase()], [42], new Array(33).fill(FP)]) {
    assert.throws(() => buildVaultUnlockRequest('https://kms.example.com', bad), VaultBridgeError);
  }
});

test('the page learns only whether the vault is unlocked', () => {
  assert.deepEqual(vaultUnlockResult({ status: 'ok', vault: { unlocked: true } }), { unlocked: true });
  assert.deepEqual(vaultUnlockResult({ status: 'error', error: 'denied in xKey' }), { unlocked: false, error: 'denied in xKey' });
  assert.deepEqual(vaultUnlockResult({ status: 'ok' }), { unlocked: false, error: 'xKey did not unlock the vault' });
});
