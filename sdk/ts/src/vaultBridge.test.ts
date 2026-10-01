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

import { describe, expect, it } from 'vitest';
import {
  detectXkeyExtension,
  keyFactorFingerprints,
  unlockWithXkey,
  XkeyBridgeError,
  XkeyExtensionUnavailableError,
  type BridgeWindow,
} from './vaultBridge.js';
import type { PasswordVaultFactor } from './types/passwords.js';

const ORIGIN = 'https://kms.example.com';
const FP = 'a'.repeat(64);

type Listener = (event: MessageEvent) => void;

/**
 * FakePage is a console page with (or without) the xKey extension's content
 * script: it answers pings, and answers unlock requests the way xKey does.
 */
class FakePage implements BridgeWindow {
  readonly location = { origin: ORIGIN };
  readonly sent: Record<string, unknown>[] = [];
  private listeners: Listener[] = [];
  constructor(
    private readonly extension: boolean,
    private readonly answer: (fingerprints: string[]) => { unlocked: boolean; error?: string } | undefined = () => ({ unlocked: true }),
    private readonly replyOrigin = ORIGIN,
  ) {}

  addEventListener(_type: 'message', l: Listener): void {
    this.listeners.push(l);
  }
  removeEventListener(_type: 'message', l: Listener): void {
    this.listeners = this.listeners.filter((x) => x !== l);
  }
  postMessage(message: unknown, targetOrigin: string): void {
    expect(targetOrigin).toBe(ORIGIN);
    const msg = message as Record<string, unknown>;
    this.sent.push(msg);
    if (!this.extension || msg.source !== 'xkms-console') return;
    const reply = (data: Record<string, unknown>) =>
      queueMicrotask(() => this.listeners.forEach((l) => l({ origin: this.replyOrigin, data: { source: 'xkey-extension', requestId: msg.requestId, ...data } } as MessageEvent)));
    if (msg.type === 'xkey-ping') reply({ type: 'xkey-pong' });
    if (msg.type === 'xkey-vault-unlock') {
      const result = this.answer(msg.fingerprints as string[]);
      if (result) reply({ type: 'xkey-vault-unlock-result', ...result });
    }
  }
}

describe('unlockWithXkey', () => {
  it('asks the extension and resolves when xKey reports the vault unlocked; nothing secret is exchanged', async () => {
    const page = new FakePage(true);
    await unlockWithXkey([FP], page);
    const request = page.sent.find((m) => m.type === 'xkey-vault-unlock')!;
    expect(request).toMatchObject({ source: 'xkms-console', fingerprints: [FP] });
    expect(Object.keys(request).sort()).toEqual(['fingerprints', 'requestId', 'source', 'type']);
  });

  it('reports a missing extension with the typed error', async () => {
    await expect(unlockWithXkey([FP], new FakePage(false))).rejects.toBeInstanceOf(XkeyExtensionUnavailableError);
    expect(await detectXkeyExtension(new FakePage(false), 10)).toBe(false);
  });

  it('surfaces xKey refusals', async () => {
    const refused = new FakePage(true, () => ({ unlocked: false, error: 'the request was denied in xKey' }));
    await expect(unlockWithXkey([FP], refused)).rejects.toThrow('denied in xKey');
    await expect(unlockWithXkey([FP], refused)).rejects.toBeInstanceOf(XkeyBridgeError);

    const silent = new FakePage(true, () => undefined);
    await expect(unlockWithXkey([FP], silent, 10)).rejects.toThrow('did not answer');
    await expect(unlockWithXkey([], new FakePage(true))).rejects.toBeInstanceOf(XkeyBridgeError);
  });

  it('ignores replies from another origin', async () => {
    expect(await detectXkeyExtension(new FakePage(true, undefined, 'https://evil.example.org'), 10)).toBe(false);
  });
});

describe('keyFactorFingerprints', () => {
  it('lists the key factors only', () => {
    const factors: PasswordVaultFactor[] = [
      { id: '1', factor: 'passphrase', created_at: '' },
      { id: '2', factor: 'piv', created_at: '', key_fingerprint: FP },
      { id: '3', factor: 'tpm', created_at: '', key_fingerprint: 'b'.repeat(64) },
      { id: '4', factor: 'passkey', created_at: '' },
    ];
    expect(keyFactorFingerprints(factors)).toEqual([FP, 'b'.repeat(64)]);
  });
});
