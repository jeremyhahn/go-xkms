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
 * The console side of the xKey browser bridge: unlocking the password vault
 * with a key factor (a PIV card, a certificate's key, a TPM key).
 *
 * A browser never holds those keys and never receives a private key or a
 * certificate upload. The page asks the xKey browser extension (over
 * window.postMessage); the extension asks the xKey app (native messaging);
 * xKey checks that the page is this server's console, asks the user to
 * approve, recovers the factor's secret with its own key backend and unlocks
 * the vault ITSELF over its own connection to the server. The page receives
 * only whether the vault is now unlocked -- no key, no secret.
 *
 * Messages are tagged `source: "xkms-console"` going out and
 * `source: "xkey-extension"` coming back, and are exchanged with this page's
 * own origin only.
 */

import type { PasswordVaultFactor } from './types/passwords.js';

/** XkeyExtensionUnavailableError: the xKey browser extension did not answer. */
export class XkeyExtensionUnavailableError extends Error {
  constructor() {
    super(
      'Unlocking with a PIV card, certificate or TPM key needs the xKey browser extension and the xKey app. ' +
        'Install the extension, pair it with xKey, and connect xKey to this server.',
    );
    this.name = 'XkeyExtensionUnavailableError';
  }
}

/** XkeyBridgeError: xKey refused or failed the unlock; the message says why. */
export class XkeyBridgeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'XkeyBridgeError';
  }
}

/** The part of `window` the bridge uses; tests supply their own. */
export interface BridgeWindow {
  location: { origin: string };
  postMessage(message: unknown, targetOrigin: string): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
}

/** How long to wait for the extension to answer a ping. */
export const XKEY_PING_TIMEOUT_MS = 800;

/** How long an unlock may take: xKey gives the user two minutes to approve. */
export const XKEY_UNLOCK_TIMEOUT_MS = 135_000;

const KEY_FACTORS = new Set(['piv', 'certificate', 'tpm']);

/** keyFactorFingerprints lists the vault's key factors by key fingerprint. */
export function keyFactorFingerprints(factors: PasswordVaultFactor[]): string[] {
  return factors.filter((f) => KEY_FACTORS.has(f.factor) && f.key_fingerprint).map((f) => f.key_fingerprint!);
}

function newRequestId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * exchange posts one request to the extension and resolves with its reply,
 * or with undefined when none arrives within timeoutMs.
 */
function exchange(
  win: BridgeWindow,
  request: Record<string, unknown>,
  replyType: string,
  timeoutMs: number,
): Promise<Record<string, unknown> | undefined> {
  const requestId = newRequestId();
  return new Promise((resolve) => {
    const onMessage = (event: MessageEvent) => {
      const data = event.data as Record<string, unknown> | null;
      if (event.origin !== win.location.origin || !data || data.source !== 'xkey-extension') return;
      if (data.type !== replyType || data.requestId !== requestId) return;
      cleanup();
      resolve(data);
    };
    const timer = setTimeout(() => {
      cleanup();
      resolve(undefined);
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(timer);
      win.removeEventListener('message', onMessage);
    };
    win.addEventListener('message', onMessage);
    win.postMessage({ source: 'xkms-console', requestId, ...request }, win.location.origin);
  });
}

/** detectXkeyExtension reports whether the xKey extension answers on this page. */
export async function detectXkeyExtension(win: BridgeWindow = window, timeoutMs = XKEY_PING_TIMEOUT_MS): Promise<boolean> {
  return (await exchange(win, { type: 'xkey-ping' }, 'xkey-pong', timeoutMs)) !== undefined;
}

/**
 * unlockWithXkey asks xKey, through its browser extension, to unlock the
 * vault with one of the key factors fingerprints names. It resolves once
 * xKey reports the vault unlocked, and throws XkeyExtensionUnavailableError
 * without the extension and XkeyBridgeError when xKey refuses (wrong page,
 * denied, timed out, no token here).
 */
export async function unlockWithXkey(
  fingerprints: string[],
  win: BridgeWindow = window,
  timeoutMs = XKEY_UNLOCK_TIMEOUT_MS,
): Promise<void> {
  if (fingerprints.length === 0) {
    throw new XkeyBridgeError('Your vault has no PIV, certificate or TPM factor.');
  }
  if (!(await detectXkeyExtension(win))) {
    throw new XkeyExtensionUnavailableError();
  }
  const reply = await exchange(win, { type: 'xkey-vault-unlock', fingerprints }, 'xkey-vault-unlock-result', timeoutMs);
  if (!reply) {
    throw new XkeyBridgeError('xKey did not answer in time.');
  }
  if (reply.unlocked !== true) {
    throw new XkeyBridgeError(typeof reply.error === 'string' && reply.error ? reply.error : 'xKey did not unlock the vault.');
  }
}
