// xKey AutoFill Extension - password-vault bridge
//
// The web console unlocks the user's password vault with a key factor (a
// PIV card, a certificate's key, a TPM key) through this extension: the
// page asks the content script, the content script asks this background
// worker, and the worker asks xKey over the encrypted native-messaging
// channel. xKey checks the origin, asks the user to approve, and unlocks
// the vault itself over its own connection to the server; the page learns
// only whether the vault is unlocked. No secret ever passes through here.
//
// The origin sent to xKey is the one the BROWSER attributes to the
// requesting frame (chrome.runtime.MessageSender), never a value the page
// put in its message, and only a top-level frame may ask.

/** The IPC message the worker sends xKey for a vault unlock. */
export interface VaultUnlockRequest {
  type: 'vault';
  vault: { action: 'unlock_key_factor'; origin: string; fingerprints: string[] };
}

/** VaultBridgeError reports a request this worker refuses to forward. */
export class VaultBridgeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultBridgeError';
  }
}

/** How long a vault request may wait: xKey gives the user two minutes. */
export const VAULT_REQUEST_TIMEOUT_MS = 130_000;

const FINGERPRINT = /^[0-9a-f]{64}$/;

/**
 * senderOrigin returns the browser-attributed origin of a top-level frame,
 * or throws VaultBridgeError for a sub-frame or a sender without one.
 */
export function senderOrigin(sender: { frameId?: number; origin?: string; url?: string }): string {
  if (sender.frameId !== 0) {
    throw new VaultBridgeError('Only the console page itself, not a frame inside it, may unlock the vault.');
  }
  if (sender.origin && sender.origin !== 'null') {
    return sender.origin;
  }
  if (sender.url) {
    const origin = new URL(sender.url).origin;
    if (origin !== 'null') return origin;
  }
  throw new VaultBridgeError('The requesting page has no origin.');
}

/**
 * buildVaultUnlockRequest validates the page's fingerprints (SPKI SHA-256,
 * hex) and builds the request for xKey.
 */
export function buildVaultUnlockRequest(origin: string, fingerprints: unknown): VaultUnlockRequest {
  if (!Array.isArray(fingerprints) || fingerprints.length === 0 || fingerprints.length > 32) {
    throw new VaultBridgeError('The request names no key factor.');
  }
  for (const fp of fingerprints) {
    if (typeof fp !== 'string' || !FINGERPRINT.test(fp)) {
      throw new VaultBridgeError('The request names a malformed key factor.');
    }
  }
  return { type: 'vault', vault: { action: 'unlock_key_factor', origin, fingerprints: fingerprints as string[] } };
}

/** vaultUnlockResult turns xKey's reply into the result the page receives. */
export function vaultUnlockResult(resp: { status?: string; error?: string; vault?: { unlocked?: boolean } }): {
  unlocked: boolean;
  error?: string;
} {
  if (resp.status === 'ok' && resp.vault?.unlocked === true) {
    return { unlocked: true };
  }
  return { unlocked: false, error: resp.error || 'xKey did not unlock the vault' };
}
