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
 * The browser side of a password-vault passkey.
 *
 * A vault passkey is a WebAuthn credential evaluated with the PRF extension:
 * `extensions: { prf: { eval: { first: prf_salt } } }`, always with
 * `userVerification: "required"`. The browser sends the authenticator the
 * hmac-secret salt SHA-256("WebAuthn PRF" || 0x00 || prf_salt) and returns
 * the 32-byte output as `results.first` -- the factor's secret. xkey and
 * xkmsctl (pkg/vaultpasskey) apply the same transform themselves, so a
 * passkey enrolled here unlocks there and the reverse
 * (pkg/fido2/testdata/webauthn_prf_salt_vectors.json proves both halves).
 *
 * The relying party is the server's: the vault status's `passkey_rp_id`,
 * which is the domain the console is served from, recorded on every passkey
 * factor (`rp_id`). A browser can only use a factor whose relying party is
 * this page's domain or a parent of it.
 *
 * Nothing here falls back: an authenticator or browser without PRF support
 * is reported as VaultPasskeyPrfUnsupportedError, never answered with a
 * weaker factor.
 */

import { bufferToBase64url, base64urlToBuffer } from './webauthn.js';
import type { PasswordVaultCredential, PasswordVaultFactor, PasswordVaultStatusResponse } from './types/passwords.js';

/** The length of a PRF salt and of a PRF output. */
const PRF_LENGTH = 32;

/** The display name of a vault passkey's relying party (pkg/vaultpasskey). */
export const VAULT_PASSKEY_RP_NAME = 'xkms password vault';

/**
 * VaultPasskeyPrfUnsupportedError: the browser or the authenticator returned
 * no PRF result. The passkey cannot hold a vault factor; the message says
 * what would.
 */
export class VaultPasskeyPrfUnsupportedError extends Error {
  constructor() {
    super(
      'This browser or security key does not support the WebAuthn PRF extension (FIDO2 hmac-secret), ' +
        'which a vault passkey needs. Use a security key with hmac-secret and a PIN, in a current Chrome, ' +
        'Edge, Firefox or Safari, or use your passphrase.',
    );
    this.name = 'VaultPasskeyPrfUnsupportedError';
  }
}

/**
 * VaultPasskeyUnavailableError: this page cannot use a vault passkey -- the
 * server offers none, the browser has no WebAuthn, or none of the vault's
 * passkeys belongs to this page's domain.
 */
export class VaultPasskeyUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultPasskeyUnavailableError';
  }
}

/** Where the module reaches WebAuthn and randomness; tests replace both. */
export interface VaultPasskeyPlatform {
  credentials?: Pick<CredentialsContainer, 'create' | 'get'>;
  hostname: string;
  random(length: number): Uint8Array<ArrayBuffer>;
}

function defaultPlatform(): VaultPasskeyPlatform {
  return {
    credentials: globalThis.navigator?.credentials,
    hostname: globalThis.location?.hostname ?? '',
    random: (n) => crypto.getRandomValues(new Uint8Array(new ArrayBuffer(n))),
  };
}

/** relyingPartyServes reports whether a page on hostname can use rpId. */
export function relyingPartyServes(rpId: string, hostname: string): boolean {
  return rpId !== '' && (hostname === rpId || hostname.endsWith('.' + rpId));
}

/** bufferToBase64 encodes bytes as standard, padded base64 (Go's []byte JSON). */
export function bufferToBase64(buffer: ArrayBuffer | ArrayBufferView): string {
  const url = bufferToBase64url(buffer).replace(/-/g, '+').replace(/_/g, '/');
  return url + '='.repeat((4 - (url.length % 4)) % 4);
}

interface PrfOutputs {
  enabled?: boolean;
  results?: { first?: ArrayBuffer | ArrayBufferView };
}

/** prfFirst returns a credential's 32-byte PRF output, or undefined. */
function prfFirst(credential: PublicKeyCredential): Uint8Array | undefined {
  const prf = (credential.getClientExtensionResults() as { prf?: PrfOutputs }).prf;
  const first = prf?.results?.first;
  if (first === undefined) return undefined;
  const bytes = first instanceof ArrayBuffer ? new Uint8Array(first) : new Uint8Array(first.buffer, first.byteOffset, first.byteLength);
  return bytes.length === PRF_LENGTH ? bytes : undefined;
}

function requireCredentials(platform: VaultPasskeyPlatform): Pick<CredentialsContainer, 'create' | 'get'> {
  if (!platform.credentials) {
    throw new VaultPasskeyUnavailableError('This browser has no WebAuthn support.');
  }
  return platform.credentials;
}

/** Options for enrolling a vault passkey. */
export interface EnrollVaultPasskeyOptions {
  /** The vault status: its `passkey_rp_id` is the relying party. */
  status: Pick<PasswordVaultStatusResponse, 'passkey_rp_id'>;
  /** Names the factor ("laptop key"). */
  label?: string;
  /** Names the credential's user on the authenticator. */
  userName?: string;
}

/**
 * enrollVaultPasskey creates a vault passkey and evaluates its PRF over a
 * fresh salt, returning the credential for `passwords.vaultEnroll` (or
 * `vaultRecover`). The authenticator is touched once when it evaluates PRF
 * at creation, twice otherwise.
 */
export async function enrollVaultPasskey(
  options: EnrollVaultPasskeyOptions,
  platform: VaultPasskeyPlatform = defaultPlatform(),
): Promise<PasswordVaultCredential> {
  const rpId = options.status.passkey_rp_id ?? '';
  if (rpId === '') {
    throw new VaultPasskeyUnavailableError(
      'The server offers no passkeys: it has no WebAuthn relying party (webauthn.rp_id) configured.',
    );
  }
  if (!relyingPartyServes(rpId, platform.hostname)) {
    throw new VaultPasskeyUnavailableError(
      `Vault passkeys belong to ${rpId}; open the console there to enroll one.`,
    );
  }
  const credentials = requireCredentials(platform);
  const salt = platform.random(PRF_LENGTH);
  const userName = options.userName ?? VAULT_PASSKEY_RP_NAME;

  const created = (await credentials.create({
    publicKey: {
      rp: { id: rpId, name: VAULT_PASSKEY_RP_NAME },
      user: { id: platform.random(16), name: userName, displayName: userName },
      challenge: platform.random(32),
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: { userVerification: 'required', residentKey: 'discouraged' },
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!created) {
    throw new VaultPasskeyUnavailableError('No passkey was created.');
  }
  const prf = (created.getClientExtensionResults() as { prf?: PrfOutputs }).prf;
  if (prf?.enabled !== true) {
    throw new VaultPasskeyPrfUnsupportedError();
  }

  // An authenticator that evaluates PRF at creation (CTAP 2.2) has already
  // answered; others evaluate it on a get() over the new credential.
  const secret = prfFirst(created) ?? (await evaluate(credentials, rpId, [{ id: created.rawId, salt }], platform)).secret;
  return {
    factor: 'passkey',
    credential_id: bufferToBase64(created.rawId),
    prf_salt: bufferToBase64(salt),
    secret: bufferToBase64(secret),
    rp_id: rpId,
    ...(options.label !== undefined ? { label: options.label } : {}),
  };
}

/**
 * unlockVaultPasskey evaluates the vault's passkeys that belong to this
 * page's domain in one WebAuthn ceremony, each over its own salt, and
 * returns the unlock credential of the one the user presented.
 */
export async function unlockVaultPasskey(
  factors: PasswordVaultFactor[],
  platform: VaultPasskeyPlatform = defaultPlatform(),
): Promise<PasswordVaultCredential> {
  const passkeys = factors.filter((f) => f.factor === 'passkey' && f.credential_id && f.prf_salt && f.rp_id);
  if (passkeys.length === 0) {
    throw new VaultPasskeyUnavailableError('Your vault has no passkey.');
  }
  const usable = passkeys.filter((f) => relyingPartyServes(f.rp_id!, platform.hostname));
  if (usable.length === 0) {
    throw new VaultPasskeyUnavailableError(
      `Your vault's passkeys belong to ${passkeys.map((f) => f.rp_id).join(', ')}; open the console there, or use xkey.`,
    );
  }
  // One ceremony is scoped to one relying party: the page's own, preferring
  // the most specific match.
  const rpId = usable.map((f) => f.rp_id!).sort((a, b) => b.length - a.length)[0]!;
  const candidates = usable
    .filter((f) => f.rp_id === rpId)
    .map((f) => ({ id: base64urlToBuffer(f.credential_id!), salt: new Uint8Array(base64urlToBuffer(f.prf_salt!)) }));
  const { id, secret } = await evaluate(requireCredentials(platform), rpId, candidates, platform);
  return { factor: 'passkey', credential_id: bufferToBase64(id), secret: bufferToBase64(secret) };
}

/**
 * evaluate runs one get() ceremony over candidates, each with its own PRF
 * salt (prf.evalByCredential), and returns the presented credential's ID and
 * PRF output.
 */
async function evaluate(
  credentials: Pick<CredentialsContainer, 'get'>,
  rpId: string,
  candidates: { id: ArrayBuffer; salt: Uint8Array<ArrayBuffer> }[],
  platform: VaultPasskeyPlatform,
): Promise<{ id: ArrayBuffer; secret: Uint8Array }> {
  const evalByCredential: Record<string, { first: Uint8Array<ArrayBuffer> }> = {};
  for (const c of candidates) evalByCredential[bufferToBase64url(c.id)] = { first: c.salt };
  const asserted = (await credentials.get({
    publicKey: {
      rpId,
      challenge: platform.random(32),
      allowCredentials: candidates.map((c) => ({ type: 'public-key', id: c.id })),
      userVerification: 'required',
      extensions: { prf: { evalByCredential } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!asserted) {
    throw new VaultPasskeyUnavailableError('No passkey was presented.');
  }
  const secret = prfFirst(asserted);
  if (!secret) {
    throw new VaultPasskeyPrfUnsupportedError();
  }
  return { id: asserted.rawId, secret };
}
