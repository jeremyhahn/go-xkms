/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of go-xkms.
 *
 * go-xkms is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

// One source for the auth panels' reading of GET /api/v1/capabilities, so
// LoginPanel and RegisterPanel gate the same method on the same key and show
// the same disabled state, naming the setting to turn on (ruling 972 (1)).

import type { AuthClientHost } from './config.ts';
import type { AuthMethod } from './provider.ts';

/** Capabilities as the server reports them; null when the probe failed. */
export type AuthCapabilities = Record<string, unknown> | null;

/** Capability key that gates each auth method. */
export const AUTH_CAPABILITY: Readonly<Record<AuthMethod, string>> = {
  passkey: 'webauthn_enabled',
  certificate: 'piv_login_enabled',
};

/** Disabled state of each sign-in method, naming the xkmsd setting. */
export const SIGN_IN_DISABLED_MESSAGE: Readonly<Record<AuthMethod, string>> = {
  passkey: 'Passkey sign-in is off: set webauthn.enabled: true in xkmsd.yaml',
  certificate: 'Certificate sign-in is off: set auth.piv_login.enabled: true in xkmsd.yaml',
};

/** Disabled state of passkey self-registration. */
export const REGISTRATION_DISABLED_MESSAGE =
  'Passkey sign-up is off: set webauthn.enabled: true in xkmsd.yaml';

/**
 * Reads the deployment capabilities. A client without a capabilities member,
 * or a probe that fails, yields null: a failed probe must not lock the
 * operator out, so nothing is disabled on its account.
 */
export async function readAuthCapabilities(client: AuthClientHost): Promise<AuthCapabilities> {
  try {
    return ((await client.capabilities?.get()) as Record<string, unknown> | undefined) ?? null;
  } catch {
    return null;
  }
}

/** True only when the server explicitly reports the method's key false. */
export function methodOff(caps: AuthCapabilities, method: AuthMethod): boolean {
  return caps !== null && caps[AUTH_CAPABILITY[method]] === false;
}
