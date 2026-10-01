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

import { enrollVaultPasskey, keyFactorFingerprints, unlockVaultPasskey, unlockWithXkey } from "@go-xkms/sdk";
import type {
  PasswordVaultCredential,
  PasswordVaultFactor,
  PasswordVaultFactorInfoType,
  PasswordVaultStatusResponse,
} from "@go-xkms/sdk";

/**
 * MIN_PASSPHRASE_LENGTH mirrors pkg/staticpw MinPassphraseLength (NIST SP
 * 800-63B). The form refuses shorter ones before the server would.
 */
export const MIN_PASSPHRASE_LENGTH = 8;

const factorLabels: Record<PasswordVaultFactorInfoType, string> = {
  passphrase: "passphrase",
  passkey: "passkey",
  piv: "PIV card",
  certificate: "certificate",
  tpm: "TPM key",
  recovery: "recovery code",
};

/** factorTypeLabel names a vault factor type for display. */
export function factorTypeLabel(type: PasswordVaultFactorInfoType): string {
  return factorLabels[type] ?? type;
}

/**
 * enrollPasskey creates a vault passkey in this browser for the server's
 * relying party (WebAuthn PRF). It throws the SDK's typed
 * VaultPasskeyPrfUnsupportedError / VaultPasskeyUnavailableError, whose
 * messages say what to do instead.
 */
export function enrollPasskey(status: PasswordVaultStatusResponse, label: string): Promise<PasswordVaultCredential> {
  return enrollVaultPasskey({ status, label });
}

/** unlockPasskey evaluates the vault's passkeys for this page's domain. */
export function unlockPasskey(factors: PasswordVaultFactor[]): Promise<PasswordVaultCredential> {
  return unlockVaultPasskey(factors);
}

/** hasPasskey reports whether the vault lists a passkey factor. */
export function hasPasskey(status: PasswordVaultStatusResponse | null): boolean {
  return status?.factors.some((f) => f.factor === "passkey") ?? false;
}

/** hasKeyFactor reports whether the vault lists a PIV, certificate or TPM factor. */
export function hasKeyFactor(status: PasswordVaultStatusResponse | null): boolean {
  return status ? keyFactorFingerprints(status.factors).length > 0 : false;
}

/**
 * unlockWithKeyFactor asks xKey, through its browser extension, to unlock
 * the vault with one of its PIV, certificate or TPM factors. xKey unlocks
 * the vault itself after the user approves; nothing secret reaches this
 * page. It throws the SDK's XkeyExtensionUnavailableError without the
 * extension and XkeyBridgeError when xKey refuses.
 */
export function unlockWithKeyFactor(status: PasswordVaultStatusResponse): Promise<void> {
  return unlockWithXkey(keyFactorFingerprints(status.factors));
}
