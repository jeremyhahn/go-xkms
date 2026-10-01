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

import type { PasswordVaultFactorInfoType } from "@go-xkms/sdk";

/**
 * MIN_PASSPHRASE_LENGTH mirrors pkg/staticpw MinPassphraseLength (NIST SP
 * 800-63B). The form refuses shorter ones before the server would.
 */
export const MIN_PASSPHRASE_LENGTH = 8;

const factorLabels: Record<PasswordVaultFactorInfoType, string> = {
  passphrase: "passphrase",
  passkey: "passkey",
  recovery: "recovery code",
};

/** factorTypeLabel names a vault factor type for display. */
export function factorTypeLabel(type: PasswordVaultFactorInfoType): string {
  return factorLabels[type] ?? type;
}
