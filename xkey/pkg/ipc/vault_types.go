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

package ipc

// ActionVaultUnlockKeyFactor asks xKey to unlock the user's password vault
// with a key factor (PIV, certificate, TPM) on behalf of the web console.
const ActionVaultUnlockKeyFactor = "unlock_key_factor"

// VaultPayload is a browser-extension password-vault request.
//
// Origin is the console page's origin as the BROWSER reported it to the
// extension (chrome.runtime MessageSender.origin), never a value the page
// supplied. Fingerprints are the key factors the page's vault lists; xKey
// unlocks only with factors it also finds in the vault it reads itself.
type VaultPayload struct {
	Action       string   `json:"action"`
	Origin       string   `json:"origin"`
	Fingerprints []string `json:"fingerprints"`
}

// VaultResult reports a vault request's outcome. It carries no secret: xKey
// unlocks the vault over its own connection and only says that it did.
type VaultResult struct {
	Unlocked bool `json:"unlocked"`
}

// Validate checks the VaultPayload for correctness.
func (p *VaultPayload) Validate() error {
	if p.Action != ActionVaultUnlockKeyFactor {
		return &DetailError{Err: ErrInvalidMessage, Detail: ": unknown vault action " + p.Action}
	}
	if p.Origin == "" {
		return &DetailError{Err: ErrInvalidMessage, Detail: ": origin is required for a vault request"}
	}
	if len(p.Fingerprints) == 0 {
		return &DetailError{Err: ErrInvalidMessage, Detail: ": fingerprints are required for a vault request"}
	}
	return nil
}
