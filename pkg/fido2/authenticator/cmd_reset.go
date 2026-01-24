// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package authenticator

import "context"

// handleReset implements the CTAP2 authenticatorReset command (0x07).
//
// The Reset command performs a factory reset of the authenticator:
//   - Deletes all stored credentials
//   - Clears the PIN and resets retry counters
//   - Preserves the AAGUID (authenticator identity)
//   - Optionally generates a new attestation key
//
// Per CTAP2 specification, reset requires:
//   - User presence confirmation
//   - Must be performed within a short time after power-up (implementation-defined)
//
// For a virtual/software authenticator, user presence is simulated as always approved,
// and the power-up timing requirement is relaxed.
//
// Returns:
//   - Success response with StatusOK on successful reset
//   - Error response if storage operations fail
func (a *Authenticator) handleReset() ([]byte, error) {
	a.mu.Lock()

	// User presence is required for reset.
	ctx := context.Background()
	a.mu.Unlock() // Temporarily release lock for user interaction
	if err := a.requestUserPresence(ctx, "", "", "", "reset"); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	// Delete all credentials from storage
	if err := a.clearAllCredentials(); err != nil {
		return nil, err
	}

	// Preserve the AAGUID before resetting state
	aaguid := a.state.AAGUID

	// Reset authenticator state
	a.resetState(aaguid)

	// Clear any cached PIN/UV auth tokens
	a.clearPINState()

	// Clear assertion state
	a.clearAssertionState()

	// Clear credential management enumeration state
	a.clearCredMgmtState()

	// Save the reset state to storage
	if err := a.storage.SaveState(a.state); err != nil {
		return nil, err
	}

	// Return success with no additional data
	return a.successResponse(nil), nil
}

// clearAllCredentials removes all credentials from storage.
// This iterates through known relying parties and deletes their credentials.
// For storage backends that support listing all credentials, we use that.
func (a *Authenticator) clearAllCredentials() error {
	// First, try to use the Clearable interface if available
	if clearable, ok := a.storage.(ClearableStorage); ok {
		return clearable.Clear()
	}

	// Fallback: Use the ListAll interface if available
	if listable, ok := a.storage.(ListableStorage); ok {
		credentialIDs, err := listable.ListAll()
		if err != nil {
			return err
		}
		for _, id := range credentialIDs {
			if err := a.storage.Delete(id); err != nil {
				// Continue deleting even if individual deletions fail
				// to ensure maximum cleanup
				continue
			}
		}
		return nil
	}

	// If neither interface is available, we cannot clear credentials
	// This should not happen with proper storage implementations
	return nil
}

// resetState resets the authenticator state to initial values while preserving AAGUID.
func (a *Authenticator) resetState(aaguid [16]byte) {
	// Create fresh state
	newState := NewAuthenticatorState()

	// Preserve AAGUID - this identifies the authenticator model and should not change
	newState.AAGUID = aaguid

	// Reset PIN state
	newState.PINHash = nil
	newState.PINSet = false
	newState.SetPINRetries(a.config.PINMaxRetries)
	newState.SetUVRetries(DefaultUVRetries)

	// Clear attestation key and certificate
	// The authenticator will generate a new one on next credential creation if needed
	newState.AttestationKey = nil
	newState.AttestationCert = nil

	a.state = newState
}

// clearPINState clears any cached PIN protocol state.
func (a *Authenticator) clearPINState() {
	a.pinState = authenticatorPINState{}
}

// clearAssertionState clears any cached assertion state used by GetNextAssertion.
func (a *Authenticator) clearAssertionState() {
	a.matchingCredentials = nil
	a.currentCredentialIndex = 0
	a.lastClientDataHash = nil
}

// clearCredMgmtState clears any credential management enumeration state.
func (a *Authenticator) clearCredMgmtState() {
	a.credMgmtState = nil
}

// ClearableStorage is an optional interface for storage backends that support
// clearing all credentials in a single operation.
type ClearableStorage interface {
	// Clear removes all stored credentials.
	// This is more efficient than iterating and deleting individually.
	Clear() error
}

// ListableStorage is an optional interface for storage backends that support
// listing all credential IDs.
type ListableStorage interface {
	// ListAll returns all credential IDs in storage.
	ListAll() ([][]byte, error)
}
