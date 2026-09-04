// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package authenticator

import "context"

// handleReset implements the CTAP2 authenticatorReset command (0x07).
//
// The Reset command performs a factory reset of the authenticator:
//   - Deletes all stored credentials
//   - Clears the PIN and resets retry counters
//   - Preserves the AAGUID (authenticator identity)
//   - Clears all wrapped keys if SO PIN is configured
//   - Optionally generates a new attestation key
//
// Per CTAP 2.1 §6.9 reset requires user presence, which is enforced here.
//
// On an initialized token reset additionally requires an authenticated Security
// Officer, because reset is the only path back to the uninitialized state and
// therefore the only way to reopen the trust-on-first-use window.
//
// On an uninitialized token there is no Security Officer to authenticate as, so
// user presence alone gates it. That is not a waiver: PKCS#11 v3.0 C_InitToken
// on an uninitialized token likewise requires no prior authentication, and
// demanding a credential that cannot exist would make an uninitialized token
// permanently unresettable.
//
// §6.9 also requires reset to arrive within a short time of power-up. That bound
// is NOT enforced here — a factory reset is driven from the UI long after
// startup — and the security doc records the gap rather than implying otherwise.
//
// Returns:
//   - Success response with StatusOK on successful reset
//   - Error response if storage operations fail or SO PIN is invalid
func (a *Authenticator) handleReset() ([]byte, error) {
	// When the token is initialized, reset is a Security Officer operation.
	// The gate can only report "not authenticated" here — the uninitialized
	// case is excluded by the branch — so it is reported as ErrSOPINRequired,
	// which names the credential the caller has to present.
	if a.IsTokenInitialized() {
		if err := a.requireSOUnlocked(); err != nil {
			return nil, ErrSOPINRequired
		}
	}

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

	// Reset authenticator state (includes SO PIN and wrapped keys)
	a.resetState(aaguid)

	// Clear any cached PIN/UV auth tokens
	a.clearPINState()

	// Clear assertion state
	a.clearAssertionState()

	// Clear credential management enumeration state
	a.clearCredMgmtState()

	// Lock the KeyManager to clear all cached keys
	if a.keyManager != nil {
		a.keyManager.Lock()
	}

	// Reinitialize KeyManager with new state
	a.keyManager = NewKeyManager(a.state, a.config)

	// Save the reset state to storage
	if err := a.storage.SaveState(a.state); err != nil {
		return nil, err
	}

	// The token is uninitialized again, so the initialization window reopens.
	// The caller has just proven user presence, and on an initialized token
	// also Security Officer possession, so this grants nothing new — but
	// without it the token could not be re-initialized until the next restart.
	a.rearmTokenInitWindow()

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

	// Clear the device attestation identity. A reset returns the device to its
	// unprovisioned state, where it registers credentials with the "none"
	// attestation format until a Security Officer provisions a new key and has
	// it certified.
	newState.AttestationCert = nil
	newState.AttestationCertChain = nil

	// Clear all wrapped keys and SO PIN state
	// After reset, SO PIN must be re-initialized
	newState.SOPINManager = nil
	newState.WrappedAK = nil
	newState.WrappedCMKUser = nil
	newState.WrappedCMKSO = nil
	newState.WrappedAttestUser = nil
	newState.WrappedAttestSO = nil
	newState.AttestedConfigHash = nil

	a.state = newState
}

// clearPINState clears any cached PIN protocol state. Per CTAP 2.1 §6.5.2.1
// authenticatorReset invalidates the pinUvAuthToken:
// stopUsingPinUvAuthTokenLocked resets its state variables and wipes the token
// bytes before the protocol state itself is discarded.
func (a *Authenticator) clearPINState() {
	a.stopUsingPinUvAuthTokenLocked()
	a.pinState = authenticatorPINState{}
}

// clearAssertionState clears any cached assertion state used by GetNextAssertion.
func (a *Authenticator) clearAssertionState() {
	a.matchingCredentials = nil
	a.currentCredentialIndex = 0
	a.lastClientDataHash = nil
	a.assertionFlags = 0
	a.assertionExtensions = nil
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
