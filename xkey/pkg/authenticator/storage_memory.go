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

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"sync"
)

// MemoryStorage implements StatefulCredentialStorage using in-memory maps.
// This implementation is useful for testing and ephemeral storage scenarios.
// All data is lost when the process exits or Close is called.
//
// Thread-safe using a read-write mutex.
type MemoryStorage struct {
	credentials map[string]*StoredCredential // keyed by hex(credentialID)
	state       *AuthenticatorState
	mu          sync.RWMutex
	closed      bool
}

// NewMemoryStorage creates a new in-memory credential storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		credentials: make(map[string]*StoredCredential),
	}
}

// Store persists a credential to memory.
// Returns ErrInvalidCredentialID if the credential ID is nil or empty.
// Returns ErrStorageClosed if the storage has been closed.
func (m *MemoryStorage) Store(credential *StoredCredential) error {
	if credential == nil || len(credential.CredentialID) == 0 {
		return ErrInvalidCredentialID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageClosed
	}

	key := hex.EncodeToString(credential.CredentialID)

	// Make a deep copy to prevent external mutation
	stored := m.copyCredential(credential)
	m.credentials[key] = stored

	return nil
}

// Load retrieves a credential by its ID.
// Returns ErrCredentialNotFound if the credential does not exist.
// Returns ErrInvalidCredentialID if the credential ID is nil or empty.
// Returns ErrStorageClosed if the storage has been closed.
func (m *MemoryStorage) Load(credentialID []byte) (*StoredCredential, error) {
	if len(credentialID) == 0 {
		return nil, ErrInvalidCredentialID
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStorageClosed
	}

	key := hex.EncodeToString(credentialID)
	cred, exists := m.credentials[key]
	if !exists {
		return nil, ErrCredentialNotFound
	}

	// Return a copy to prevent external mutation
	return m.copyCredential(cred), nil
}

// LoadByRPID retrieves all credentials for a relying party.
// Returns an empty slice if no credentials exist for the given RPID.
// Returns ErrInvalidRPIDEmpty if the rpID is empty.
// Returns ErrStorageClosed if the storage has been closed.
func (m *MemoryStorage) LoadByRPID(rpID string) ([]*StoredCredential, error) {
	if rpID == "" {
		return nil, ErrInvalidRPIDEmpty
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStorageClosed
	}

	var result []*StoredCredential
	for _, cred := range m.credentials {
		if cred.RPID == rpID {
			result = append(result, m.copyCredential(cred))
		}
	}

	return result, nil
}

// Delete removes a credential by its ID.
// Returns ErrCredentialNotFound if the credential does not exist.
// Returns ErrInvalidCredentialID if the credential ID is nil or empty.
// Returns ErrStorageClosed if the storage has been closed.
func (m *MemoryStorage) Delete(credentialID []byte) error {
	if len(credentialID) == 0 {
		return ErrInvalidCredentialID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageClosed
	}

	key := hex.EncodeToString(credentialID)
	if _, exists := m.credentials[key]; !exists {
		return ErrCredentialNotFound
	}

	delete(m.credentials, key)
	return nil
}

// Count returns the total number of stored credentials.
// Returns ErrStorageClosed if the storage has been closed.
func (m *MemoryStorage) Count() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return 0, ErrStorageClosed
	}

	return len(m.credentials), nil
}

// CountDiscoverable returns the number of discoverable (resident) credentials.
// Returns ErrStorageClosed if the storage has been closed.
func (m *MemoryStorage) CountDiscoverable() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return 0, ErrStorageClosed
	}

	count := 0
	for _, cred := range m.credentials {
		if cred.Discoverable {
			count++
		}
	}

	return count, nil
}

// EnumerateDiscoverable returns all discoverable credentials.
// This implements the CredentialEnumerator interface for credential management.
// Returns ErrStorageClosed if the storage has been closed.
func (m *MemoryStorage) EnumerateDiscoverable() ([]*StoredCredential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStorageClosed
	}

	var result []*StoredCredential
	for _, cred := range m.credentials {
		if cred.Discoverable {
			result = append(result, m.copyCredential(cred))
		}
	}

	return result, nil
}

// SaveState persists the authenticator state to memory.
// Returns ErrStorageClosed if the storage has been closed.
func (m *MemoryStorage) SaveState(state *AuthenticatorState) error {
	if state == nil {
		return ErrInvalidParameter
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageClosed
	}

	// Create a copy of the state
	m.state = m.copyState(state)

	return nil
}

// LoadState retrieves the persisted authenticator state.
// Returns ErrStateNotFound if no state has been saved.
// Returns ErrStorageClosed if the storage has been closed.
func (m *MemoryStorage) LoadState() (*AuthenticatorState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStorageClosed
	}

	if m.state == nil {
		return nil, ErrStateNotFound
	}

	return m.copyState(m.state), nil
}

// Close releases resources and marks the storage as closed.
// After Close is called, all other methods return ErrStorageClosed.
// Close is idempotent and may be called multiple times safely.
func (m *MemoryStorage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	m.credentials = nil
	m.state = nil

	return nil
}

// Clear removes all stored credentials.
// This implements the ClearableStorage interface for efficient reset operations.
// Returns ErrStorageClosed if the storage has been closed.
func (m *MemoryStorage) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageClosed
	}

	// Replace the map with a new empty one
	m.credentials = make(map[string]*StoredCredential)

	return nil
}

// ListAll returns all credential IDs in storage.
// This implements the ListableStorage interface.
// Returns ErrStorageClosed if the storage has been closed.
func (m *MemoryStorage) ListAll() ([][]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStorageClosed
	}

	result := make([][]byte, 0, len(m.credentials))
	for _, cred := range m.credentials {
		// Make a copy of the credential ID
		id := make([]byte, len(cred.CredentialID))
		copy(id, cred.CredentialID)
		result = append(result, id)
	}

	return result, nil
}

// copyCredential creates a deep copy of a StoredCredential.
// This prevents external mutation of stored data.
func (m *MemoryStorage) copyCredential(cred *StoredCredential) *StoredCredential {
	if cred == nil {
		return nil
	}

	copied := &StoredCredential{
		RPID:                cred.RPID,
		RPName:              cred.RPName,
		UserName:            cred.UserName,
		UserDisplayName:     cred.UserDisplayName,
		Algorithm:           cred.Algorithm,
		SignCount:           cred.SignCount,
		Discoverable:        cred.Discoverable,
		CredProtect:         cred.CredProtect,
		CreatedAt:           cred.CreatedAt,
		RPUVPolicy:          cred.RPUVPolicy,
		RPUPPolicy:          cred.RPUPPolicy,
		RPResidentKeyPolicy: cred.RPResidentKeyPolicy,
		RPAttestationPref:   cred.RPAttestationPref,
	}

	// Copy byte slices
	if len(cred.CredentialID) > 0 {
		copied.CredentialID = make([]byte, len(cred.CredentialID))
		copy(copied.CredentialID, cred.CredentialID)
	}

	if len(cred.UserID) > 0 {
		copied.UserID = make([]byte, len(cred.UserID))
		copy(copied.UserID, cred.UserID)
	}

	if len(cred.PrivateKey) > 0 {
		copied.PrivateKey = make([]byte, len(cred.PrivateKey))
		copy(copied.PrivateKey, cred.PrivateKey)
	}

	if len(cred.PublicKeyCOSE) > 0 {
		copied.PublicKeyCOSE = make([]byte, len(cred.PublicKeyCOSE))
		copy(copied.PublicKeyCOSE, cred.PublicKeyCOSE)
	}

	if len(cred.HMACSecretKey) > 0 {
		copied.HMACSecretKey = make([]byte, len(cred.HMACSecretKey))
		copy(copied.HMACSecretKey, cred.HMACSecretKey)
	}

	return copied
}

// copyState creates a deep copy of an AuthenticatorState.
// This prevents external mutation of stored state.
func (m *MemoryStorage) copyState(state *AuthenticatorState) *AuthenticatorState {
	if state == nil {
		return nil
	}

	copied := NewAuthenticatorState()
	copied.AAGUID = state.AAGUID
	copied.PINSet = state.PINSet
	copied.SetPINRetries(state.PINRetries())
	copied.SetUVRetries(state.UVRetries())

	// Copy PIN hash
	if len(state.PINHash) > 0 {
		copied.PINHash = make([]byte, len(state.PINHash))
		copy(copied.PINHash, state.PINHash)
	}

	// Copy attestation key (ECDSA private keys are immutable, but we copy for safety)
	if state.AttestationKey != nil {
		// Deep copy the ECDSA key by serializing and deserializing
		keyBytes, err := x509.MarshalECPrivateKey(state.AttestationKey)
		if err == nil {
			key, err := x509.ParseECPrivateKey(keyBytes)
			if err == nil {
				copied.AttestationKey = key
			}
		}
		// If copy fails, reference the original (better than nil)
		if copied.AttestationKey == nil {
			copied.AttestationKey = state.AttestationKey
		}
	}

	// Copy attestation certificate
	if len(state.AttestationCert) > 0 {
		copied.AttestationCert = make([]byte, len(state.AttestationCert))
		copy(copied.AttestationCert, state.AttestationCert)
	}

	// Copy policy HMAC integrity fields
	copied.PolicyHMACTag = copyBytes(state.PolicyHMACTag)
	if state.SignedPolicyFields != nil {
		pf := *state.SignedPolicyFields
		copied.SignedPolicyFields = &pf
	}

	return copied
}

// Ensure MemoryStorage implements StatefulCredentialStorage.
var _ StatefulCredentialStorage = (*MemoryStorage)(nil)

// Ensure MemoryStorage implements CredentialStorage.
var _ CredentialStorage = (*MemoryStorage)(nil)

// Ensure MemoryStorage implements ClearableStorage.
var _ ClearableStorage = (*MemoryStorage)(nil)

// Ensure MemoryStorage implements ListableStorage.
var _ ListableStorage = (*MemoryStorage)(nil)

// Ensure MemoryStorage implements CredentialEnumerator.
var _ CredentialEnumerator = (*MemoryStorage)(nil)

// stateToSerializable converts an AuthenticatorState to a SerializableState.
func stateToSerializable(state *AuthenticatorState) (*SerializableState, error) {
	if state == nil {
		return nil, ErrInvalidParameter
	}

	s := &SerializableState{
		AAGUID:     state.AAGUID,
		PINSet:     state.PINSet,
		PINRetries: state.PINRetries(),
		UVRetries:  state.UVRetries(),
	}

	// Copy PIN hash
	if len(state.PINHash) > 0 {
		s.PINHash = make([]byte, len(state.PINHash))
		copy(s.PINHash, state.PINHash)
	}

	// Serialize attestation key to PKCS#8 (only if not using wrapped keys)
	if state.AttestationKey != nil && len(state.WrappedAttestSO) == 0 {
		keyBytes, err := x509.MarshalPKCS8PrivateKey(state.AttestationKey)
		if err != nil {
			return nil, ErrSerializationFailed
		}
		s.AttestationKeyPKCS8 = keyBytes
	}

	// Copy attestation certificate
	if len(state.AttestationCert) > 0 {
		s.AttestationCert = make([]byte, len(state.AttestationCert))
		copy(s.AttestationCert, state.AttestationCert)
	}

	// Serialize SO PIN manager state
	if state.SOPINManager != nil {
		s.SOPINSet = state.SOPINManager.IsSet
		s.SOPINRetries = state.SOPINManager.Retries()
		s.SOPINIterations = state.SOPINManager.Iterations
		s.SOPINMemory = state.SOPINManager.Memory
		s.SOPINParallelism = state.SOPINManager.Parallelism
		if len(state.SOPINManager.Salt) > 0 {
			s.SOPINSalt = make([]byte, len(state.SOPINManager.Salt))
			copy(s.SOPINSalt, state.SOPINManager.Salt)
		}
	}

	// Copy wrapped keys
	s.WrappedAK = copyBytes(state.WrappedAK)
	s.WrappedCMKUser = copyBytes(state.WrappedCMKUser)
	s.WrappedCMKSO = copyBytes(state.WrappedCMKSO)
	s.WrappedAttestUser = copyBytes(state.WrappedAttestUser)
	s.WrappedAttestSO = copyBytes(state.WrappedAttestSO)
	s.AttestedConfigHash = copyBytes(state.AttestedConfigHash)

	// Copy PIN sync state
	s.PINSyncPending = state.PINSyncPending

	// Copy policy HMAC integrity fields
	s.PolicyHMACTag = copyBytes(state.PolicyHMACTag)
	if state.SignedPolicyFields != nil {
		pf := *state.SignedPolicyFields
		s.SignedPolicyFields = &pf
	}

	return s, nil
}

// copyBytes creates a copy of a byte slice, returning nil for nil/empty input.
func copyBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

// serializableToState converts a SerializableState back to an AuthenticatorState.
func serializableToState(s *SerializableState) (*AuthenticatorState, error) {
	if s == nil {
		return nil, ErrInvalidParameter
	}

	state := NewAuthenticatorState()
	state.AAGUID = s.AAGUID
	state.PINSet = s.PINSet
	state.SetPINRetries(s.PINRetries)
	state.SetUVRetries(s.UVRetries)

	// Copy PIN hash
	if len(s.PINHash) > 0 {
		state.PINHash = make([]byte, len(s.PINHash))
		copy(state.PINHash, s.PINHash)
	}

	// Deserialize attestation key from PKCS#8 (only if not using wrapped keys)
	if len(s.AttestationKeyPKCS8) > 0 && len(s.WrappedAttestSO) == 0 {
		key, err := x509.ParsePKCS8PrivateKey(s.AttestationKeyPKCS8)
		if err != nil {
			return nil, ErrDeserializationFailed
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrDeserializationFailed
		}
		state.AttestationKey = ecKey
	}

	// Copy attestation certificate
	if len(s.AttestationCert) > 0 {
		state.AttestationCert = make([]byte, len(s.AttestationCert))
		copy(state.AttestationCert, s.AttestationCert)
	}

	// Deserialize SO PIN manager state
	if s.SOPINSet || len(s.SOPINSalt) > 0 {
		state.SOPINManager = NewSOPINManager()
		state.SOPINManager.IsSet = s.SOPINSet
		state.SOPINManager.SetRetries(s.SOPINRetries)
		if s.SOPINIterations > 0 {
			state.SOPINManager.Iterations = s.SOPINIterations
		}
		if s.SOPINMemory > 0 {
			state.SOPINManager.Memory = s.SOPINMemory
		}
		if s.SOPINParallelism > 0 {
			state.SOPINManager.Parallelism = s.SOPINParallelism
		}
		state.SOPINManager.Salt = copyBytes(s.SOPINSalt)
	}

	// Copy wrapped keys
	state.WrappedAK = copyBytes(s.WrappedAK)
	state.WrappedCMKUser = copyBytes(s.WrappedCMKUser)
	state.WrappedCMKSO = copyBytes(s.WrappedCMKSO)
	state.WrappedAttestUser = copyBytes(s.WrappedAttestUser)
	state.WrappedAttestSO = copyBytes(s.WrappedAttestSO)
	state.AttestedConfigHash = copyBytes(s.AttestedConfigHash)

	// Copy PIN sync state
	state.PINSyncPending = s.PINSyncPending

	// Copy policy HMAC integrity fields
	state.PolicyHMACTag = copyBytes(s.PolicyHMACTag)
	if s.SignedPolicyFields != nil {
		pf := *s.SignedPolicyFields
		state.SignedPolicyFields = &pf
	}

	return state, nil
}
