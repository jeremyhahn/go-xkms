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

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestHandleReset_ClearsAllCredentials(t *testing.T) {
	auth, storage := createTestAuthenticatorWithStorageForReset(t)
	defer func() { _ = auth.Close() }()

	// Create multiple credentials for different relying parties
	cred1 := createTestStoredCredentialForReset(t, []byte{1, 2, 3, 4}, "example.com", true)
	cred2 := createTestStoredCredentialForReset(t, []byte{5, 6, 7, 8}, "example.com", false)
	cred3 := createTestStoredCredentialForReset(t, []byte{9, 10, 11, 12}, "another.com", true)

	if err := storage.Store(cred1); err != nil {
		t.Fatalf("failed to store cred1: %v", err)
	}
	if err := storage.Store(cred2); err != nil {
		t.Fatalf("failed to store cred2: %v", err)
	}
	if err := storage.Store(cred3); err != nil {
		t.Fatalf("failed to store cred3: %v", err)
	}

	// Verify credentials were stored
	count, err := storage.Count()
	if err != nil {
		t.Fatalf("failed to count credentials: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 credentials before reset, got %d", count)
	}

	// Execute reset command
	response, err := auth.ProcessCBOR(CmdReset, nil)
	if err != nil {
		t.Fatalf("Reset command failed: %v", err)
	}

	// Verify success response
	if len(response) != 1 || response[0] != StatusOK {
		t.Errorf("expected StatusOK response, got %v", response)
	}

	// Verify all credentials were deleted
	count, err = storage.Count()
	if err != nil {
		t.Fatalf("failed to count credentials after reset: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 credentials after reset, got %d", count)
	}
}

func TestHandleReset_ClearsPINState(t *testing.T) {
	auth, _ := createTestAuthenticatorWithStorageForReset(t)
	defer func() { _ = auth.Close() }()

	// Set up PIN state
	pinHash := sha256.Sum256([]byte("testpin"))
	auth.state.PINHash = pinHash[:16]
	auth.state.PINSet = true
	auth.state.SetPINRetries(3) // Simulate some failed attempts

	// Verify PIN is set before reset
	if !auth.IsPINSet() {
		t.Fatal("expected PIN to be set before reset")
	}
	if auth.PINRetries() != 3 {
		t.Errorf("expected PINRetries=3 before reset, got %d", auth.PINRetries())
	}

	// Execute reset command
	response, err := auth.ProcessCBOR(CmdReset, nil)
	if err != nil {
		t.Fatalf("Reset command failed: %v", err)
	}

	// Verify success response
	if len(response) != 1 || response[0] != StatusOK {
		t.Errorf("expected StatusOK response, got %v", response)
	}

	// Verify PIN state was cleared
	if auth.IsPINSet() {
		t.Error("expected PIN to be cleared after reset")
	}
	if auth.state.PINHash != nil {
		t.Error("expected PINHash to be nil after reset")
	}
	if auth.PINRetries() != DefaultPINMaxRetries {
		t.Errorf("expected PINRetries=%d after reset, got %d", DefaultPINMaxRetries, auth.PINRetries())
	}
}

func TestHandleReset_PreservesAAGUID(t *testing.T) {
	auth, _ := createTestAuthenticatorWithStorageForReset(t)
	defer func() { _ = auth.Close() }()

	// Get the original AAGUID
	originalAAGUID := auth.AAGUID()

	// Execute reset command
	response, err := auth.ProcessCBOR(CmdReset, nil)
	if err != nil {
		t.Fatalf("Reset command failed: %v", err)
	}

	// Verify success response
	if len(response) != 1 || response[0] != StatusOK {
		t.Errorf("expected StatusOK response, got %v", response)
	}

	// Verify AAGUID was preserved
	newAAGUID := auth.AAGUID()
	if originalAAGUID != newAAGUID {
		t.Errorf("AAGUID changed after reset: was %v, now %v", originalAAGUID, newAAGUID)
	}
}

func TestHandleReset_OperationsWorkAfterReset(t *testing.T) {
	auth, storage := createTestAuthenticatorWithStorageForReset(t)
	defer func() { _ = auth.Close() }()

	// Create some credentials before reset
	cred1 := createTestStoredCredentialForReset(t, []byte{1, 2, 3, 4}, "example.com", true)
	if err := storage.Store(cred1); err != nil {
		t.Fatalf("failed to store credential: %v", err)
	}

	// Execute reset command
	response, err := auth.ProcessCBOR(CmdReset, nil)
	if err != nil {
		t.Fatalf("Reset command failed: %v", err)
	}
	if response[0] != StatusOK {
		t.Fatalf("expected StatusOK, got %d", response[0])
	}

	// Verify we can create new credentials after reset
	cred2 := createTestStoredCredentialForReset(t, []byte{5, 6, 7, 8}, "newsite.com", true)
	if err := storage.Store(cred2); err != nil {
		t.Fatalf("failed to store credential after reset: %v", err)
	}

	// Verify the new credential was stored
	loaded, err := storage.Load(cred2.CredentialID)
	if err != nil {
		t.Fatalf("failed to load credential after reset: %v", err)
	}
	if !bytes.Equal(loaded.CredentialID, cred2.CredentialID) {
		t.Error("loaded credential ID does not match")
	}

	// Verify count is correct (only new credential)
	count, err := storage.Count()
	if err != nil {
		t.Fatalf("failed to count credentials: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 credential after reset and new store, got %d", count)
	}
}

func TestHandleReset_MultipleResets(t *testing.T) {
	auth, storage := createTestAuthenticatorWithStorageForReset(t)
	defer func() { _ = auth.Close() }()

	originalAAGUID := auth.AAGUID()

	// Perform multiple resets
	for i := 0; i < 3; i++ {
		// Add some credentials
		cred := createTestStoredCredentialForReset(t, []byte{byte(i), 1, 2, 3}, "example.com", true)
		if err := storage.Store(cred); err != nil {
			t.Fatalf("iteration %d: failed to store credential: %v", i, err)
		}

		// Set PIN state
		auth.state.PINSet = true
		auth.state.PINHash = []byte{1, 2, 3, 4, 5, 6, 7, 8}

		// Execute reset
		response, err := auth.ProcessCBOR(CmdReset, nil)
		if err != nil {
			t.Fatalf("iteration %d: Reset command failed: %v", i, err)
		}
		if response[0] != StatusOK {
			t.Fatalf("iteration %d: expected StatusOK, got %d", i, response[0])
		}

		// Verify state was reset
		count, err := storage.Count()
		if err != nil {
			t.Fatalf("iteration %d: failed to count credentials: %v", i, err)
		}
		if count != 0 {
			t.Errorf("iteration %d: expected 0 credentials after reset, got %d", i, count)
		}
		if auth.IsPINSet() {
			t.Errorf("iteration %d: expected PIN to be cleared", i)
		}

		// Verify AAGUID is preserved
		if auth.AAGUID() != originalAAGUID {
			t.Errorf("iteration %d: AAGUID changed", i)
		}
	}
}

func TestHandleReset_ClearsAttestationKey(t *testing.T) {
	auth, _ := createTestAuthenticatorWithStorageForReset(t)
	defer func() { _ = auth.Close() }()

	// Generate and set an attestation key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate attestation key: %v", err)
	}
	auth.state.AttestationKey = privateKey
	auth.state.AttestationCert = []byte{0x30, 0x82, 0x01, 0x00} // Dummy DER cert

	// Execute reset command
	response, err := auth.ProcessCBOR(CmdReset, nil)
	if err != nil {
		t.Fatalf("Reset command failed: %v", err)
	}
	if response[0] != StatusOK {
		t.Fatalf("expected StatusOK, got %d", response[0])
	}

	// Verify attestation key was cleared
	if auth.state.AttestationKey != nil {
		t.Error("expected AttestationKey to be nil after reset")
	}
	if auth.state.AttestationCert != nil {
		t.Error("expected AttestationCert to be nil after reset")
	}
}

func TestHandleReset_ClearsAssertionState(t *testing.T) {
	auth, storage := createTestAuthenticatorWithStorageForReset(t)
	defer func() { _ = auth.Close() }()

	// Create some credentials and simulate assertion state
	cred := createTestStoredCredentialForReset(t, []byte{1, 2, 3, 4}, "example.com", true)
	if err := storage.Store(cred); err != nil {
		t.Fatalf("failed to store credential: %v", err)
	}

	// Simulate having assertion state from a previous GetAssertion call
	auth.matchingCredentials = []*StoredCredential{cred}
	auth.currentCredentialIndex = 0
	auth.lastClientDataHash = []byte{1, 2, 3, 4, 5}

	// Execute reset command
	response, err := auth.ProcessCBOR(CmdReset, nil)
	if err != nil {
		t.Fatalf("Reset command failed: %v", err)
	}
	if response[0] != StatusOK {
		t.Fatalf("expected StatusOK, got %d", response[0])
	}

	// Verify assertion state was cleared
	if auth.matchingCredentials != nil {
		t.Error("expected matchingCredentials to be nil after reset")
	}
	if auth.currentCredentialIndex != 0 {
		t.Error("expected currentCredentialIndex to be 0 after reset")
	}
	if auth.lastClientDataHash != nil {
		t.Error("expected lastClientDataHash to be nil after reset")
	}
}

func TestHandleReset_ResetOnEmptyAuthenticator(t *testing.T) {
	auth, storage := createTestAuthenticatorWithStorageForReset(t)
	defer func() { _ = auth.Close() }()

	// Verify authenticator starts empty
	count, err := storage.Count()
	if err != nil {
		t.Fatalf("failed to count credentials: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 credentials initially, got %d", count)
	}

	// Execute reset on empty authenticator
	response, err := auth.ProcessCBOR(CmdReset, nil)
	if err != nil {
		t.Fatalf("Reset command failed: %v", err)
	}

	// Verify success response (reset on empty should succeed)
	if len(response) != 1 || response[0] != StatusOK {
		t.Errorf("expected StatusOK response, got %v", response)
	}

	// Verify state is still valid
	if auth.AAGUID() == [16]byte{} {
		t.Error("AAGUID should not be zero after reset")
	}
}

func TestHandleReset_ResetUVRetries(t *testing.T) {
	auth, _ := createTestAuthenticatorWithStorageForReset(t)
	defer func() { _ = auth.Close() }()

	// Simulate reduced UV retries
	auth.state.SetUVRetries(1)

	// Execute reset command
	response, err := auth.ProcessCBOR(CmdReset, nil)
	if err != nil {
		t.Fatalf("Reset command failed: %v", err)
	}
	if response[0] != StatusOK {
		t.Fatalf("expected StatusOK, got %d", response[0])
	}

	// Verify UV retries were reset to default
	if auth.state.UVRetries() != DefaultUVRetries {
		t.Errorf("expected UVRetries=%d after reset, got %d", DefaultUVRetries, auth.state.UVRetries())
	}
}

func TestHandleReset_ClearsCredMgmtState(t *testing.T) {
	auth, storage := createTestAuthenticatorWithStorageForReset(t)
	defer func() { _ = auth.Close() }()

	// Store some credentials
	cred1 := createTestStoredCredentialForReset(t, []byte{1, 2, 3, 4}, "example.com", true)
	cred2 := createTestStoredCredentialForReset(t, []byte{5, 6, 7, 8}, "another.com", true)
	if err := storage.Store(cred1); err != nil {
		t.Fatalf("failed to store cred1: %v", err)
	}
	if err := storage.Store(cred2); err != nil {
		t.Fatalf("failed to store cred2: %v", err)
	}

	// Simulate having credential management enumeration state
	auth.credMgmtState = &credMgmtEnumerationState{
		rpList:         []rpEntry{{rpIDHash: []byte{1, 2, 3}, rpID: "example.com"}},
		currentRPIndex: 0,
		credList:       []*StoredCredential{cred1},
	}

	// Execute reset command
	response, err := auth.ProcessCBOR(CmdReset, nil)
	if err != nil {
		t.Fatalf("Reset command failed: %v", err)
	}
	if response[0] != StatusOK {
		t.Fatalf("expected StatusOK, got %d", response[0])
	}

	// Verify credMgmtState was cleared
	if auth.credMgmtState != nil {
		t.Error("expected credMgmtState to be nil after reset")
	}
}

func TestClearAllCredentials_WithListableStorageFallback(t *testing.T) {
	// Create a storage wrapper that doesn't implement ClearableStorage
	baseStorage := NewMemoryStorage()
	storage := &nonClearableStorage{storage: baseStorage}

	config := &Config{
		AAGUID:                     DefaultAAGUID,
		SupportedAlgorithms:        []int{COSEAlgES256},
		MaxCredentials:             100,
		MaxResidentCredentials:     25,
		PINMinLength:               4,
		PINMaxRetries:              DefaultPINMaxRetries,
		EnablePIN:                  true,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		Storage:                    storage,
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer func() { _ = auth.Close() }()

	// Store some credentials
	err = baseStorage.Store(&StoredCredential{
		CredentialID: []byte{1, 2, 3, 4},
		RPID:         "example.com",
	})
	if err != nil {
		t.Fatalf("failed to store credential: %v", err)
	}
	err = baseStorage.Store(&StoredCredential{
		CredentialID: []byte{5, 6, 7, 8},
		RPID:         "test.com",
	})
	if err != nil {
		t.Fatalf("failed to store credential: %v", err)
	}

	// Verify credentials exist
	count, err := baseStorage.Count()
	if err != nil {
		t.Fatalf("failed to count: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 credentials, got %d", count)
	}

	// Clear credentials using the ListAll fallback path
	err = auth.clearAllCredentials()
	if err != nil {
		t.Fatalf("clearAllCredentials failed: %v", err)
	}

	// Verify credentials are cleared
	count, err = baseStorage.Count()
	if err != nil {
		t.Fatalf("failed to count after clear: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 credentials after clear, got %d", count)
	}
}

func TestClientPINToUint8_AllTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected uint8
		hasError bool
	}{
		{"int", int(42), 42, false},
		{"int8", int8(42), 42, false},
		{"int16", int16(42), 42, false},
		{"int32", int32(42), 42, false},
		{"int64", int64(42), 42, false},
		{"uint", uint(42), 42, false},
		{"uint8", uint8(42), 42, false},
		{"uint16", uint16(42), 42, false},
		{"uint32", uint32(42), 42, false},
		{"uint64", uint64(42), 42, false},
		{"string", "42", 0, true},
		{"float64", float64(42.0), 0, true},
		{"nil", nil, 0, true},
		{"bool", true, 0, true},
		{"slice", []byte{42}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := clientPINToUint8(tt.input)
			if tt.hasError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected %d, got %d", tt.expected, result)
				}
			}
		})
	}
}

// Additional tests for clearAllCredentials coverage

func TestClearAllCredentials_WithClearableStorage(t *testing.T) {
	auth, storage := createTestAuthenticatorWithStorageForReset(t)
	defer func() { _ = auth.Close() }()

	// Store credentials
	cred1 := createTestStoredCredentialForReset(t, []byte{1, 2, 3, 4}, "example.com", true)
	cred2 := createTestStoredCredentialForReset(t, []byte{5, 6, 7, 8}, "test.com", false)

	if err := storage.Store(cred1); err != nil {
		t.Fatalf("failed to store cred1: %v", err)
	}
	if err := storage.Store(cred2); err != nil {
		t.Fatalf("failed to store cred2: %v", err)
	}

	count, _ := storage.Count()
	if count != 2 {
		t.Fatalf("expected 2 credentials, got %d", count)
	}

	// Clear credentials - MemoryStorage implements ClearableStorage
	err := auth.clearAllCredentials()
	if err != nil {
		t.Fatalf("clearAllCredentials failed: %v", err)
	}

	count, _ = storage.Count()
	if count != 0 {
		t.Errorf("expected 0 credentials after clear, got %d", count)
	}
}

func TestClearAllCredentials_ListAllError(t *testing.T) {
	// Create a storage that returns error from ListAll
	storage := &listAllErrorStorage{
		listAllErr: errors.New("list all error"),
	}

	config := &Config{
		AAGUID:                 DefaultAAGUID,
		SupportedAlgorithms:    []int{COSEAlgES256},
		MaxCredentials:         100,
		MaxResidentCredentials: 25,
		PINMinLength:           4,
		PINMaxRetries:          DefaultPINMaxRetries,
		Storage:                storage,
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer func() { _ = auth.Close() }()

	// clearAllCredentials should return error from ListAll
	err = auth.clearAllCredentials()
	if err == nil {
		t.Error("expected error from clearAllCredentials")
	}
}

func TestClearAllCredentials_NoListableOrClearableStorage(t *testing.T) {
	// Create a storage that doesn't implement ClearableStorage or ListableStorage
	storage := &minimalStorage{}

	config := &Config{
		AAGUID:                 DefaultAAGUID,
		SupportedAlgorithms:    []int{COSEAlgES256},
		MaxCredentials:         100,
		MaxResidentCredentials: 25,
		PINMinLength:           4,
		PINMaxRetries:          DefaultPINMaxRetries,
		Storage:                storage,
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer func() { _ = auth.Close() }()

	// clearAllCredentials should succeed (returns nil for unsupported storage)
	err = auth.clearAllCredentials()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClearAllCredentials_DeleteErrors(t *testing.T) {
	// Create storage that implements ListableStorage but Delete fails
	storage := &deleteErrorStorage{
		credentials: map[string]*StoredCredential{
			"0102030405": {CredentialID: []byte{1, 2, 3, 4, 5}},
			"0607080910": {CredentialID: []byte{6, 7, 8, 9, 10}},
		},
		deleteErr: errors.New("delete error"),
	}

	config := &Config{
		AAGUID:                 DefaultAAGUID,
		SupportedAlgorithms:    []int{COSEAlgES256},
		MaxCredentials:         100,
		MaxResidentCredentials: 25,
		PINMinLength:           4,
		PINMaxRetries:          DefaultPINMaxRetries,
		Storage:                storage,
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer func() { _ = auth.Close() }()

	// clearAllCredentials should continue even when individual deletes fail
	err = auth.clearAllCredentials()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHandleReset_StorageSaveStateError(t *testing.T) {
	// Create storage that fails on SaveState
	baseStorage := NewMemoryStorage()
	storage := &saveStateErrorStorage{
		storage:      baseStorage,
		saveStateErr: errors.New("save state error"),
	}

	config := &Config{
		AAGUID:                 DefaultAAGUID,
		SupportedAlgorithms:    []int{COSEAlgES256},
		MaxCredentials:         100,
		MaxResidentCredentials: 25,
		PINMinLength:           4,
		PINMaxRetries:          DefaultPINMaxRetries,
		Storage:                storage,
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer func() { _ = auth.Close() }()

	// Reset should fail because SaveState fails
	_, err = auth.ProcessCBOR(CmdReset, nil)
	if err == nil {
		t.Error("expected error from reset when SaveState fails")
	}
}

// Test helper storage types

// nonClearableStorage wraps MemoryStorage but doesn't implement ClearableStorage
// It does implement ListableStorage to test the fallback path
type nonClearableStorage struct {
	storage *MemoryStorage
}

func (s *nonClearableStorage) Store(credential *StoredCredential) error {
	return s.storage.Store(credential)
}

func (s *nonClearableStorage) Load(credentialID []byte) (*StoredCredential, error) {
	return s.storage.Load(credentialID)
}

func (s *nonClearableStorage) LoadByRPID(rpID string) ([]*StoredCredential, error) {
	return s.storage.LoadByRPID(rpID)
}

func (s *nonClearableStorage) Delete(credentialID []byte) error {
	return s.storage.Delete(credentialID)
}

func (s *nonClearableStorage) Count() (int, error) {
	return s.storage.Count()
}

func (s *nonClearableStorage) CountDiscoverable() (int, error) {
	return s.storage.CountDiscoverable()
}

// ListAll implements ListableStorage interface
func (s *nonClearableStorage) ListAll() ([][]byte, error) {
	return s.storage.ListAll()
}

// EnumerateDiscoverable implements EnumerableStorage interface
func (s *nonClearableStorage) EnumerateDiscoverable() ([]*StoredCredential, error) {
	return s.storage.EnumerateDiscoverable()
}

// SaveState implements StatefulCredentialStorage interface
func (s *nonClearableStorage) SaveState(state *AuthenticatorState) error {
	return s.storage.SaveState(state)
}

// LoadState implements StatefulCredentialStorage interface
func (s *nonClearableStorage) LoadState() (*AuthenticatorState, error) {
	return s.storage.LoadState()
}

// Close implements io.Closer interface
func (s *nonClearableStorage) Close() error {
	return s.storage.Close()
}

// listAllErrorStorage returns error from ListAll
type listAllErrorStorage struct {
	listAllErr error
}

func (s *listAllErrorStorage) Store(credential *StoredCredential) error {
	return nil
}

func (s *listAllErrorStorage) Load(credentialID []byte) (*StoredCredential, error) {
	return nil, ErrCredentialNotFound
}

func (s *listAllErrorStorage) LoadByRPID(rpID string) ([]*StoredCredential, error) {
	return nil, nil
}

func (s *listAllErrorStorage) Delete(credentialID []byte) error {
	return nil
}

func (s *listAllErrorStorage) Count() (int, error) {
	return 0, nil
}

func (s *listAllErrorStorage) CountDiscoverable() (int, error) {
	return 0, nil
}

func (s *listAllErrorStorage) ListAll() ([][]byte, error) {
	return nil, s.listAllErr
}

func (s *listAllErrorStorage) SaveState(state *AuthenticatorState) error {
	return nil
}

func (s *listAllErrorStorage) LoadState() (*AuthenticatorState, error) {
	return nil, ErrStateNotFound
}

func (s *listAllErrorStorage) Close() error {
	return nil
}

// minimalStorage implements only basic CredentialStorage methods
type minimalStorage struct{}

func (s *minimalStorage) Store(credential *StoredCredential) error {
	return nil
}

func (s *minimalStorage) Load(credentialID []byte) (*StoredCredential, error) {
	return nil, ErrCredentialNotFound
}

func (s *minimalStorage) LoadByRPID(rpID string) ([]*StoredCredential, error) {
	return nil, nil
}

func (s *minimalStorage) Delete(credentialID []byte) error {
	return nil
}

func (s *minimalStorage) Count() (int, error) {
	return 0, nil
}

func (s *minimalStorage) CountDiscoverable() (int, error) {
	return 0, nil
}

func (s *minimalStorage) SaveState(state *AuthenticatorState) error {
	return nil
}

func (s *minimalStorage) LoadState() (*AuthenticatorState, error) {
	return nil, ErrStateNotFound
}

func (s *minimalStorage) Close() error {
	return nil
}

// deleteErrorStorage implements ListableStorage but Delete fails
type deleteErrorStorage struct {
	credentials map[string]*StoredCredential
	deleteErr   error
}

func (s *deleteErrorStorage) Store(credential *StoredCredential) error {
	return nil
}

func (s *deleteErrorStorage) Load(credentialID []byte) (*StoredCredential, error) {
	return nil, ErrCredentialNotFound
}

func (s *deleteErrorStorage) LoadByRPID(rpID string) ([]*StoredCredential, error) {
	return nil, nil
}

func (s *deleteErrorStorage) Delete(credentialID []byte) error {
	return s.deleteErr
}

func (s *deleteErrorStorage) Count() (int, error) {
	return len(s.credentials), nil
}

func (s *deleteErrorStorage) CountDiscoverable() (int, error) {
	return 0, nil
}

func (s *deleteErrorStorage) ListAll() ([][]byte, error) {
	var result [][]byte
	for _, cred := range s.credentials {
		result = append(result, cred.CredentialID)
	}
	return result, nil
}

func (s *deleteErrorStorage) SaveState(state *AuthenticatorState) error {
	return nil
}

func (s *deleteErrorStorage) LoadState() (*AuthenticatorState, error) {
	return nil, ErrStateNotFound
}

func (s *deleteErrorStorage) Close() error {
	return nil
}

// saveStateErrorStorage wraps MemoryStorage but fails on SaveState
type saveStateErrorStorage struct {
	storage      *MemoryStorage
	saveStateErr error
}

func (s *saveStateErrorStorage) Store(credential *StoredCredential) error {
	return s.storage.Store(credential)
}

func (s *saveStateErrorStorage) Load(credentialID []byte) (*StoredCredential, error) {
	return s.storage.Load(credentialID)
}

func (s *saveStateErrorStorage) LoadByRPID(rpID string) ([]*StoredCredential, error) {
	return s.storage.LoadByRPID(rpID)
}

func (s *saveStateErrorStorage) Delete(credentialID []byte) error {
	return s.storage.Delete(credentialID)
}

func (s *saveStateErrorStorage) Count() (int, error) {
	return s.storage.Count()
}

func (s *saveStateErrorStorage) CountDiscoverable() (int, error) {
	return s.storage.CountDiscoverable()
}

func (s *saveStateErrorStorage) SaveState(state *AuthenticatorState) error {
	return s.saveStateErr
}

func (s *saveStateErrorStorage) LoadState() (*AuthenticatorState, error) {
	return s.storage.LoadState()
}

func (s *saveStateErrorStorage) Close() error {
	return s.storage.Close()
}

func (s *saveStateErrorStorage) Clear() error {
	return s.storage.Clear()
}

// Helper functions for testing

func createTestAuthenticatorWithStorageForReset(t *testing.T) (*Authenticator, *MemoryStorage) {
	t.Helper()
	storage := NewMemoryStorage()
	config := &Config{
		AAGUID:                     DefaultAAGUID,
		SupportedAlgorithms:        []int{COSEAlgES256},
		MaxCredentials:             100,
		MaxResidentCredentials:     25,
		PINMinLength:               4,
		PINMaxRetries:              DefaultPINMaxRetries,
		EnablePIN:                  true,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		Storage:                    storage,
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	return auth, storage
}

func createTestStoredCredentialForReset(t *testing.T, id []byte, rpID string, discoverable bool) *StoredCredential {
	t.Helper()

	// Generate a test private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Encode public key to COSE format
	pubKeyCOSE, err := EncodeCOSEPublicKey(&privateKey.PublicKey, COSEAlgES256)
	if err != nil {
		t.Fatalf("failed to encode public key: %v", err)
	}

	return &StoredCredential{
		CredentialID:    id,
		RPID:            rpID,
		RPName:          "Test RP",
		UserID:          []byte("testuser"),
		UserName:        "testuser@example.com",
		UserDisplayName: "Test User",
		PrivateKey:      nil, // Would be PKCS#8 encoded in real implementation
		PublicKeyCOSE:   pubKeyCOSE,
		Algorithm:       COSEAlgES256,
		SignCount:       0,
		Discoverable:    discoverable,
		HMACSecretKey:   nil,
		CreatedAt:       1234567890,
	}
}
