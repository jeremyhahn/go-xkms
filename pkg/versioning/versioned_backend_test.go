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

package versioning

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// mockKeyBackend is a simple in-memory backend for testing.
type mockKeyBackend struct {
	mu     sync.RWMutex
	keys   map[string]crypto.PrivateKey
	closed bool
}

func newMockKeyBackend() *mockKeyBackend {
	return &mockKeyBackend{
		keys: make(map[string]crypto.PrivateKey),
	}
}

func (m *mockKeyBackend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

func (m *mockKeyBackend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:        true,
		Signing:     true,
		Decryption:  true,
		KeyRotation: false, // Underlying backend doesn't support rotation
	}
}

func (m *mockKeyBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrBackendClosed
	}

	// Generate an ECDSA P-256 key for testing
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	m.keys[attrs.CN] = key
	return key, nil
}

func (m *mockKeyBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrBackendClosed
	}

	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, types.ErrFileNotFound
	}
	return key, nil
}

func (m *mockKeyBackend) DeleteKey(attrs *types.KeyAttributes) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrBackendClosed
	}

	if _, ok := m.keys[attrs.CN]; !ok {
		return types.ErrFileNotFound
	}
	delete(m.keys, attrs.CN)
	return nil
}

func (m *mockKeyBackend) ListKeys() ([]*types.KeyAttributes, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrBackendClosed
	}

	result := make([]*types.KeyAttributes, 0, len(m.keys))
	for cn := range m.keys {
		result = append(result, &types.KeyAttributes{CN: cn})
	}
	return result, nil
}

func (m *mockKeyBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	key, err := m.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, types.ErrInvalidKeyAlgorithm
	}
	return signer, nil
}

func (m *mockKeyBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	key, err := m.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, types.ErrInvalidKeyAlgorithm
	}
	return decrypter, nil
}

func (m *mockKeyBackend) RotateKey(attrs *types.KeyAttributes) error {
	// Mock backend doesn't support rotation
	return types.ErrInvalidKeyAlgorithm
}

func (m *mockKeyBackend) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// Helper to create a test versioned backend
func newTestVersionedBackend() *VersionedBackend {
	backend := newMockKeyBackend()
	versionStore := NewMemoryVersionStore()
	return NewVersionedBackend(backend, versionStore)
}

func TestVersionedBackend_GenerateKey(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	// Generate key
	key, err := vb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("GenerateKey returned nil key")
	}

	// Verify version was created
	version, err := vb.GetCurrentVersion("test-key")
	if err != nil {
		t.Fatalf("GetCurrentVersion failed: %v", err)
	}
	if version != 1 {
		t.Errorf("Current version = %d, want 1", version)
	}

	// Verify version info
	info, err := vb.GetVersionInfo("test-key", 1)
	if err != nil {
		t.Fatalf("GetVersionInfo failed: %v", err)
	}
	if info.BackendKeyID != "test-key-v1" {
		t.Errorf("BackendKeyID = %q, want %q", info.BackendKeyID, "test-key-v1")
	}
	if info.State != KeyStateEnabled {
		t.Errorf("State = %q, want %q", info.State, KeyStateEnabled)
	}
}

func TestVersionedBackend_GenerateDuplicateKeyFails(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate first key
	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("First GenerateKey failed: %v", err)
	}

	// Second generate should fail
	_, err := vb.GenerateKey(attrs)
	if err == nil {
		t.Error("Expected error for duplicate key generation")
	}
}

func TestVersionedBackend_RotateKey(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate initial key
	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Rotate key
	if err := vb.RotateKey(attrs); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Verify current version is now 2
	version, err := vb.GetCurrentVersion("test-key")
	if err != nil {
		t.Fatalf("GetCurrentVersion failed: %v", err)
	}
	if version != 2 {
		t.Errorf("Current version = %d, want 2", version)
	}

	// Verify both versions exist
	versions, err := vb.ListVersions("test-key")
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("Expected 2 versions, got %d", len(versions))
	}
}

func TestVersionedBackend_GetKey(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate key
	originalKey, err := vb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Get key
	retrievedKey, err := vb.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	// Keys should be the same
	if originalKey != retrievedKey {
		t.Error("Retrieved key doesn't match original")
	}
}

func TestVersionedBackend_GetKeyVersion(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate initial key
	key1, err := vb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Rotate to create version 2
	if err := vb.RotateKey(attrs); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Get version 1 specifically
	retrievedKey1, err := vb.GetKeyVersion(attrs, 1)
	if err != nil {
		t.Fatalf("GetKeyVersion(1) failed: %v", err)
	}
	if key1 != retrievedKey1 {
		t.Error("Retrieved version 1 key doesn't match original")
	}

	// Get version 0 (should return current = version 2)
	key2, err := vb.GetKeyVersion(attrs, 0)
	if err != nil {
		t.Fatalf("GetKeyVersion(0) failed: %v", err)
	}
	if key2 == key1 {
		t.Error("Version 0 should return version 2, not version 1")
	}
}

func TestVersionedBackend_Signer(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate key
	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Get signer
	signer, err := vb.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}
	if signer == nil {
		t.Fatal("Signer returned nil")
	}

	// Test signing
	digest := []byte("test message to sign")
	sig, err := signer.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Error("Signature is empty")
	}
}

func TestVersionedBackend_SignerVersion(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate initial key
	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Rotate
	if err := vb.RotateKey(attrs); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Get signer for version 1
	signer1, err := vb.SignerVersion(attrs, 1)
	if err != nil {
		t.Fatalf("SignerVersion(1) failed: %v", err)
	}

	// Get signer for version 2
	signer2, err := vb.SignerVersion(attrs, 2)
	if err != nil {
		t.Fatalf("SignerVersion(2) failed: %v", err)
	}

	// Signers should have different public keys
	pub1 := signer1.Public().(*ecdsa.PublicKey)
	pub2 := signer2.Public().(*ecdsa.PublicKey)

	if pub1.Equal(pub2) {
		t.Error("Version 1 and 2 signers have same public key")
	}
}

func TestVersionedBackend_DeleteKey(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate and rotate
	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if err := vb.RotateKey(attrs); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Delete key
	if err := vb.DeleteKey(attrs); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Key should be gone
	_, err := vb.GetCurrentVersion("test-key")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestVersionedBackend_DeleteKeyVersion(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate and rotate
	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if err := vb.RotateKey(attrs); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Delete version 1
	if err := vb.DeleteKeyVersion(attrs, 1); err != nil {
		t.Fatalf("DeleteKeyVersion failed: %v", err)
	}

	// Version 1 should be gone
	_, err := vb.GetVersionInfo("test-key", 1)
	if err != ErrVersionNotFound {
		t.Errorf("Expected ErrVersionNotFound, got %v", err)
	}

	// Version 2 should still exist
	info, err := vb.GetVersionInfo("test-key", 2)
	if err != nil {
		t.Fatalf("GetVersionInfo(2) failed: %v", err)
	}
	if info.Version != 2 {
		t.Errorf("Version = %d, want 2", info.Version)
	}
}

func TestVersionedBackend_ListKeys(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	// Create multiple keys
	keyNames := []string{"alpha", "beta", "gamma"}
	for _, name := range keyNames {
		attrs := &types.KeyAttributes{
			CN:           name,
			KeyAlgorithm: x509.ECDSA,
		}
		if _, err := vb.GenerateKey(attrs); err != nil {
			t.Fatalf("GenerateKey(%s) failed: %v", name, err)
		}
	}

	// List keys
	keys, err := vb.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != len(keyNames) {
		t.Fatalf("Expected %d keys, got %d", len(keyNames), len(keys))
	}
}

func TestVersionedBackend_SetCurrentVersion(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate and rotate twice
	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if err := vb.RotateKey(attrs); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Current should be 2
	version, _ := vb.GetCurrentVersion("test-key")
	if version != 2 {
		t.Errorf("Initial current = %d, want 2", version)
	}

	// Set current to 1
	if err := vb.SetCurrentVersion("test-key", 1); err != nil {
		t.Fatalf("SetCurrentVersion failed: %v", err)
	}

	version, _ = vb.GetCurrentVersion("test-key")
	if version != 1 {
		t.Errorf("After SetCurrentVersion = %d, want 1", version)
	}
}

func TestVersionedBackend_UpdateVersionState(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Update state
	if err := vb.UpdateVersionState("test-key", 1, KeyStateDisabled); err != nil {
		t.Fatalf("UpdateVersionState failed: %v", err)
	}

	info, _ := vb.GetVersionInfo("test-key", 1)
	if info.State != KeyStateDisabled {
		t.Errorf("State = %q, want %q", info.State, KeyStateDisabled)
	}
}

func TestVersionedBackend_CapabilitiesWithRotation(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	caps := vb.Capabilities()

	// Even though underlying backend doesn't support rotation,
	// versioned backend should enable it
	if !caps.KeyRotation {
		t.Error("VersionedBackend should report KeyRotation = true")
	}
}

func TestVersionedBackend_Type(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	// Should return underlying backend type
	if vb.Type() != types.BackendTypeSoftware {
		t.Errorf("Type = %v, want %v", vb.Type(), types.BackendTypeSoftware)
	}
}

func TestVersionedBackend_Close(t *testing.T) {
	vb := newTestVersionedBackend()

	// Close should work
	if err := vb.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Operations after close should fail
	attrs := &types.KeyAttributes{CN: "test"}
	_, err := vb.GenerateKey(attrs)
	if err != ErrBackendClosed {
		t.Errorf("GenerateKey after close = %v, want ErrBackendClosed", err)
	}

	_, err = vb.GetKey(attrs)
	if err != ErrBackendClosed {
		t.Errorf("GetKey after close = %v, want ErrBackendClosed", err)
	}

	// Second close should be idempotent
	if err := vb.Close(); err != nil {
		t.Errorf("Second Close failed: %v", err)
	}
}

func TestVersionedBackend_Accessors(t *testing.T) {
	backend := newMockKeyBackend()
	versionStore := NewMemoryVersionStore()
	vb := NewVersionedBackend(backend, versionStore)
	defer func() { _ = vb.Close() }()

	if vb.Backend() != backend {
		t.Error("Backend() returned wrong backend")
	}

	if vb.VersionStore() != versionStore {
		t.Error("VersionStore() returned wrong store")
	}
}

func TestVersionedBackend_Concurrent(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	var wg sync.WaitGroup
	numGoroutines := 5
	rotationsPerGoroutine := 5

	// Generate initial key
	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}
	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Concurrent rotations should fail gracefully (only one wins at a time)
	// This tests thread safety
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < rotationsPerGoroutine; j++ {
				_ = vb.RotateKey(attrs)
			}
		}()
	}
	wg.Wait()

	// Verify we have at least one rotation
	versions, err := vb.ListVersions("test-key")
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}
	if len(versions) < 2 {
		t.Errorf("Expected at least 2 versions, got %d", len(versions))
	}
}

func TestVersionedBackend_GenerateKeyVersion(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	// Generate version 5 explicitly
	key, err := vb.GenerateKeyVersion(attrs, 5)
	if err != nil {
		t.Fatalf("GenerateKeyVersion failed: %v", err)
	}
	if key == nil {
		t.Fatal("GenerateKeyVersion returned nil key")
	}

	// Verify version was created
	info, err := vb.GetVersionInfo("test-key", 5)
	if err != nil {
		t.Fatalf("GetVersionInfo failed: %v", err)
	}
	if info.Version != 5 {
		t.Errorf("Version = %d, want 5", info.Version)
	}
	if info.BackendKeyID != "test-key-v5" {
		t.Errorf("BackendKeyID = %q, want %q", info.BackendKeyID, "test-key-v5")
	}

	// Current version should be 5
	current, err := vb.GetCurrentVersion("test-key")
	if err != nil {
		t.Fatalf("GetCurrentVersion failed: %v", err)
	}
	if current != 5 {
		t.Errorf("Current version = %d, want 5", current)
	}
}

func TestVersionedBackend_GenerateKeyVersionClosed(t *testing.T) {
	vb := newTestVersionedBackend()
	_ = vb.Close()

	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := vb.GenerateKeyVersion(attrs, 1)
	if err != ErrBackendClosed {
		t.Errorf("GenerateKeyVersion on closed backend = %v, want ErrBackendClosed", err)
	}
}

// mockDecryptBackend is a mock backend that supports decryption
type mockDecryptBackend struct {
	*mockKeyBackend
}

func newMockDecryptBackend() *mockDecryptBackend {
	return &mockDecryptBackend{
		mockKeyBackend: newMockKeyBackend(),
	}
}

func (m *mockDecryptBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	key, err := m.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	// ECDSA implements crypto.Decrypter interface
	if dec, ok := key.(*ecdsa.PrivateKey); ok {
		return &mockDecrypterWrapper{key: dec}, nil
	}
	return nil, types.ErrInvalidKeyAlgorithm
}

// mockDecrypterWrapper wraps an ECDSA key to implement crypto.Decrypter
type mockDecrypterWrapper struct {
	key *ecdsa.PrivateKey
}

func (m *mockDecrypterWrapper) Public() crypto.PublicKey {
	return &m.key.PublicKey
}

func (m *mockDecrypterWrapper) Decrypt(_ io.Reader, _ []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	// Mock implementation - just return empty for testing purposes
	return []byte("decrypted"), nil
}

func TestVersionedBackend_Decrypter(t *testing.T) {
	backend := newMockDecryptBackend()
	versionStore := NewMemoryVersionStore()
	vb := NewVersionedBackend(backend, versionStore)
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate key
	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Get decrypter
	decrypter, err := vb.Decrypter(attrs)
	if err != nil {
		t.Fatalf("Decrypter failed: %v", err)
	}
	if decrypter == nil {
		t.Fatal("Decrypter returned nil")
	}

	// Verify it can decrypt
	result, err := decrypter.Decrypt(rand.Reader, []byte("test"), nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(result) != "decrypted" {
		t.Errorf("Decrypt result = %q, want %q", result, "decrypted")
	}
}

func TestVersionedBackend_DecrypterVersion(t *testing.T) {
	backend := newMockDecryptBackend()
	versionStore := NewMemoryVersionStore()
	vb := NewVersionedBackend(backend, versionStore)
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate and rotate
	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if err := vb.RotateKey(attrs); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Get decrypter for version 1
	decrypter1, err := vb.DecrypterVersion(attrs, 1)
	if err != nil {
		t.Fatalf("DecrypterVersion(1) failed: %v", err)
	}

	// Get decrypter for version 2
	decrypter2, err := vb.DecrypterVersion(attrs, 2)
	if err != nil {
		t.Fatalf("DecrypterVersion(2) failed: %v", err)
	}

	// Get decrypter for version 0 (current = 2)
	decrypter0, err := vb.DecrypterVersion(attrs, 0)
	if err != nil {
		t.Fatalf("DecrypterVersion(0) failed: %v", err)
	}

	// Decrypters should have different public keys for v1 vs v2
	pub1 := decrypter1.Public().(*ecdsa.PublicKey)
	pub2 := decrypter2.Public().(*ecdsa.PublicKey)
	pub0 := decrypter0.Public().(*ecdsa.PublicKey)

	if pub1.Equal(pub2) {
		t.Error("Version 1 and 2 decrypters have same public key")
	}
	if !pub2.Equal(pub0) {
		t.Error("Version 0 (current) decrypter should match version 2")
	}
}

func TestVersionedBackend_DecrypterClosed(t *testing.T) {
	vb := newTestVersionedBackend()
	_ = vb.Close()

	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := vb.DecrypterVersion(attrs, 0)
	if err != ErrBackendClosed {
		t.Errorf("DecrypterVersion on closed backend = %v, want ErrBackendClosed", err)
	}
}

func TestVersionedBackend_ClosedOperations(t *testing.T) {
	vb := newTestVersionedBackend()
	_ = vb.Close()

	// Test all operations on closed backend
	attrs := &types.KeyAttributes{CN: "test-key"}

	if _, err := vb.GetKeyVersion(attrs, 1); err != ErrBackendClosed {
		t.Errorf("GetKeyVersion = %v, want ErrBackendClosed", err)
	}

	if err := vb.DeleteKey(attrs); err != ErrBackendClosed {
		t.Errorf("DeleteKey = %v, want ErrBackendClosed", err)
	}

	if err := vb.DeleteKeyVersion(attrs, 1); err != ErrBackendClosed {
		t.Errorf("DeleteKeyVersion = %v, want ErrBackendClosed", err)
	}

	if _, err := vb.ListKeys(); err != ErrBackendClosed {
		t.Errorf("ListKeys = %v, want ErrBackendClosed", err)
	}

	if _, err := vb.SignerVersion(attrs, 0); err != ErrBackendClosed {
		t.Errorf("SignerVersion = %v, want ErrBackendClosed", err)
	}

	if err := vb.RotateKey(attrs); err != ErrBackendClosed {
		t.Errorf("RotateKey = %v, want ErrBackendClosed", err)
	}

	if _, err := vb.GetCurrentVersion("test-key"); err != ErrBackendClosed {
		t.Errorf("GetCurrentVersion = %v, want ErrBackendClosed", err)
	}

	if _, err := vb.GetVersionInfo("test-key", 1); err != ErrBackendClosed {
		t.Errorf("GetVersionInfo = %v, want ErrBackendClosed", err)
	}

	if _, err := vb.ListVersions("test-key"); err != ErrBackendClosed {
		t.Errorf("ListVersions = %v, want ErrBackendClosed", err)
	}

	if err := vb.SetCurrentVersion("test-key", 1); err != ErrBackendClosed {
		t.Errorf("SetCurrentVersion = %v, want ErrBackendClosed", err)
	}

	if err := vb.UpdateVersionState("test-key", 1, KeyStateDisabled); err != ErrBackendClosed {
		t.Errorf("UpdateVersionState = %v, want ErrBackendClosed", err)
	}
}

func TestVersionedBackend_AlgorithmFromAttrs(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	// Test with X25519 attributes
	attrsX25519 := &types.KeyAttributes{
		CN:               "x25519-key",
		X25519Attributes: &types.X25519Attributes{},
	}
	key, err := vb.GenerateKey(attrsX25519)
	if err != nil {
		t.Fatalf("GenerateKey with X25519 attrs failed: %v", err)
	}
	if key == nil {
		t.Fatal("GenerateKey returned nil key")
	}

	info, _ := vb.GetVersionInfo("x25519-key", 1)
	if info.Algorithm != "X25519" {
		t.Errorf("X25519 Algorithm = %q, want %q", info.Algorithm, "X25519")
	}

	// Test with symmetric algorithm
	attrsSymmetric := &types.KeyAttributes{
		CN:                 "symmetric-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	key2, err := vb.GenerateKey(attrsSymmetric)
	if err != nil {
		t.Fatalf("GenerateKey with symmetric attrs failed: %v", err)
	}
	if key2 == nil {
		t.Fatal("GenerateKey returned nil key")
	}

	info2, _ := vb.GetVersionInfo("symmetric-key", 1)
	if info2.Algorithm != string(types.SymmetricAES256GCM) {
		t.Errorf("Symmetric Algorithm = %q, want %q", info2.Algorithm, types.SymmetricAES256GCM)
	}
}

func TestVersionedBackend_CopyKeyAttributesNil(t *testing.T) {
	// Test that copyKeyAttributes handles nil gracefully
	result := copyKeyAttributes(nil)
	if result != nil {
		t.Errorf("copyKeyAttributes(nil) = %v, want nil", result)
	}
}

func TestVersionedBackend_ResolveVersionError(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate key
	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Try to get non-existent version
	_, err := vb.GetKeyVersion(attrs, 99)
	if err != ErrVersionNotFound {
		t.Errorf("GetKeyVersion(99) = %v, want ErrVersionNotFound", err)
	}

	// Try to sign with non-existent version
	_, err = vb.SignerVersion(attrs, 99)
	if err != ErrVersionNotFound {
		t.Errorf("SignerVersion(99) = %v, want ErrVersionNotFound", err)
	}

	// Try to decrypt with non-existent version
	_, err = vb.DecrypterVersion(attrs, 99)
	if err != ErrVersionNotFound {
		t.Errorf("DecrypterVersion(99) = %v, want ErrVersionNotFound", err)
	}
}

func TestVersionedBackend_GetKeyNonexistent(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{CN: "nonexistent-key"}

	_, err := vb.GetKey(attrs)
	if err != ErrKeyNotFound {
		t.Errorf("GetKey(nonexistent) = %v, want ErrKeyNotFound", err)
	}
}

func TestVersionedBackend_DeleteKeyVersionNonexistent(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate key
	if _, err := vb.GenerateKey(attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Try to delete non-existent version
	err := vb.DeleteKeyVersion(attrs, 99)
	if err == nil {
		t.Error("Expected error for deleting non-existent version")
	}
}

func TestVersionedBackend_RotateKeyNonexistent(t *testing.T) {
	vb := newTestVersionedBackend()
	defer func() { _ = vb.Close() }()

	attrs := &types.KeyAttributes{CN: "nonexistent-key"}

	err := vb.RotateKey(attrs)
	if err == nil {
		t.Error("Expected error for rotating non-existent key")
	}
}
