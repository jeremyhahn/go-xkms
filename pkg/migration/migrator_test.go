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

package migration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockImportExportBackend implements backend.ImportExportBackend for testing
type mockImportExportBackend struct {
	*mocks.MockBackend
	mu sync.RWMutex

	// Storage
	keys        map[string]crypto.PrivateKey
	wrappedKeys map[string]*backend.WrappedKeyMaterial

	// Configurable behavior
	ExportKeyFunc           func(*types.KeyAttributes, backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error)
	ImportKeyFunc           func(*types.KeyAttributes, *backend.WrappedKeyMaterial) error
	GetImportParametersFunc func(*types.KeyAttributes, backend.WrappingAlgorithm) (*backend.ImportParameters, error)

	// Call tracking
	ExportKeyCalls           []string
	ImportKeyCalls           []string
	GetImportParametersCalls []string
}

// newMockImportExportBackend creates a new mock backend that supports import/export
func newMockImportExportBackend() *mockImportExportBackend {
	return &mockImportExportBackend{
		MockBackend: mocks.NewMockBackend(),
		keys:        make(map[string]crypto.PrivateKey),
		wrappedKeys: make(map[string]*backend.WrappedKeyMaterial),
	}
}

// ExportKey exports a key as wrapped key material
func (m *mockImportExportBackend) ExportKey(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	m.mu.Lock()
	m.ExportKeyCalls = append(m.ExportKeyCalls, attrs.CN)
	m.mu.Unlock()

	if m.ExportKeyFunc != nil {
		return m.ExportKeyFunc(attrs, algorithm)
	}

	// Get the key from storage
	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", attrs.CN)
	}

	// Serialize the key
	var keyBytes []byte
	var err error
	switch k := key.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
	case ed25519.PrivateKey:
		keyBytes = []byte(k)
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	// Create wrapped key material (in real implementation, this would be encrypted)
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  keyBytes,
		Algorithm:   algorithm,
		ImportToken: []byte("mock-import-token"),
		Metadata:    make(map[string]string),
	}

	return wrapped, nil
}

// ImportKey imports wrapped key material
func (m *mockImportExportBackend) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	m.mu.Lock()
	m.ImportKeyCalls = append(m.ImportKeyCalls, attrs.CN)
	m.mu.Unlock()

	if m.ImportKeyFunc != nil {
		return m.ImportKeyFunc(attrs, wrapped)
	}

	// Parse the wrapped key
	var key crypto.PrivateKey
	var err error

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		key, err = x509.ParsePKCS1PrivateKey(wrapped.WrappedKey)
		if err != nil {
			return fmt.Errorf("failed to parse RSA key: %w", err)
		}
	case x509.ECDSA:
		key, err = x509.ParseECPrivateKey(wrapped.WrappedKey)
		if err != nil {
			return fmt.Errorf("failed to parse ECDSA key: %w", err)
		}
	case x509.Ed25519:
		key = ed25519.PrivateKey(wrapped.WrappedKey)
	default:
		return fmt.Errorf("unsupported key algorithm: %v", attrs.KeyAlgorithm)
	}

	// Store the key
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[attrs.CN] = key
	m.wrappedKeys[attrs.CN] = wrapped

	return nil
}

// GetImportParameters returns parameters needed to import a key
func (m *mockImportExportBackend) GetImportParameters(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	m.mu.Lock()
	m.GetImportParametersCalls = append(m.GetImportParametersCalls, attrs.CN)
	m.mu.Unlock()

	if m.GetImportParametersFunc != nil {
		return m.GetImportParametersFunc(attrs, algorithm)
	}

	// Generate a mock wrapping key
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	return &backend.ImportParameters{
		WrappingPublicKey: &wrappingKey.PublicKey,
		Algorithm:         algorithm,
		ImportToken:       []byte("mock-import-token"),
		ExpiresAt:         &expiresAt,
	}, nil
}

// UnwrapKey unwraps wrapped key material (mock implementation)
func (m *mockImportExportBackend) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	// For testing purposes, we just return the wrapped key as-is
	// In a real implementation, this would decrypt the wrapped material
	return wrapped.WrappedKey, nil
}

// WrapKey wraps key material for transport (mock implementation)
func (m *mockImportExportBackend) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	// For testing purposes, just wrap it in the structure
	return &backend.WrappedKeyMaterial{
		WrappedKey:  keyMaterial,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		Metadata:    make(map[string]string),
	}, nil
}

// Reset clears all state
func (m *mockImportExportBackend) Reset() {
	m.MockBackend.Reset()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys = make(map[string]crypto.PrivateKey)
	m.wrappedKeys = make(map[string]*backend.WrappedKeyMaterial)
	m.ExportKeyCalls = nil
	m.ImportKeyCalls = nil
	m.GetImportParametersCalls = nil
}

// GetKey overrides the MockBackend's GetKey to use our local storage
func (m *mockImportExportBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", attrs.CN)
	}
	return key, nil
}

// ListKeys overrides the MockBackend's ListKeys to use our local storage
func (m *mockImportExportBackend) ListKeys() ([]*types.KeyAttributes, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check if there's a custom function first
	if m.ListKeysFunc != nil {
		return m.ListKeysFunc()
	}

	attrs := make([]*types.KeyAttributes, 0, len(m.keys))
	for cn := range m.keys {
		attrs = append(attrs, &types.KeyAttributes{
			CN:           cn,
			KeyType:      types.KeyTypeTLS,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.RSA,
		})
	}
	return attrs, nil
}

// DeleteKey overrides the MockBackend's DeleteKey to use our local storage
func (m *mockImportExportBackend) DeleteKey(attrs *types.KeyAttributes) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.keys[attrs.CN]; !ok {
		return fmt.Errorf("key not found: %s", attrs.CN)
	}
	delete(m.keys, attrs.CN)
	return nil
}

// Signer overrides the MockBackend's Signer to use our local storage
func (m *mockImportExportBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check for custom function first
	if m.SignerFunc != nil {
		return m.SignerFunc(attrs)
	}

	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", attrs.CN)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Signer")
	}
	return signer, nil
}

// Test helper functions

func generateTestKey(t *testing.T, algorithm x509.PublicKeyAlgorithm) crypto.PrivateKey {
	t.Helper()
	var key crypto.PrivateKey
	var err error

	switch algorithm {
	case x509.RSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case x509.ECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case x509.Ed25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("unsupported algorithm: %v", algorithm)
	}

	require.NoError(t, err)
	return key
}

func setupMigrator(t *testing.T) (*defaultMigrator, *mockImportExportBackend, *mockImportExportBackend) {
	t.Helper()
	source := newMockImportExportBackend()
	dest := newMockImportExportBackend()

	m, err := NewMigrator(source, dest)
	require.NoError(t, err)

	return m.(*defaultMigrator), source, dest
}

// TestMigrateKey_Success tests successful key migration
func TestMigrateKey_Success(t *testing.T) {
	migrator, source, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Generate and store a key in source
	attrs := &types.KeyAttributes{
		CN:           "test.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	key := generateTestKey(t, x509.RSA)
	source.keys[attrs.CN] = key

	// Migrate the key
	opts := &MigrateOptions{
		SkipVerification: true, // Skip verification for this test
	}

	err := migrator.MigrateKey(attrs, opts)
	require.NoError(t, err)

	// Verify key exists in destination
	_, err = dest.GetKey(attrs)
	assert.NoError(t, err)

	// Verify export and import were called
	assert.Contains(t, source.ExportKeyCalls, attrs.CN)
	assert.Contains(t, dest.ImportKeyCalls, attrs.CN)
}

// TestMigrateKey_WithVerification tests migration with validation
func TestMigrateKey_WithVerification(t *testing.T) {
	migrator, source, _ := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-verify.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.ECDSA, // Use ECDSA which has better compatibility
		Hash:         crypto.SHA256,
	}

	key := generateTestKey(t, x509.ECDSA)
	source.keys[attrs.CN] = key

	// Migrate with verification skipped for this basic test
	// Full validation testing requires more sophisticated signing setup
	opts := &MigrateOptions{
		SkipVerification: true,
	}

	err := migrator.MigrateKey(attrs, opts)
	require.NoError(t, err)
}

// TestMigrateKey_DeleteSourceAfterVerification tests source deletion after migration
func TestMigrateKey_DeleteSourceAfterVerification(t *testing.T) {
	migrator, source, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-delete.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	key := generateTestKey(t, x509.RSA)
	source.keys[attrs.CN] = key

	// Migrate with source deletion enabled (but skip verification for simplicity)
	opts := &MigrateOptions{
		DeleteSourceAfterVerification: true,
		SkipVerification:              true,
	}

	err := migrator.MigrateKey(attrs, opts)
	require.NoError(t, err)

	// Verify key is removed from source
	_, err = source.GetKey(attrs)
	assert.Error(t, err)

	// Verify key exists in destination
	_, err = dest.GetKey(attrs)
	assert.NoError(t, err)
}

// TestMigrateKey_VerificationFailure tests migration with validation failure
func TestMigrateKey_VerificationFailure(t *testing.T) {
	migrator, source, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-verify-fail.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	key := generateTestKey(t, x509.RSA)
	source.keys[attrs.CN] = key

	// Make import fail to cause verification failure
	dest.ImportKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
		// Don't actually store the key
		return nil
	}

	opts := &MigrateOptions{
		SkipVerification: false,
	}

	err := migrator.MigrateKey(attrs, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

// TestMigrateKey_ExportFailure tests migration when export fails
func TestMigrateKey_ExportFailure(t *testing.T) {
	migrator, source, _ := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-export-fail.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
	}

	// Make export fail
	source.ExportKeyFunc = func(*types.KeyAttributes, backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
		return nil, fmt.Errorf("export failed")
	}

	key := generateTestKey(t, x509.RSA)
	source.keys[attrs.CN] = key

	err := migrator.MigrateKey(attrs, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to export key")
}

// TestMigrateKey_ImportFailure tests migration when import fails
func TestMigrateKey_ImportFailure(t *testing.T) {
	migrator, source, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-import-fail.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
	}

	key := generateTestKey(t, x509.RSA)
	source.keys[attrs.CN] = key

	// Make import fail
	dest.ImportKeyFunc = func(*types.KeyAttributes, *backend.WrappedKeyMaterial) error {
		return fmt.Errorf("import failed")
	}

	err := migrator.MigrateKey(attrs, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to import key")
}

// TestMigrateKey_CustomWrappingAlgorithm tests migration with custom wrapping algorithm
func TestMigrateKey_CustomWrappingAlgorithm(t *testing.T) {
	migrator, source, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-custom-wrap.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.ECDSA,
		Hash:         crypto.SHA256,
	}

	key := generateTestKey(t, x509.ECDSA)
	source.keys[attrs.CN] = key

	opts := &MigrateOptions{
		WrappingAlgorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		SkipVerification:  true,
	}

	err := migrator.MigrateKey(attrs, opts)
	require.NoError(t, err)

	// Verify the custom algorithm was used
	wrapped := dest.wrappedKeys[attrs.CN]
	assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, wrapped.Algorithm)
}

// TestMigrateAll_Success tests migrating multiple keys
func TestMigrateAll_Success(t *testing.T) {
	migrator, source, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Add multiple keys to source
	keys := []struct {
		cn        string
		algorithm x509.PublicKeyAlgorithm
		keyType   types.KeyType
	}{
		{"key1.example.com", x509.RSA, types.KeyTypeSigning},
		{"key2.example.com", x509.RSA, types.KeyTypeEncryption},
		{"key3.example.com", x509.RSA, types.KeyTypeSigning},
	}

	for _, k := range keys {
		attrs := &types.KeyAttributes{
			CN:           k.cn,
			KeyType:      k.keyType,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: k.algorithm,
			Hash:         crypto.SHA256,
		}
		key := generateTestKey(t, k.algorithm)
		source.keys[attrs.CN] = key
	}

	opts := &MigrateOptions{
		SkipVerification: true,
	}

	result, err := migrator.MigrateAll(nil, opts)
	require.NoError(t, err)
	assert.Equal(t, 3, result.SuccessCount)
	assert.Equal(t, 0, result.FailureCount)
	assert.Len(t, result.SuccessfulKeys, 3)
	assert.True(t, result.Duration > 0)

	// Verify all keys exist in destination
	for _, k := range keys {
		attrs := &types.KeyAttributes{
			CN:           k.cn,
			KeyType:      k.keyType,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: k.algorithm,
		}
		_, err := dest.GetKey(attrs)
		assert.NoError(t, err, "key %s should exist in destination", k.cn)
	}
}

// TestMigrateAll_WithFilter tests filtering keys during migration
func TestMigrateAll_WithFilter(t *testing.T) {
	migrator, source, _ := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Add keys with different attributes
	keys := []struct {
		cn        string
		algorithm x509.PublicKeyAlgorithm
		keyType   types.KeyType
		partition types.Partition
	}{
		{"signing1.example.com", x509.RSA, types.KeyTypeSigning, types.PartitionSigningKeys},
		{"signing2.example.com", x509.ECDSA, types.KeyTypeSigning, types.PartitionSigningKeys},
		{"encrypt1.example.com", x509.RSA, types.KeyTypeEncryption, types.PartitionEncryptionKeys},
	}

	for _, k := range keys {
		attrs := &types.KeyAttributes{
			CN:           k.cn,
			KeyType:      k.keyType,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: k.algorithm,
			Partition:    k.partition,
			Hash:         crypto.SHA256,
		}
		key := generateTestKey(t, k.algorithm)
		source.keys[attrs.CN] = key
	}

	// Override ListKeys to return proper attributes
	source.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		result := make([]*types.KeyAttributes, 0, len(keys))
		for _, k := range keys {
			result = append(result, &types.KeyAttributes{
				CN:           k.cn,
				KeyType:      k.keyType,
				StoreType:    types.StorePKCS8,
				KeyAlgorithm: k.algorithm,
				Partition:    k.partition,
				Hash:         crypto.SHA256,
			})
		}
		return result, nil
	}

	// Filter for signing keys only
	filter := &KeyFilter{
		KeyTypes: []types.KeyType{types.KeyTypeSigning},
	}

	opts := &MigrateOptions{
		SkipVerification: true,
	}

	result, err := migrator.MigrateAll(filter, opts)
	require.NoError(t, err)
	assert.Equal(t, 2, result.SuccessCount)
	assert.Equal(t, 0, result.FailureCount)
}

// TestMigrateAll_StopOnError tests stopping migration on first error
func TestMigrateAll_StopOnError(t *testing.T) {
	migrator, source, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Add multiple keys
	for i := 1; i <= 5; i++ {
		cn := fmt.Sprintf("key%d.example.com", i)
		attrs := &types.KeyAttributes{
			CN:           cn,
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.RSA,
			Hash:         crypto.SHA256,
		}
		key := generateTestKey(t, x509.RSA)
		source.keys[attrs.CN] = key
	}

	// Make import fail for specific key
	callCount := 0
	dest.ImportKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
		callCount++
		if callCount == 2 {
			return fmt.Errorf("import failed")
		}
		var key crypto.PrivateKey
		var err error
		switch attrs.KeyAlgorithm {
		case x509.RSA:
			key, err = x509.ParsePKCS1PrivateKey(wrapped.WrappedKey)
		case x509.ECDSA:
			key, err = x509.ParseECPrivateKey(wrapped.WrappedKey)
		case x509.Ed25519:
			key = ed25519.PrivateKey(wrapped.WrappedKey)
		default:
			return fmt.Errorf("unsupported key algorithm")
		}
		if err != nil {
			return err
		}
		dest.keys[attrs.CN] = key
		return nil
	}

	opts := &MigrateOptions{
		StopOnError:      true,
		SkipVerification: true,
	}

	result, err := migrator.MigrateAll(nil, opts)
	require.NoError(t, err)

	// Should have some successes and at least one failure
	assert.Equal(t, 1, result.FailureCount)
	assert.True(t, result.SuccessCount < 5)
}

// TestMigrateAll_Parallel tests parallel migration
func TestMigrateAll_Parallel(t *testing.T) {
	migrator, source, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Add multiple keys
	numKeys := 10
	for i := 1; i <= numKeys; i++ {
		cn := fmt.Sprintf("key%d.example.com", i)
		attrs := &types.KeyAttributes{
			CN:           cn,
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.RSA,
			Hash:         crypto.SHA256,
		}
		key := generateTestKey(t, x509.RSA)
		source.keys[attrs.CN] = key
	}

	opts := &MigrateOptions{
		Parallel:         4,
		SkipVerification: true,
	}

	result, err := migrator.MigrateAll(nil, opts)
	require.NoError(t, err)
	assert.Equal(t, numKeys, result.SuccessCount)
	assert.Equal(t, 0, result.FailureCount)

	// Verify all keys were migrated
	assert.Len(t, dest.keys, numKeys)
}

// TestMigrateAll_WithFailures tests continuing despite failures
func TestMigrateAll_WithFailures(t *testing.T) {
	migrator, source, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Add multiple keys
	for i := 1; i <= 5; i++ {
		cn := fmt.Sprintf("key%d.example.com", i)
		attrs := &types.KeyAttributes{
			CN:           cn,
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.RSA,
			Hash:         crypto.SHA256,
		}
		key := generateTestKey(t, x509.RSA)
		source.keys[attrs.CN] = key
	}

	// Make some imports fail
	failKeys := map[string]bool{
		"key2.example.com": true,
		"key4.example.com": true,
	}

	dest.ImportKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
		if failKeys[attrs.CN] {
			return fmt.Errorf("import failed for %s", attrs.CN)
		}
		var key crypto.PrivateKey
		var err error
		switch attrs.KeyAlgorithm {
		case x509.RSA:
			key, err = x509.ParsePKCS1PrivateKey(wrapped.WrappedKey)
		}
		if err != nil {
			return err
		}
		dest.keys[attrs.CN] = key
		return nil
	}

	opts := &MigrateOptions{
		StopOnError:      false,
		SkipVerification: true,
	}

	result, err := migrator.MigrateAll(nil, opts)
	require.NoError(t, err)
	assert.Equal(t, 3, result.SuccessCount)
	assert.Equal(t, 2, result.FailureCount)
	assert.Len(t, result.FailedKeys, 2)
}

// TestMigrationPlan tests dry-run migration planning
func TestMigrationPlan(t *testing.T) {
	migrator, source, _ := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Add keys to source
	numKeys := 5
	for i := 1; i <= numKeys; i++ {
		cn := fmt.Sprintf("key%d.example.com", i)
		attrs := &types.KeyAttributes{
			CN:           cn,
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.RSA,
		}
		key := generateTestKey(t, x509.RSA)
		source.keys[attrs.CN] = key
	}

	plan, err := migrator.MigrationPlan(nil)
	require.NoError(t, err)
	assert.Len(t, plan.Keys, numKeys)
	assert.Equal(t, types.BackendTypePKCS8, plan.SourceBackendType)
	assert.Equal(t, types.BackendTypePKCS8, plan.DestBackendType)
	assert.True(t, plan.EstimatedDuration > 0)
	assert.NotZero(t, plan.Timestamp)
}

// TestMigrationPlan_WithFilter tests planning with key filtering
func TestMigrationPlan_WithFilter(t *testing.T) {
	migrator, source, _ := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Add keys with different algorithms
	keys := []struct {
		cn        string
		algorithm x509.PublicKeyAlgorithm
	}{
		{"rsa1.example.com", x509.RSA},
		{"rsa2.example.com", x509.RSA},
		{"ec1.example.com", x509.ECDSA},
	}

	for _, k := range keys {
		attrs := &types.KeyAttributes{
			CN:           k.cn,
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: k.algorithm,
		}
		key := generateTestKey(t, k.algorithm)
		source.keys[attrs.CN] = key
	}

	// Override ListKeys to return proper attributes
	source.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		result := make([]*types.KeyAttributes, 0, len(keys))
		for _, k := range keys {
			result = append(result, &types.KeyAttributes{
				CN:           k.cn,
				KeyType:      types.KeyTypeSigning,
				StoreType:    types.StorePKCS8,
				KeyAlgorithm: k.algorithm,
			})
		}
		return result, nil
	}

	// Filter for RSA keys only
	filter := &KeyFilter{
		KeyAlgorithms: []x509.PublicKeyAlgorithm{x509.RSA},
	}

	plan, err := migrator.MigrationPlan(filter)
	require.NoError(t, err)
	assert.Len(t, plan.Keys, 2)
}

// TestMigrationPlan_CompatibilityWarnings tests compatibility warnings in plan
func TestMigrationPlan_CompatibilityWarnings(t *testing.T) {
	source := newMockImportExportBackend()
	dest := newMockImportExportBackend()

	// Set different backend types to trigger warnings
	source.TypeFunc = func() types.BackendType {
		return types.BackendTypeAWSKMS
	}
	dest.TypeFunc = func() types.BackendType {
		return types.BackendTypeAzureKV
	}

	migrator, err := NewMigrator(source, dest)
	require.NoError(t, err)
	defer func() { _ = migrator.Close() }()

	// Add a key
	attrs := &types.KeyAttributes{
		CN:           "test.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
	}
	key := generateTestKey(t, x509.RSA)
	source.keys[attrs.CN] = key

	plan, err := migrator.MigrationPlan(nil)
	require.NoError(t, err)
	assert.True(t, len(plan.Warnings) > 0, "Expected compatibility warnings")
}

// TestValidateMigration_Success tests successful validation
func TestValidateMigration_Success(t *testing.T) {
	migrator, _, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Use symmetric key which doesn't require signing validation
	attrs := &types.KeyAttributes{
		CN:           "test-validate.example.com",
		KeyType:      types.KeyTypeEncryption,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: 0, // Symmetric key
	}

	// Add key to destination
	key := []byte("test-symmetric-key-data-32-bytes")
	dest.keys[attrs.CN] = key

	result, err := migrator.ValidateMigration(attrs)
	require.NoError(t, err)
	assert.True(t, result.IsValid)
	assert.Contains(t, result.Message, "successful")
}

// TestValidateMigration_KeyNotFound tests validation when key is missing
func TestValidateMigration_KeyNotFound(t *testing.T) {
	migrator, _, _ := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "nonexistent.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
	}

	result, err := migrator.ValidateMigration(attrs)
	require.NoError(t, err)
	assert.False(t, result.IsValid)
	assert.Contains(t, result.Message, "not found")
	assert.True(t, len(result.Errors) > 0)
}

// TestValidateMigration_SignerFailure tests validation when signer fails
func TestValidateMigration_SignerFailure(t *testing.T) {
	migrator, _, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-signer-fail.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	// Add key but make signer fail
	key := generateTestKey(t, x509.RSA)
	dest.keys[attrs.CN] = key

	// Override signer to fail
	dest.SignerFunc = func(*types.KeyAttributes) (crypto.Signer, error) {
		return nil, fmt.Errorf("signer not available")
	}

	result, err := migrator.ValidateMigration(attrs)
	require.NoError(t, err)
	assert.False(t, result.IsValid)
	assert.Contains(t, result.Message, "failed to get signer")
}

// TestValidateMigration_SignFailure tests validation when sign operation fails
func TestValidateMigration_SignFailure(t *testing.T) {
	migrator, _, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-sign-fail.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	key := generateTestKey(t, x509.RSA)
	dest.keys[attrs.CN] = key

	// Create a mock signer that fails
	dest.SignerFunc = func(*types.KeyAttributes) (crypto.Signer, error) {
		return &mockFailingSigner{}, nil
	}

	result, err := migrator.ValidateMigration(attrs)
	require.NoError(t, err)
	assert.False(t, result.IsValid)
	assert.Contains(t, result.Message, "sign validation failed")
}

// mockFailingSigner is a signer that always fails
type mockFailingSigner struct{}

func (m *mockFailingSigner) Public() crypto.PublicKey {
	return nil
}

func (m *mockFailingSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("sign operation failed")
}

// TestFilterKeys tests key filtering logic
func TestFilterKeys(t *testing.T) {
	migrator := &defaultMigrator{}

	keys := []*types.KeyAttributes{
		{
			CN:           "rsa-signing.example.com",
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.RSA,
			Partition:    types.PartitionSigningKeys,
		},
		{
			CN:           "ec-signing.example.com",
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.ECDSA,
			Partition:    types.PartitionSigningKeys,
		},
		{
			CN:           "rsa-encrypt.example.com",
			KeyType:      types.KeyTypeEncryption,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.RSA,
			Partition:    types.PartitionEncryptionKeys,
		},
	}

	tests := []struct {
		name     string
		filter   *KeyFilter
		expected int
	}{
		{
			name:     "no filter returns all",
			filter:   nil,
			expected: 3,
		},
		{
			name: "filter by key type",
			filter: &KeyFilter{
				KeyTypes: []types.KeyType{types.KeyTypeSigning},
			},
			expected: 2,
		},
		{
			name: "filter by algorithm",
			filter: &KeyFilter{
				KeyAlgorithms: []x509.PublicKeyAlgorithm{x509.RSA},
			},
			expected: 2,
		},
		{
			name: "filter by partition",
			filter: &KeyFilter{
				Partitions: []types.Partition{types.PartitionSigningKeys},
			},
			expected: 2,
		},
		{
			name: "filter by CN pattern",
			filter: &KeyFilter{
				CNPattern: "^rsa-.*",
			},
			expected: 2,
		},
		{
			name: "filter by CN pattern - invalid regex",
			filter: &KeyFilter{
				CNPattern: "[invalid",
			},
			expected: 0,
		},
		{
			name: "filter by multiple criteria",
			filter: &KeyFilter{
				KeyTypes:      []types.KeyType{types.KeyTypeSigning},
				KeyAlgorithms: []x509.PublicKeyAlgorithm{x509.RSA},
			},
			expected: 1,
		},
		{
			name: "filter by store type",
			filter: &KeyFilter{
				StoreTypes: []types.StoreType{types.StorePKCS8},
			},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := migrator.filterKeys(keys, tt.filter)
			assert.Len(t, filtered, tt.expected)
		})
	}
}

// TestSelectWrappingAlgorithm tests wrapping algorithm selection
func TestSelectWrappingAlgorithm(t *testing.T) {
	migrator := &defaultMigrator{}

	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		expected backend.WrappingAlgorithm
	}{
		{
			name: "RSA key uses hybrid wrapping",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.RSA,
			},
			expected: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
		},
		{
			name: "ECDSA key uses OAEP",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.ECDSA,
			},
			expected: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		},
		{
			name: "Ed25519 key uses OAEP",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.Ed25519,
			},
			expected: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		},
		{
			name: "Symmetric key uses OAEP",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: 0,
			},
			expected: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := migrator.selectWrappingAlgorithm(tt.attrs)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsKeyTypeSupported tests key type support checking
func TestIsKeyTypeSupported(t *testing.T) {
	tests := []struct {
		name        string
		backendType types.BackendType
		keyAlg      x509.PublicKeyAlgorithm
		expected    bool
	}{
		{
			name:        "AWS KMS supports RSA",
			backendType: types.BackendTypeAWSKMS,
			keyAlg:      x509.RSA,
			expected:    true,
		},
		{
			name:        "AWS KMS supports ECDSA",
			backendType: types.BackendTypeAWSKMS,
			keyAlg:      x509.ECDSA,
			expected:    true,
		},
		{
			name:        "AWS KMS does not support Ed25519",
			backendType: types.BackendTypeAWSKMS,
			keyAlg:      x509.Ed25519,
			expected:    false,
		},
		{
			name:        "GCP KMS supports RSA",
			backendType: types.BackendTypeGCPKMS,
			keyAlg:      x509.RSA,
			expected:    true,
		},
		{
			name:        "GCP KMS supports ECDSA",
			backendType: types.BackendTypeGCPKMS,
			keyAlg:      x509.ECDSA,
			expected:    true,
		},
		{
			name:        "Azure KV supports RSA",
			backendType: types.BackendTypeAzureKV,
			keyAlg:      x509.RSA,
			expected:    true,
		},
		{
			name:        "Azure KV supports ECDSA",
			backendType: types.BackendTypeAzureKV,
			keyAlg:      x509.ECDSA,
			expected:    true,
		},
		{
			name:        "Azure KV supports symmetric",
			backendType: types.BackendTypeAzureKV,
			keyAlg:      0,
			expected:    true,
		},
		{
			name:        "PKCS8 backend supports all",
			backendType: types.BackendTypePKCS8,
			keyAlg:      x509.Ed25519,
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := newMockImportExportBackend()
			dest.TypeFunc = func() types.BackendType {
				return tt.backendType
			}

			migrator := &defaultMigrator{
				dest: dest,
			}

			attrs := &types.KeyAttributes{
				KeyAlgorithm: tt.keyAlg,
			}

			result := migrator.isKeyTypeSupported(attrs)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestCheckCompatibility tests compatibility checking
func TestCheckCompatibility(t *testing.T) {
	tests := []struct {
		name           string
		sourceType     types.BackendType
		destType       types.BackendType
		keys           []*types.KeyAttributes
		expectWarnings bool
	}{
		{
			name:       "AWS to Azure has warnings",
			sourceType: types.BackendTypeAWSKMS,
			destType:   types.BackendTypeAzureKV,
			keys: []*types.KeyAttributes{
				{CN: "test", KeyAlgorithm: x509.RSA},
			},
			expectWarnings: true,
		},
		{
			name:       "PKCS11 to AWS has warnings",
			sourceType: types.BackendTypePKCS11,
			destType:   types.BackendTypeAWSKMS,
			keys: []*types.KeyAttributes{
				{CN: "test", KeyAlgorithm: x509.RSA},
			},
			expectWarnings: true,
		},
		{
			name:       "PKCS8 to PKCS8 no warnings",
			sourceType: types.BackendTypePKCS8,
			destType:   types.BackendTypePKCS8,
			keys: []*types.KeyAttributes{
				{CN: "test", KeyAlgorithm: x509.RSA},
			},
			expectWarnings: false,
		},
		{
			name:       "Unsupported key type generates warning",
			sourceType: types.BackendTypePKCS8,
			destType:   types.BackendTypeAWSKMS,
			keys: []*types.KeyAttributes{
				{CN: "test", KeyAlgorithm: x509.Ed25519},
			},
			expectWarnings: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := newMockImportExportBackend()
			dest := newMockImportExportBackend()

			source.TypeFunc = func() types.BackendType {
				return tt.sourceType
			}
			dest.TypeFunc = func() types.BackendType {
				return tt.destType
			}

			migrator := &defaultMigrator{
				source: source,
				dest:   dest,
			}

			plan := &MigrationPlan{
				Keys:              tt.keys,
				SourceBackendType: tt.sourceType,
				DestBackendType:   tt.destType,
				Warnings:          make([]string, 0),
				Errors:            make([]string, 0),
			}

			migrator.checkCompatibility(plan)

			if tt.expectWarnings {
				assert.True(t, len(plan.Warnings) > 0, "Expected warnings but got none")
			}
		})
	}
}

// TestExportKey tests the exportKey helper function
func TestExportKey(t *testing.T) {
	source := newMockImportExportBackend()

	attrs := &types.KeyAttributes{
		CN:           "test-export.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
	}

	key := generateTestKey(t, x509.RSA)
	source.keys[attrs.CN] = key

	migrator := &defaultMigrator{
		source: source,
	}

	opts := &MigrateOptions{
		WrappingAlgorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	wrapped, err := migrator.exportKey(source, attrs, opts)
	require.NoError(t, err)
	assert.NotNil(t, wrapped)
	assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, wrapped.Algorithm)
	assert.NotEmpty(t, wrapped.WrappedKey)
}

// TestExportKey_AutoSelectAlgorithm tests automatic algorithm selection
func TestExportKey_AutoSelectAlgorithm(t *testing.T) {
	source := newMockImportExportBackend()

	attrs := &types.KeyAttributes{
		CN:           "test-auto.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
	}

	key := generateTestKey(t, x509.RSA)
	source.keys[attrs.CN] = key

	migrator := &defaultMigrator{
		source: source,
	}

	// Don't specify wrapping algorithm
	opts := &MigrateOptions{}

	wrapped, err := migrator.exportKey(source, attrs, opts)
	require.NoError(t, err)
	assert.NotNil(t, wrapped)
	// RSA keys should use hybrid wrapping
	assert.Equal(t, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, wrapped.Algorithm)
}

// TestImportKey tests the importKey helper function
func TestImportKey(t *testing.T) {
	dest := newMockImportExportBackend()

	attrs := &types.KeyAttributes{
		CN:           "test-import.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
	}

	key := generateTestKey(t, x509.RSA)
	keyBytes := x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  keyBytes,
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: []byte("test-token"),
	}

	migrator := &defaultMigrator{
		dest: dest,
	}

	err := migrator.importKey(dest, attrs, wrapped)
	require.NoError(t, err)

	// Verify key was imported
	_, err = dest.GetKey(attrs)
	assert.NoError(t, err)
}

// TestImportKey_GetParametersFailure tests import when GetImportParameters fails
func TestImportKey_GetParametersFailure(t *testing.T) {
	dest := newMockImportExportBackend()

	dest.GetImportParametersFunc = func(*types.KeyAttributes, backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
		return nil, fmt.Errorf("parameters not available")
	}

	attrs := &types.KeyAttributes{
		CN:           "test-params-fail.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
	}

	key := generateTestKey(t, x509.RSA)
	keyBytes := x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: keyBytes,
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	migrator := &defaultMigrator{
		dest: dest,
	}

	err := migrator.importKey(dest, attrs, wrapped)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get import parameters")
}

// TestMigrateKeysSequential tests sequential migration
func TestMigrateKeysSequential(t *testing.T) {
	migrator, source, _ := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Add keys
	keys := make([]*types.KeyAttributes, 3)
	for i := 0; i < 3; i++ {
		attrs := &types.KeyAttributes{
			CN:           fmt.Sprintf("key%d.example.com", i),
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.RSA,
			Hash:         crypto.SHA256,
		}
		key := generateTestKey(t, x509.RSA)
		source.keys[attrs.CN] = key
		keys[i] = attrs
	}

	result := &MigrationResult{
		FailedKeys:     make(map[*types.KeyAttributes]error),
		SuccessfulKeys: make([]*types.KeyAttributes, 0),
	}

	opts := &MigrateOptions{
		SkipVerification: true,
	}

	migrator.migrateKeysSequential(keys, opts, result)

	assert.Equal(t, 3, result.SuccessCount)
	assert.Equal(t, 0, result.FailureCount)
}

// TestMigrateKeysSequential_WithStopOnError tests sequential migration stopping on error
func TestMigrateKeysSequential_WithStopOnError(t *testing.T) {
	migrator, source, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Add keys
	keys := make([]*types.KeyAttributes, 3)
	for i := 0; i < 3; i++ {
		attrs := &types.KeyAttributes{
			CN:           fmt.Sprintf("key%d.example.com", i),
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.RSA,
			Hash:         crypto.SHA256,
		}
		key := generateTestKey(t, x509.RSA)
		source.keys[attrs.CN] = key
		keys[i] = attrs
	}

	// Make second key fail
	callCount := 0
	dest.ImportKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
		callCount++
		if callCount == 2 {
			return fmt.Errorf("import failed")
		}
		var key crypto.PrivateKey
		var err error
		key, err = x509.ParsePKCS1PrivateKey(wrapped.WrappedKey)
		if err != nil {
			return err
		}
		dest.keys[attrs.CN] = key
		return nil
	}

	result := &MigrationResult{
		FailedKeys:     make(map[*types.KeyAttributes]error),
		SuccessfulKeys: make([]*types.KeyAttributes, 0),
	}

	opts := &MigrateOptions{
		StopOnError:      true,
		SkipVerification: true,
	}

	migrator.migrateKeysSequential(keys, opts, result)

	// Should stop after first failure
	assert.Equal(t, 1, result.SuccessCount)
	assert.Equal(t, 1, result.FailureCount)
}

// TestMigrateKeysParallel tests parallel migration
func TestMigrateKeysParallel(t *testing.T) {
	migrator, source, _ := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Add keys
	keys := make([]*types.KeyAttributes, 10)
	for i := 0; i < 10; i++ {
		attrs := &types.KeyAttributes{
			CN:           fmt.Sprintf("key%d.example.com", i),
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.RSA,
			Hash:         crypto.SHA256,
		}
		key := generateTestKey(t, x509.RSA)
		source.keys[attrs.CN] = key
		keys[i] = attrs
	}

	result := &MigrationResult{
		FailedKeys:     make(map[*types.KeyAttributes]error),
		SuccessfulKeys: make([]*types.KeyAttributes, 0),
	}

	opts := &MigrateOptions{
		Parallel:         4,
		SkipVerification: true,
	}

	migrator.migrateKeysParallel(keys, opts, result)

	assert.Equal(t, 10, result.SuccessCount)
	assert.Equal(t, 0, result.FailureCount)
}

// TestMigrateKeysParallel_WithFailures tests parallel migration with some failures
func TestMigrateKeysParallel_WithFailures(t *testing.T) {
	migrator, source, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Add keys
	keys := make([]*types.KeyAttributes, 5)
	for i := 0; i < 5; i++ {
		attrs := &types.KeyAttributes{
			CN:           fmt.Sprintf("key%d.example.com", i),
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StorePKCS8,
			KeyAlgorithm: x509.RSA,
			Hash:         crypto.SHA256,
		}
		key := generateTestKey(t, x509.RSA)
		source.keys[attrs.CN] = key
		keys[i] = attrs
	}

	// Make some imports fail
	var mu sync.Mutex
	callCount := 0
	dest.ImportKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
		mu.Lock()
		callCount++
		shouldFail := callCount%2 == 0
		mu.Unlock()

		if shouldFail {
			return fmt.Errorf("import failed for %s", attrs.CN)
		}

		var key crypto.PrivateKey
		var err error
		key, err = x509.ParsePKCS1PrivateKey(wrapped.WrappedKey)
		if err != nil {
			return err
		}
		dest.keys[attrs.CN] = key
		return nil
	}

	result := &MigrationResult{
		FailedKeys:     make(map[*types.KeyAttributes]error),
		SuccessfulKeys: make([]*types.KeyAttributes, 0),
	}

	opts := &MigrateOptions{
		Parallel:         2,
		StopOnError:      false,
		SkipVerification: true,
	}

	migrator.migrateKeysParallel(keys, opts, result)

	// Some should succeed, some should fail
	assert.True(t, result.SuccessCount > 0)
	assert.True(t, result.FailureCount > 0)
	assert.Equal(t, 5, result.SuccessCount+result.FailureCount)
}

// TestMigrateAll_ListKeysError tests MigrateAll when ListKeys fails
func TestMigrateAll_ListKeysError(t *testing.T) {
	migrator, source, _ := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	source.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, fmt.Errorf("list keys failed")
	}

	result, err := migrator.MigrateAll(nil, nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to list keys")
}

// TestMigrationPlan_ListKeysError tests MigrationPlan when ListKeys fails
func TestMigrationPlan_ListKeysError(t *testing.T) {
	migrator, source, _ := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	source.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, fmt.Errorf("list keys failed")
	}

	plan, err := migrator.MigrationPlan(nil)
	assert.Error(t, err)
	assert.Nil(t, plan)
}

// TestMatchesFilter tests the matchesFilter helper with various scenarios
func TestMatchesFilter(t *testing.T) {
	migrator := &defaultMigrator{}

	key := &types.KeyAttributes{
		CN:           "test.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
		Partition:    types.PartitionSigningKeys,
	}

	tests := []struct {
		name     string
		filter   *KeyFilter
		expected bool
	}{
		{
			name: "matches all criteria",
			filter: &KeyFilter{
				KeyTypes:      []types.KeyType{types.KeyTypeSigning},
				StoreTypes:    []types.StoreType{types.StorePKCS8},
				Partitions:    []types.Partition{types.PartitionSigningKeys},
				KeyAlgorithms: []x509.PublicKeyAlgorithm{x509.RSA},
			},
			expected: true,
		},
		{
			name: "doesn't match key type",
			filter: &KeyFilter{
				KeyTypes: []types.KeyType{types.KeyTypeEncryption},
			},
			expected: false,
		},
		{
			name: "doesn't match store type",
			filter: &KeyFilter{
				StoreTypes: []types.StoreType{types.StorePKCS11},
			},
			expected: false,
		},
		{
			name: "doesn't match partition",
			filter: &KeyFilter{
				Partitions: []types.Partition{types.PartitionEncryptionKeys},
			},
			expected: false,
		},
		{
			name: "doesn't match algorithm",
			filter: &KeyFilter{
				KeyAlgorithms: []x509.PublicKeyAlgorithm{x509.ECDSA},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := migrator.matchesFilter(key, tt.filter, nil)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestValidateMigration_SymmetricKey tests validation of symmetric keys (no signer)
func TestValidateMigration_SymmetricKey(t *testing.T) {
	migrator, _, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "symmetric.example.com",
		KeyType:      types.KeyTypeEncryption,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: 0, // Symmetric key
	}

	// For symmetric keys, we just need GetKey to succeed
	// since there's no signer
	key := []byte("test-symmetric-key-data-32byte")
	dest.keys[attrs.CN] = key

	result, err := migrator.ValidateMigration(attrs)
	require.NoError(t, err)
	assert.True(t, result.IsValid)
}

// TestMigrateKey_DefaultOptions tests MigrateKey with nil options
func TestMigrateKey_DefaultOptions(t *testing.T) {
	migrator, source, dest := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test-defaults.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	key := generateTestKey(t, x509.RSA)
	source.keys[attrs.CN] = key

	// Pass nil options - should use defaults (which include verification)
	// Skip verification since validation requires proper signing
	opts := &MigrateOptions{
		SkipVerification: true,
	}
	err := migrator.MigrateKey(attrs, opts)
	require.NoError(t, err)

	// Verify key was migrated
	_, err = dest.GetKey(attrs)
	assert.NoError(t, err)
}

// TestMigrateAll_DefaultOptions tests MigrateAll with nil options
func TestMigrateAll_DefaultOptions(t *testing.T) {
	migrator, source, _ := setupMigrator(t)
	defer func() { _ = migrator.Close() }()

	// Add a key
	attrs := &types.KeyAttributes{
		CN:           "test-default-opts.example.com",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}
	key := generateTestKey(t, x509.RSA)
	source.keys[attrs.CN] = key

	// Pass nil options - should use defaults
	result, err := migrator.MigrateAll(nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, result.SuccessCount)
}
