//go:build frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package frost

import (
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// mockStorageBackend implements storage.Backend for testing
type mockStorageBackend struct {
	data map[string][]byte
}

func newMockStorageBackend() *mockStorageBackend {
	return &mockStorageBackend{data: make(map[string][]byte)}
}

func (m *mockStorageBackend) Put(key string, value []byte, _ *storage.Options) error {
	m.data[key] = value
	return nil
}

func (m *mockStorageBackend) Get(key string) ([]byte, error) {
	if v, ok := m.data[key]; ok {
		return v, nil
	}
	return nil, errors.New("not found")
}

func (m *mockStorageBackend) Delete(key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockStorageBackend) Exists(key string) (bool, error) {
	_, ok := m.data[key]
	return ok, nil
}

func (m *mockStorageBackend) List(prefix string) ([]string, error) {
	var keys []string
	for k := range m.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m *mockStorageBackend) Close() error {
	return nil
}

// mockSecretBackend implements types.Backend for testing
type mockSecretBackend struct {
	data map[string][]byte
}

func newMockSecretBackend() *mockSecretBackend {
	return &mockSecretBackend{data: make(map[string][]byte)}
}

func (m *mockSecretBackend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

func (m *mockSecretBackend) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Signing: true}
}

func (m *mockSecretBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs.SealData != nil {
		m.data[attrs.CN] = attrs.SealData.Bytes()
	}
	return nil, nil
}

func (m *mockSecretBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if v, ok := m.data[attrs.CN]; ok {
		return v, nil
	}
	return nil, errors.New("not found")
}

func (m *mockSecretBackend) DeleteKey(attrs *types.KeyAttributes) error {
	delete(m.data, attrs.CN)
	return nil
}

func (m *mockSecretBackend) ListKeys() ([]*types.KeyAttributes, error) {
	return nil, nil
}

func (m *mockSecretBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, ErrNotImplemented
}

func (m *mockSecretBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, ErrNotImplemented
}

func (m *mockSecretBackend) RotateKey(attrs *types.KeyAttributes) error {
	return ErrNotImplemented
}

func (m *mockSecretBackend) Close() error {
	return nil
}

func TestConfig_Validate_Success(t *testing.T) {
	config := &Config{
		PublicStorage:    newMockStorageBackend(),
		SecretBackend:    newMockSecretBackend(),
		Algorithm:        types.FrostAlgorithmEd25519,
		DefaultThreshold: 2,
		DefaultTotal:     3,
	}

	err := config.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_MissingPublicStorage(t *testing.T) {
	config := &Config{
		SecretBackend: newMockSecretBackend(),
	}

	err := config.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfig))
	assert.Contains(t, err.Error(), "PublicStorage")
}

func TestConfig_Validate_MissingSecretBackend(t *testing.T) {
	config := &Config{
		PublicStorage: newMockStorageBackend(),
	}

	err := config.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfig))
	assert.Contains(t, err.Error(), "SecretBackend")
}

func TestConfig_Validate_InvalidAlgorithm(t *testing.T) {
	config := &Config{
		PublicStorage: newMockStorageBackend(),
		SecretBackend: newMockSecretBackend(),
		Algorithm:     "invalid-algo",
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Algorithm")
}

func TestConfig_Validate_ThresholdTooLow(t *testing.T) {
	config := &Config{
		PublicStorage:    newMockStorageBackend(),
		SecretBackend:    newMockSecretBackend(),
		DefaultThreshold: 1,
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Threshold")
	assert.Contains(t, err.Error(), "at least 2")
}

func TestConfig_Validate_TotalLessThanThreshold(t *testing.T) {
	config := &Config{
		PublicStorage:    newMockStorageBackend(),
		SecretBackend:    newMockSecretBackend(),
		DefaultThreshold: 3,
		DefaultTotal:     2,
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Total")
	assert.Contains(t, err.Error(), "Threshold")
}

func TestConfig_Validate_ThresholdTooHigh(t *testing.T) {
	config := &Config{
		PublicStorage:    newMockStorageBackend(),
		SecretBackend:    newMockSecretBackend(),
		DefaultThreshold: 256,
		DefaultTotal:     256,
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Threshold")
	assert.Contains(t, err.Error(), "255")
}

func TestConfig_Validate_TotalTooHigh(t *testing.T) {
	config := &Config{
		PublicStorage:    newMockStorageBackend(),
		SecretBackend:    newMockSecretBackend(),
		DefaultThreshold: 2,
		DefaultTotal:     256,
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Total")
	assert.Contains(t, err.Error(), "255")
}

func TestConfig_Validate_InvalidParticipantID(t *testing.T) {
	config := &Config{
		PublicStorage:    newMockStorageBackend(),
		SecretBackend:    newMockSecretBackend(),
		DefaultThreshold: 2,
		DefaultTotal:     3,
		ParticipantID:    4, // Invalid: > Total
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ParticipantID")
}

func TestConfig_Validate_ParticipantsLengthMismatch(t *testing.T) {
	config := &Config{
		PublicStorage:    newMockStorageBackend(),
		SecretBackend:    newMockSecretBackend(),
		DefaultThreshold: 2,
		DefaultTotal:     3,
		Participants:     []string{"alice", "bob"}, // Only 2, but Total is 3
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Participants")
}

func TestConfig_SetDefaults(t *testing.T) {
	config := &Config{}
	config.SetDefaults()

	assert.Equal(t, types.FrostAlgorithmEd25519, config.Algorithm)
	assert.Equal(t, 2, config.DefaultThreshold)
	assert.Equal(t, 3, config.DefaultTotal)
}

func TestConfig_SetDefaults_PreservesExisting(t *testing.T) {
	config := &Config{
		Algorithm:        types.FrostAlgorithmP256,
		DefaultThreshold: 5,
		DefaultTotal:     10,
	}
	config.SetDefaults()

	// Should preserve existing values
	assert.Equal(t, types.FrostAlgorithmP256, config.Algorithm)
	assert.Equal(t, 5, config.DefaultThreshold)
	assert.Equal(t, 10, config.DefaultTotal)
}

func TestConfig_GetNonceStorage(t *testing.T) {
	publicStorage := newMockStorageBackend()
	nonceStorage := newMockStorageBackend()

	// When NonceStorage is set, return it
	config := &Config{
		PublicStorage: publicStorage,
		NonceStorage:  nonceStorage,
	}
	assert.Equal(t, nonceStorage, config.GetNonceStorage())

	// When NonceStorage is nil, return PublicStorage
	config = &Config{
		PublicStorage: publicStorage,
	}
	assert.Equal(t, publicStorage, config.GetNonceStorage())
}

func TestConfig_GetKeyGenerator(t *testing.T) {
	// When DKG is nil, return TrustedDealer
	config := &Config{}
	gen := config.GetKeyGenerator()
	assert.NotNil(t, gen)
	_, ok := gen.(*TrustedDealer)
	assert.True(t, ok)

	// When DKG is set, return it
	customGen := &TrustedDealer{}
	config = &Config{DKG: customGen}
	assert.Equal(t, customGen, config.GetKeyGenerator())
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.Equal(t, types.FrostAlgorithmEd25519, config.Algorithm)
	assert.Equal(t, 2, config.DefaultThreshold)
	assert.Equal(t, 3, config.DefaultTotal)
	assert.True(t, config.EnableNonceTracking)
}
