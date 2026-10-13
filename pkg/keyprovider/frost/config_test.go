//go:build frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package frost

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// errMockUnimplemented is returned by mockSecretBackend methods that this
// test double never exercises.
var errMockUnimplemented = errors.New("mock: not implemented")

// errMockSealed is returned by Unseal when the sealed data was not produced
// by this mock's Seal (wrong backend marker or corrupt payload), standing in
// for a real backend's "wrong or missing wrapping key" failure.
var errMockSealed = errors.New("mock: sealed data not recognized")

// mockSecretBackend implements types.SealingKeyProvider for testing: a
// types.Sealer (Seal/Unseal/CanSeal, an in-memory stand-in for a real
// backend's encryption) plus the types.KeyProvider methods FrostBackend
// calls directly (Type/Capabilities).
//
// sealErr and unsealErr, when set, are returned by Seal/Unseal
// unconditionally — standing in for a secret backend whose seal/unseal
// failed, letting tests confirm a retried KeyStore.StoreKeyPackage /
// DeleteKey resumes correctly, and that a wrong/missing wrapping key
// surfaces as a typed error.
type mockSecretBackend struct {
	sealErr   error
	unsealErr error
	canSeal   bool
}

func newMockSecretBackend() *mockSecretBackend {
	return &mockSecretBackend{canSeal: true}
}

func (m *mockSecretBackend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

func (m *mockSecretBackend) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Signing: true, Sealing: true}
}

func (m *mockSecretBackend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errMockUnimplemented
}

func (m *mockSecretBackend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrKeyNotFound
}

func (m *mockSecretBackend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return errMockUnimplemented
}

func (m *mockSecretBackend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	return nil, nil
}

func (m *mockSecretBackend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errMockUnimplemented
}

func (m *mockSecretBackend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errMockUnimplemented
}

func (m *mockSecretBackend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return errMockUnimplemented
}

func (m *mockSecretBackend) Close() error {
	return nil
}

// CanSeal reports whether this mock is configured to support sealing.
// Defaults to true (see newMockSecretBackend); a test that needs a
// Sealer reporting false constructs a mockSecretBackend literal directly.
func (m *mockSecretBackend) CanSeal() bool {
	return m.canSeal
}

// Seal "encrypts" data by prefixing it with a fixed marker, so Unseal can
// detect payloads it did not produce (the "wrong wrapping key" case) without
// a real cipher.
func (m *mockSecretBackend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	ciphertext := append([]byte("mock-sealed:"), data...)
	return &types.SealedData{
		Backend:    types.BackendTypeSoftware,
		Ciphertext: ciphertext,
	}, nil
}

// Unseal reverses Seal, returning errMockSealed for any payload lacking the
// marker Seal writes (simulating a wrong or missing wrapping key).
func (m *mockSecretBackend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	if sealed == nil {
		return nil, errMockSealed
	}
	const marker = "mock-sealed:"
	if len(sealed.Ciphertext) < len(marker) || string(sealed.Ciphertext[:len(marker)]) != marker {
		return nil, errMockSealed
	}
	return sealed.Ciphertext[len(marker):], nil
}

func TestConfig_Validate_Success(t *testing.T) {
	config := &Config{
		DAOs:             testutil.NewMemoryDAOFactory(),
		SecretBackend:    newMockSecretBackend(),
		Algorithm:        types.FrostAlgorithmEd25519,
		DefaultThreshold: 2,
		DefaultTotal:     3,
	}

	err := config.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_MissingDAOs(t *testing.T) {
	config := &Config{
		SecretBackend: newMockSecretBackend(),
	}

	err := config.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfig))
	var configErr *ConfigError
	require.ErrorAs(t, err, &configErr)
	assert.Equal(t, "DAOs", configErr.Field)
}

func TestConfig_Validate_MissingSecretBackend(t *testing.T) {
	config := &Config{
		DAOs: testutil.NewMemoryDAOFactory(),
	}

	err := config.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfig))
	assert.Contains(t, err.Error(), "SecretBackend")
}

func TestConfig_Validate_InvalidAlgorithm(t *testing.T) {
	config := &Config{
		DAOs:          testutil.NewMemoryDAOFactory(),
		SecretBackend: newMockSecretBackend(),
		Algorithm:     "invalid-algo",
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Algorithm")
}

func TestConfig_Validate_ThresholdTooLow(t *testing.T) {
	config := &Config{
		DAOs:             testutil.NewMemoryDAOFactory(),
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
		DAOs:             testutil.NewMemoryDAOFactory(),
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
		DAOs:             testutil.NewMemoryDAOFactory(),
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
		DAOs:             testutil.NewMemoryDAOFactory(),
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
		DAOs:             testutil.NewMemoryDAOFactory(),
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
		DAOs:             testutil.NewMemoryDAOFactory(),
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
