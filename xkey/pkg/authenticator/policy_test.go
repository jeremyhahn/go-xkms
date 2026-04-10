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
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPolicyKey generates a 32-byte random key for testing.
func testPolicyKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

// testConfig returns a Config suitable for policy testing.
func testPolicyConfig() *Config {
	cfg := DefaultConfig()
	cfg.Storage = NewMemoryStorage()
	cfg.PINMinLength = 6
	cfg.PINMaxRetries = 5
	cfg.AlwaysUV = true
	cfg.MaxCredentials = 50
	cfg.MaxResidentCredentials = 10
	cfg.EnableCredentialManagement = true
	return cfg
}

func TestExtractPolicyFields(t *testing.T) {
	cfg := testPolicyConfig()

	pf := ExtractPolicyFields(cfg)

	assert.Equal(t, cfg.PINMinLength, pf.MinPINLength)
	assert.Equal(t, cfg.PINMaxRetries, pf.MaxPINRetries)
	assert.Equal(t, DefaultSOPINMaxRetries, pf.SOPINMaxRetries)
	assert.Equal(t, cfg.AlwaysUV, pf.AlwaysUV)
	assert.Equal(t, cfg.MaxCredentials, pf.MaxCredentials)
	assert.Equal(t, cfg.MaxResidentCredentials, pf.MaxResidentCredentials)
	assert.Equal(t, cfg.EnableCredentialManagement, pf.EnableCredentialManagement)
}

func TestExtractPolicyFields_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Storage = NewMemoryStorage()
	cfg.SetDefaults()

	pf := ExtractPolicyFields(cfg)

	assert.Equal(t, DefaultPINMinLength, pf.MinPINLength)
	assert.Equal(t, DefaultPINMaxRetries, pf.MaxPINRetries)
	assert.Equal(t, DefaultSOPINMaxRetries, pf.SOPINMaxRetries)
	assert.False(t, pf.AlwaysUV)
	assert.Equal(t, DefaultMaxCredentials, pf.MaxCredentials)
	assert.Equal(t, DefaultMaxResidentCredentials, pf.MaxResidentCredentials)
	assert.True(t, pf.EnableCredentialManagement)
}

func TestPolicyFieldsCanonical(t *testing.T) {
	pf := &PolicyFields{
		MinPINLength:               6,
		MaxPINRetries:              5,
		SOPINMaxRetries:            8,
		AlwaysUV:                   true,
		MaxCredentials:             50,
		MaxResidentCredentials:     10,
		EnableCredentialManagement: true,
	}

	data1, err := pf.Canonical()
	require.NoError(t, err)
	require.NotEmpty(t, data1)

	// Verify it produces valid JSON
	var decoded PolicyFields
	err = json.Unmarshal(data1, &decoded)
	require.NoError(t, err)
	assert.Equal(t, pf.MinPINLength, decoded.MinPINLength)
	assert.Equal(t, pf.MaxPINRetries, decoded.MaxPINRetries)
	assert.Equal(t, pf.SOPINMaxRetries, decoded.SOPINMaxRetries)
	assert.Equal(t, pf.AlwaysUV, decoded.AlwaysUV)
	assert.Equal(t, pf.MaxCredentials, decoded.MaxCredentials)
	assert.Equal(t, pf.MaxResidentCredentials, decoded.MaxResidentCredentials)
	assert.Equal(t, pf.EnableCredentialManagement, decoded.EnableCredentialManagement)

	// Verify deterministic output
	data2, err := pf.Canonical()
	require.NoError(t, err)
	assert.Equal(t, data1, data2)
}

func TestPolicyFieldsCanonical_NilReceiver(t *testing.T) {
	var pf *PolicyFields
	data, err := pf.Canonical()
	assert.Nil(t, data)
	assert.ErrorIs(t, err, ErrPolicySignFailed)
}

func TestSoftwarePolicyProvider_SignVerify(t *testing.T) {
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	canonical := []byte(`{"minPINLength":6,"maxPINRetries":5}`)

	tag, err := provider.Sign(canonical)
	require.NoError(t, err)
	require.Len(t, tag, 32) // SHA-256 HMAC output is 32 bytes

	err = provider.Verify(canonical, tag)
	assert.NoError(t, err)
}

func TestSoftwarePolicyProvider_VerifyTampered(t *testing.T) {
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	canonical := []byte(`{"minPINLength":6,"maxPINRetries":5}`)
	tag, err := provider.Sign(canonical)
	require.NoError(t, err)

	// Modify the canonical data
	tampered := []byte(`{"minPINLength":4,"maxPINRetries":5}`)
	err = provider.Verify(tampered, tag)
	assert.ErrorIs(t, err, ErrPolicyTampered)
}

func TestSoftwarePolicyProvider_VerifyCorruptedTag(t *testing.T) {
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	canonical := []byte(`{"minPINLength":6}`)
	tag, err := provider.Sign(canonical)
	require.NoError(t, err)

	// Corrupt the tag
	corruptedTag := make([]byte, len(tag))
	copy(corruptedTag, tag)
	corruptedTag[0] ^= 0xFF

	err = provider.Verify(canonical, corruptedTag)
	assert.ErrorIs(t, err, ErrPolicyTampered)
}

func TestSoftwarePolicyProvider_SignNilCanonical(t *testing.T) {
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	tag, err := provider.Sign(nil)
	assert.Nil(t, tag)
	assert.ErrorIs(t, err, ErrPolicySignFailed)
}

func TestSoftwarePolicyProvider_VerifyNilInputs(t *testing.T) {
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	err = provider.Verify(nil, []byte("tag"))
	assert.ErrorIs(t, err, ErrPolicyVerifyFailed)

	err = provider.Verify([]byte("data"), nil)
	assert.ErrorIs(t, err, ErrPolicyVerifyFailed)
}

func TestSoftwarePolicyProvider_InvalidKey(t *testing.T) {
	shortKey := make([]byte, 16) // Less than 32 bytes
	provider, err := NewSoftwarePolicyProvider(shortKey)
	assert.Nil(t, provider)
	assert.ErrorIs(t, err, ErrPolicyKeyTooShort)
}

func TestSoftwarePolicyProvider_MinimumKeyLength(t *testing.T) {
	key := make([]byte, 32) // Exactly 32 bytes
	_, err := rand.Read(key)
	require.NoError(t, err)

	provider, err := NewSoftwarePolicyProvider(key)
	assert.NotNil(t, provider)
	assert.NoError(t, err)
}

func TestSoftwarePolicyProvider_KeyIsCopied(t *testing.T) {
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	canonical := []byte(`{"test":"data"}`)
	tag, err := provider.Sign(canonical)
	require.NoError(t, err)

	// Modify the original key
	key[0] ^= 0xFF

	// Verification should still succeed because the provider copied the key
	err = provider.Verify(canonical, tag)
	assert.NoError(t, err)
}

func TestSoftwarePolicyProvider_DifferentKeysProduceDifferentTags(t *testing.T) {
	key1 := testPolicyKey(t)
	key2 := testPolicyKey(t)

	provider1, err := NewSoftwarePolicyProvider(key1)
	require.NoError(t, err)
	provider2, err := NewSoftwarePolicyProvider(key2)
	require.NoError(t, err)

	canonical := []byte(`{"minPINLength":6}`)

	tag1, err := provider1.Sign(canonical)
	require.NoError(t, err)
	tag2, err := provider2.Sign(canonical)
	require.NoError(t, err)

	assert.NotEqual(t, tag1, tag2)

	// Cross-verification should fail
	err = provider1.Verify(canonical, tag2)
	assert.ErrorIs(t, err, ErrPolicyTampered)
}

func TestPolicyManager_Sign(t *testing.T) {
	cfg := testPolicyConfig()
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	pm := NewPolicyManager(cfg, provider)
	state := NewAuthenticatorState()

	err = pm.Sign(state)
	require.NoError(t, err)

	assert.NotEmpty(t, state.PolicyHMACTag)
	assert.Len(t, state.PolicyHMACTag, 32)
	assert.NotNil(t, state.SignedPolicyFields)
	assert.Equal(t, cfg.PINMinLength, state.SignedPolicyFields.MinPINLength)
	assert.Equal(t, cfg.PINMaxRetries, state.SignedPolicyFields.MaxPINRetries)
	assert.Equal(t, cfg.AlwaysUV, state.SignedPolicyFields.AlwaysUV)
	assert.Equal(t, cfg.MaxCredentials, state.SignedPolicyFields.MaxCredentials)
	assert.Equal(t, cfg.MaxResidentCredentials, state.SignedPolicyFields.MaxResidentCredentials)
	assert.Equal(t, cfg.EnableCredentialManagement, state.SignedPolicyFields.EnableCredentialManagement)
}

func TestPolicyManager_Verify(t *testing.T) {
	cfg := testPolicyConfig()
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	pm := NewPolicyManager(cfg, provider)
	state := NewAuthenticatorState()

	// Sign the policy
	err = pm.Sign(state)
	require.NoError(t, err)

	// Verify should succeed
	diag, err := pm.Verify(state)
	require.NoError(t, err)
	assert.True(t, diag.Valid)
	assert.Empty(t, diag.Mismatches)
}

func TestPolicyManager_VerifyTampered(t *testing.T) {
	cfg := testPolicyConfig()
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	pm := NewPolicyManager(cfg, provider)
	state := NewAuthenticatorState()

	// Sign the policy
	err = pm.Sign(state)
	require.NoError(t, err)

	// Tamper with the config
	cfg.PINMinLength = 8
	cfg.AlwaysUV = false

	// Verify should detect tampering
	diag, err := pm.Verify(state)
	assert.ErrorIs(t, err, ErrPolicyTampered)
	assert.NotNil(t, diag)
	assert.False(t, diag.Valid)

	// Verify mismatches identify the changed fields
	assert.GreaterOrEqual(t, len(diag.Mismatches), 2)
	fieldNames := make(map[string]bool)
	for _, m := range diag.Mismatches {
		fieldNames[m.Field] = true
	}
	assert.True(t, fieldNames["minPINLength"])
	assert.True(t, fieldNames["alwaysUV"])
}

func TestPolicyManager_VerifyMissingHMAC(t *testing.T) {
	cfg := testPolicyConfig()
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	pm := NewPolicyManager(cfg, provider)
	state := NewAuthenticatorState()

	// State has no HMAC tag
	diag, err := pm.Verify(state)
	assert.ErrorIs(t, err, ErrPolicyHMACMissing)
	assert.Nil(t, diag)
}

func TestPolicyManager_VerifyCorruptedHMAC(t *testing.T) {
	cfg := testPolicyConfig()
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	pm := NewPolicyManager(cfg, provider)
	state := NewAuthenticatorState()

	// Sign, then corrupt the tag
	err = pm.Sign(state)
	require.NoError(t, err)
	state.PolicyHMACTag[0] ^= 0xFF

	// Verify should detect corruption
	diag, err := pm.Verify(state)
	assert.ErrorIs(t, err, ErrPolicyTampered)
	assert.NotNil(t, diag)
	assert.False(t, diag.Valid)
}

func TestPolicyManager_SignThenModifyThenReSign(t *testing.T) {
	cfg := testPolicyConfig()
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	pm := NewPolicyManager(cfg, provider)
	state := NewAuthenticatorState()

	// Sign initial policy
	err = pm.Sign(state)
	require.NoError(t, err)
	originalTag := make([]byte, len(state.PolicyHMACTag))
	copy(originalTag, state.PolicyHMACTag)

	// Modify config (SO operation)
	cfg.PINMinLength = 8

	// Re-sign with new config
	err = pm.Sign(state)
	require.NoError(t, err)
	assert.NotEqual(t, originalTag, state.PolicyHMACTag)
	assert.Equal(t, 8, state.SignedPolicyFields.MinPINLength)

	// Verify should succeed with new tag
	diag, err := pm.Verify(state)
	require.NoError(t, err)
	assert.True(t, diag.Valid)
}

func TestComputeMismatches(t *testing.T) {
	current := &PolicyFields{
		MinPINLength:               8,
		MaxPINRetries:              10,
		SOPINMaxRetries:            5,
		AlwaysUV:                   true,
		MaxCredentials:             200,
		MaxResidentCredentials:     50,
		EnableCredentialManagement: false,
	}

	signed := &PolicyFields{
		MinPINLength:               6,
		MaxPINRetries:              8,
		SOPINMaxRetries:            8,
		AlwaysUV:                   false,
		MaxCredentials:             100,
		MaxResidentCredentials:     25,
		EnableCredentialManagement: true,
	}

	mismatches := computeMismatches(current, signed)

	assert.Len(t, mismatches, 7) // All fields differ

	fieldMap := make(map[string]PolicyMismatch)
	for _, m := range mismatches {
		fieldMap[m.Field] = m
	}

	assert.Equal(t, 6, fieldMap["minPINLength"].Expected)
	assert.Equal(t, 8, fieldMap["minPINLength"].Actual)

	assert.Equal(t, 8, fieldMap["maxPINRetries"].Expected)
	assert.Equal(t, 10, fieldMap["maxPINRetries"].Actual)

	assert.Equal(t, 8, fieldMap["soPINMaxRetries"].Expected)
	assert.Equal(t, 5, fieldMap["soPINMaxRetries"].Actual)

	assert.Equal(t, false, fieldMap["alwaysUV"].Expected)
	assert.Equal(t, true, fieldMap["alwaysUV"].Actual)

	assert.Equal(t, 100, fieldMap["maxCredentials"].Expected)
	assert.Equal(t, 200, fieldMap["maxCredentials"].Actual)

	assert.Equal(t, 25, fieldMap["maxResidentCredentials"].Expected)
	assert.Equal(t, 50, fieldMap["maxResidentCredentials"].Actual)

	assert.Equal(t, true, fieldMap["enableCredentialManagement"].Expected)
	assert.Equal(t, false, fieldMap["enableCredentialManagement"].Actual)
}

func TestComputeMismatches_NoChanges(t *testing.T) {
	pf := &PolicyFields{
		MinPINLength:               6,
		MaxPINRetries:              8,
		SOPINMaxRetries:            8,
		AlwaysUV:                   false,
		MaxCredentials:             100,
		MaxResidentCredentials:     25,
		EnableCredentialManagement: true,
	}

	mismatches := computeMismatches(pf, pf)
	assert.Empty(t, mismatches)
}

func TestComputeMismatches_NilSigned(t *testing.T) {
	current := &PolicyFields{MinPINLength: 6}
	mismatches := computeMismatches(current, nil)
	assert.Nil(t, mismatches)
}

func TestComputeMismatches_SingleFieldChange(t *testing.T) {
	tests := []struct {
		name     string
		modify   func(*PolicyFields)
		expected string
	}{
		{
			name:     "MinPINLength",
			modify:   func(pf *PolicyFields) { pf.MinPINLength = 99 },
			expected: "minPINLength",
		},
		{
			name:     "MaxPINRetries",
			modify:   func(pf *PolicyFields) { pf.MaxPINRetries = 99 },
			expected: "maxPINRetries",
		},
		{
			name:     "SOPINMaxRetries",
			modify:   func(pf *PolicyFields) { pf.SOPINMaxRetries = 99 },
			expected: "soPINMaxRetries",
		},
		{
			name:     "AlwaysUV",
			modify:   func(pf *PolicyFields) { pf.AlwaysUV = true },
			expected: "alwaysUV",
		},
		{
			name:     "MaxCredentials",
			modify:   func(pf *PolicyFields) { pf.MaxCredentials = 999 },
			expected: "maxCredentials",
		},
		{
			name:     "MaxResidentCredentials",
			modify:   func(pf *PolicyFields) { pf.MaxResidentCredentials = 999 },
			expected: "maxResidentCredentials",
		},
		{
			name:     "EnableCredentialManagement",
			modify:   func(pf *PolicyFields) { pf.EnableCredentialManagement = false },
			expected: "enableCredentialManagement",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed := &PolicyFields{
				MinPINLength:               6,
				MaxPINRetries:              8,
				SOPINMaxRetries:            8,
				AlwaysUV:                   false,
				MaxCredentials:             100,
				MaxResidentCredentials:     25,
				EnableCredentialManagement: true,
			}

			// Create a copy for current, then modify
			current := *signed
			tt.modify(&current)

			mismatches := computeMismatches(&current, signed)
			require.Len(t, mismatches, 1)
			assert.Equal(t, tt.expected, mismatches[0].Field)
		})
	}
}

func TestPolicyDiagnostics_Mismatches(t *testing.T) {
	cfg := testPolicyConfig()
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	pm := NewPolicyManager(cfg, provider)
	state := NewAuthenticatorState()

	// Sign policy
	err = pm.Sign(state)
	require.NoError(t, err)

	// Tamper with MaxCredentials in config
	cfg.MaxCredentials = 999

	diag, err := pm.Verify(state)
	assert.ErrorIs(t, err, ErrPolicyTampered)
	require.NotNil(t, diag)
	assert.False(t, diag.Valid)

	// Find the maxCredentials mismatch
	found := false
	for _, m := range diag.Mismatches {
		if m.Field == "maxCredentials" {
			found = true
			assert.Equal(t, 50, m.Expected) // Original config value
			assert.Equal(t, 999, m.Actual)  // Tampered value
		}
	}
	assert.True(t, found, "expected maxCredentials mismatch in diagnostics")
}

func TestPolicyIntegration_AuthenticatorStartup(t *testing.T) {
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	storage := NewMemoryStorage()

	// Create authenticator with policy provider
	cfg := DefaultConfig()
	cfg.Storage = storage
	cfg.PolicyIntegrityProvider = provider

	auth, err := NewAuthenticator(cfg)
	require.NoError(t, err)
	defer auth.Close()

	// No tamper detected (no HMAC tag in fresh state)
	assert.False(t, auth.TamperDetected.Load())
	assert.NotNil(t, auth.PolicyManager())
}

func TestPolicyIntegration_TamperDetectedOnStartup(t *testing.T) {
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	storage := NewMemoryStorage()

	// Create and sign policy with initial config
	cfg := DefaultConfig()
	cfg.Storage = storage
	cfg.PolicyIntegrityProvider = provider

	auth, err := NewAuthenticator(cfg)
	require.NoError(t, err)

	// Sign the policy
	err = auth.PolicyManager().Sign(auth.state)
	require.NoError(t, err)

	// Save state
	err = storage.SaveState(auth.state)
	require.NoError(t, err)
	auth.Close()

	// Tamper: create a new authenticator with modified config
	cfg2 := DefaultConfig()
	cfg2.Storage = storage
	cfg2.PolicyIntegrityProvider = provider
	cfg2.PINMinLength = 12 // Changed from default

	auth2, err := NewAuthenticator(cfg2)
	require.NoError(t, err)
	defer auth2.Close()

	// Tamper should be detected
	assert.True(t, auth2.TamperDetected.Load())
}

func TestPolicyIntegration_NilProviderDisablesChecking(t *testing.T) {
	storage := NewMemoryStorage()

	cfg := DefaultConfig()
	cfg.Storage = storage
	// No PolicyIntegrityProvider set

	auth, err := NewAuthenticator(cfg)
	require.NoError(t, err)
	defer auth.Close()

	assert.Nil(t, auth.PolicyManager())
	assert.False(t, auth.TamperDetected.Load())
}

func TestPolicySerializationRoundTrip(t *testing.T) {
	state := NewAuthenticatorState()
	state.PolicyHMACTag = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	state.SignedPolicyFields = &PolicyFields{
		MinPINLength:               6,
		MaxPINRetries:              8,
		SOPINMaxRetries:            8,
		AlwaysUV:                   true,
		MaxCredentials:             100,
		MaxResidentCredentials:     25,
		EnableCredentialManagement: true,
	}

	// Serialize
	serializable, err := stateToSerializable(state)
	require.NoError(t, err)
	assert.Equal(t, state.PolicyHMACTag, serializable.PolicyHMACTag)
	assert.NotNil(t, serializable.SignedPolicyFields)
	assert.Equal(t, 6, serializable.SignedPolicyFields.MinPINLength)

	// Deserialize
	restored, err := serializableToState(serializable)
	require.NoError(t, err)
	assert.Equal(t, state.PolicyHMACTag, restored.PolicyHMACTag)
	require.NotNil(t, restored.SignedPolicyFields)
	assert.Equal(t, state.SignedPolicyFields.MinPINLength, restored.SignedPolicyFields.MinPINLength)
	assert.Equal(t, state.SignedPolicyFields.MaxPINRetries, restored.SignedPolicyFields.MaxPINRetries)
	assert.Equal(t, state.SignedPolicyFields.SOPINMaxRetries, restored.SignedPolicyFields.SOPINMaxRetries)
	assert.Equal(t, state.SignedPolicyFields.AlwaysUV, restored.SignedPolicyFields.AlwaysUV)
	assert.Equal(t, state.SignedPolicyFields.MaxCredentials, restored.SignedPolicyFields.MaxCredentials)
	assert.Equal(t, state.SignedPolicyFields.MaxResidentCredentials, restored.SignedPolicyFields.MaxResidentCredentials)
	assert.Equal(t, state.SignedPolicyFields.EnableCredentialManagement, restored.SignedPolicyFields.EnableCredentialManagement)
}

func TestPolicySerializationRoundTrip_NilFields(t *testing.T) {
	state := NewAuthenticatorState()
	// No policy fields set

	serializable, err := stateToSerializable(state)
	require.NoError(t, err)
	assert.Nil(t, serializable.PolicyHMACTag)
	assert.Nil(t, serializable.SignedPolicyFields)

	restored, err := serializableToState(serializable)
	require.NoError(t, err)
	assert.Nil(t, restored.PolicyHMACTag)
	assert.Nil(t, restored.SignedPolicyFields)
}

func TestPolicyMemoryStorageCopy(t *testing.T) {
	storage := NewMemoryStorage()

	state := NewAuthenticatorState()
	state.PolicyHMACTag = []byte{0xAA, 0xBB, 0xCC}
	state.SignedPolicyFields = &PolicyFields{
		MinPINLength:   6,
		MaxCredentials: 100,
	}

	err := storage.SaveState(state)
	require.NoError(t, err)

	// Modify original after saving
	state.PolicyHMACTag[0] = 0xFF
	state.SignedPolicyFields.MinPINLength = 99

	// Load should return the saved values, not modified ones
	loaded, err := storage.LoadState()
	require.NoError(t, err)
	assert.Equal(t, byte(0xAA), loaded.PolicyHMACTag[0])
	assert.Equal(t, 6, loaded.SignedPolicyFields.MinPINLength)
}

func TestErrorToStatus_PolicyTampered(t *testing.T) {
	status := errorToStatus(ErrPolicyTampered)
	assert.Equal(t, byte(StatusIntegrityFailure), status)
}

// failingProvider is a test provider that always returns errors.
type failingProvider struct{}

func (f *failingProvider) Sign(canonical []byte) ([]byte, error) {
	return nil, errors.New("authenticator: sign operation failed")
}

func (f *failingProvider) Verify(canonical, tag []byte) error {
	return errors.New("authenticator: verify operation failed")
}

func TestPolicyManager_SignWithFailingProvider(t *testing.T) {
	cfg := testPolicyConfig()
	pm := NewPolicyManager(cfg, &failingProvider{})
	state := NewAuthenticatorState()

	err := pm.Sign(state)
	assert.Error(t, err)
	assert.Empty(t, state.PolicyHMACTag)
}

func TestPolicyManager_VerifyWithFailingProvider(t *testing.T) {
	cfg := testPolicyConfig()
	pm := NewPolicyManager(cfg, &failingProvider{})
	state := NewAuthenticatorState()
	state.PolicyHMACTag = []byte{1, 2, 3} // Non-empty tag

	diag, err := pm.Verify(state)
	assert.Error(t, err)
	assert.Nil(t, diag)
}

func TestPolicyFieldsCanonical_DeterministicAcrossInstances(t *testing.T) {
	// Two separate instances with identical values should produce identical output
	pf1 := &PolicyFields{
		MinPINLength:               6,
		MaxPINRetries:              8,
		SOPINMaxRetries:            8,
		AlwaysUV:                   true,
		MaxCredentials:             100,
		MaxResidentCredentials:     25,
		EnableCredentialManagement: true,
	}

	pf2 := &PolicyFields{
		MinPINLength:               6,
		MaxPINRetries:              8,
		SOPINMaxRetries:            8,
		AlwaysUV:                   true,
		MaxCredentials:             100,
		MaxResidentCredentials:     25,
		EnableCredentialManagement: true,
	}

	data1, err := pf1.Canonical()
	require.NoError(t, err)

	data2, err := pf2.Canonical()
	require.NoError(t, err)

	assert.Equal(t, data1, data2)
}

func TestSoftwarePolicyProvider_EmptyCanonical(t *testing.T) {
	key := testPolicyKey(t)
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	// Empty but non-nil canonical should work
	tag, err := provider.Sign([]byte{})
	require.NoError(t, err)
	require.NotEmpty(t, tag)

	err = provider.Verify([]byte{}, tag)
	assert.NoError(t, err)
}

func TestSoftwarePolicyProvider_LargeKey(t *testing.T) {
	// Keys larger than 32 bytes should also work
	key := make([]byte, 64)
	_, err := rand.Read(key)
	require.NoError(t, err)

	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	canonical := []byte(`{"test":"data"}`)
	tag, err := provider.Sign(canonical)
	require.NoError(t, err)

	err = provider.Verify(canonical, tag)
	assert.NoError(t, err)
}
