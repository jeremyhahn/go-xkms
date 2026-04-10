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

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// createTestAgentWithMock creates a XKMSAgent with a mock client for testing.
func createTestAgentWithMock(t *testing.T, mockClient *MockClient, touchHandler TouchHandler, requireTouch bool) *XKMSAgent {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if touchHandler == nil {
		touchHandler = &NoOpTouchHandler{}
	}

	return &XKMSAgent{
		client:       mockClient,
		backend:      "software",
		requireTouch: requireTouch,
		touchHandler: touchHandler,
		logger:       logger,
		keyCache:     make(map[string]*cachedKey),
	}
}

func TestNoOpTouchHandler(t *testing.T) {
	handler := &NoOpTouchHandler{}

	err := handler.RequestTouch(nil, "test-op", "test-key")
	assert.NoError(t, err)
}

func TestNoOpTouchHandler_WithContext(t *testing.T) {
	handler := &NoOpTouchHandler{}

	ctx := context.Background()
	err := handler.RequestTouch(ctx, "ssh-sign", "my-key-id")
	assert.NoError(t, err)
}

func TestDefaultSocketPath(t *testing.T) {
	path := DefaultSocketPath()
	require.NotEmpty(t, path)

	// Should contain "xkey" in the path
	assert.Contains(t, path, "xkey")
	// Should end with .sock
	assert.Contains(t, path, "ssh-agent.sock")
}

func TestSSHSupportedAlgorithms(t *testing.T) {
	// Verify the supported algorithms list contains expected values
	assert.Contains(t, SSHSupportedAlgorithms, types.AlgorithmEd25519)
	assert.Contains(t, SSHSupportedAlgorithms, types.AlgorithmRSA)
	assert.Contains(t, SSHSupportedAlgorithms, types.AlgorithmECDSA)

	// DSA should NOT be in the list (deprecated)
	assert.NotContains(t, SSHSupportedAlgorithms, types.AlgorithmDSA)

	// Symmetric algorithms should NOT be in the list
	assert.NotContains(t, SSHSupportedAlgorithms, types.AlgorithmAES)
	assert.NotContains(t, SSHSupportedAlgorithms, types.AlgorithmSymmetric)
}

func TestIsSSHSupportedAlgorithm(t *testing.T) {
	// Test with typed constants - the correct way
	assert.True(t, IsSSHSupportedAlgorithm(types.AlgorithmEd25519))
	assert.True(t, IsSSHSupportedAlgorithm(types.AlgorithmRSA))
	assert.True(t, IsSSHSupportedAlgorithm(types.AlgorithmECDSA))

	// Symmetric algorithms are NOT supported by SSH
	assert.False(t, IsSSHSupportedAlgorithm(types.AlgorithmAES))
	assert.False(t, IsSSHSupportedAlgorithm(types.AlgorithmSymmetric))

	// DSA is deprecated and not supported
	assert.False(t, IsSSHSupportedAlgorithm(types.AlgorithmDSA))
}

func TestIsSSHCompatible(t *testing.T) {
	// Test the string-based wrapper function that handles SDK responses
	tests := []struct {
		keyType    string
		compatible bool
		reason     string
	}{
		// Ed25519 variants
		{"ed25519", true, "Ed25519 is SSH-supported"},
		{"Ed25519", true, "Ed25519 case-insensitive"},
		{"ED25519", true, "Ed25519 uppercase"},

		// RSA variants
		{"rsa", true, "RSA is SSH-supported"},
		{"RSA", true, "RSA uppercase"},

		// ECDSA variants (including curve-specific from xkmsd)
		{"ecdsa", true, "ECDSA is SSH-supported"},
		{"ECDSA", true, "ECDSA uppercase"},
		{"ecdsa-p256", true, "ECDSA P-256 curve"},
		{"ecdsa-p384", true, "ECDSA P-384 curve"},
		{"ecdsa-p521", true, "ECDSA P-521 curve"},
		{"ECDSA-P256", true, "ECDSA P-256 uppercase"},

		// Symmetric algorithms - NOT supported by SSH
		{"aes", false, "AES is symmetric, not SSH-supported"},
		{"AES", false, "AES uppercase"},
		{"aes-256-gcm", false, "AES-GCM variant"},
		{"hmac", false, "HMAC is symmetric"},
		{"chacha20", false, "ChaCha20 is symmetric"},

		// Other unsupported types
		{"unknown", false, "Unknown algorithm"},
		{"", false, "Empty string"},
		{"x25519", false, "X25519 is key exchange, not signing"},
	}

	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			result := isSSHCompatible(tt.keyType)
			assert.Equal(t, tt.compatible, result, tt.reason)
		})
	}
}

func TestDetermineSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		keyType  string
		flags    agent.SignatureFlags
		expected string
	}{
		{"ed25519", "ssh-ed25519", 0, "ed25519"},
		{"rsa-default", "ssh-rsa", 0, "rsa-sha256"},
		{"rsa-sha256", "ssh-rsa", agent.SignatureFlagRsaSha256, "rsa-sha256"},
		{"rsa-sha512", "ssh-rsa", agent.SignatureFlagRsaSha512, "rsa-sha512"},
		{"ecdsa-p256", "ecdsa-sha2-nistp256", 0, "ecdsa-sha256"},
		{"ecdsa-p384", "ecdsa-sha2-nistp384", 0, "ecdsa-sha384"},
		{"ecdsa-p521", "ecdsa-sha2-nistp521", 0, "ecdsa-sha512"},
		{"unknown", "unknown-type", 0, "raw"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineSignatureAlgorithm(tt.keyType, tt.flags)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSignatureFormat(t *testing.T) {
	tests := []struct {
		name     string
		keyType  string
		flags    agent.SignatureFlags
		expected string
	}{
		{"ed25519", "ssh-ed25519", 0, "ssh-ed25519"},
		{"rsa-default", "ssh-rsa", 0, "rsa-sha2-256"},
		{"rsa-sha256", "ssh-rsa", agent.SignatureFlagRsaSha256, "rsa-sha2-256"},
		{"rsa-sha512", "ssh-rsa", agent.SignatureFlagRsaSha512, "rsa-sha2-512"},
		{"ecdsa-p256", "ecdsa-sha2-nistp256", 0, "ecdsa-sha2-nistp256"},
		{"ecdsa-p384", "ecdsa-sha2-nistp384", 0, "ecdsa-sha2-nistp384"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := signatureFormat(tt.keyType, tt.flags)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewAgentRequiresConfig(t *testing.T) {
	_, err := New(nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentConnectionFailed)
}

func TestNewAgentInvalidURL(t *testing.T) {
	_, err := New(&Config{
		XKMSURL: "invalid://not-a-real-url",
		Backend: "software",
	})
	// Should fail to connect
	assert.Error(t, err)
}

func TestAgentList_Empty(t *testing.T) {
	mockClient := NewMockClient()
	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestAgentList_WithEd25519Key(t *testing.T) {
	mockClient := NewMockClient()
	err := mockClient.AddEd25519Key("software", "test-ed25519-key")
	require.NoError(t, err)

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	assert.Equal(t, ssh.KeyAlgoED25519, keys[0].Format)
	assert.Equal(t, "test-ed25519-key", keys[0].Comment)
}

func TestAgentList_WithRSAKey(t *testing.T) {
	mockClient := NewMockClient()
	err := mockClient.AddRSAKey("software", "test-rsa-key", 2048)
	require.NoError(t, err)

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	assert.Equal(t, ssh.KeyAlgoRSA, keys[0].Format)
	assert.Equal(t, "test-rsa-key", keys[0].Comment)
}

func TestAgentList_WithECDSAKey(t *testing.T) {
	tests := []struct {
		name        string
		curve       elliptic.Curve
		expectedAlg string
	}{
		{"P256", elliptic.P256(), ssh.KeyAlgoECDSA256},
		{"P384", elliptic.P384(), ssh.KeyAlgoECDSA384},
		{"P521", elliptic.P521(), ssh.KeyAlgoECDSA521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := NewMockClient()
			err := mockClient.AddECDSAKey("software", "test-ecdsa-key", tt.curve)
			require.NoError(t, err)

			ag := createTestAgentWithMock(t, mockClient, nil, false)

			keys, err := ag.List()
			require.NoError(t, err)
			require.Len(t, keys, 1)

			assert.Equal(t, tt.expectedAlg, keys[0].Format)
		})
	}
}

func TestAgentList_MultipleKeys(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "key1"))
	require.NoError(t, mockClient.AddRSAKey("software", "key2", 2048))
	require.NoError(t, mockClient.AddECDSAKey("software", "key3", elliptic.P256()))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	assert.Len(t, keys, 3)
}

func TestAgentList_WhenLocked(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	// Lock the agent
	err := ag.Lock([]byte("passphrase"))
	require.NoError(t, err)

	// List should return empty when locked (per SSH agent spec)
	keys, err := ag.List()
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Unlock and verify keys are visible again
	err = ag.Unlock([]byte("passphrase"))
	require.NoError(t, err)

	keys, err = ag.List()
	require.NoError(t, err)
	assert.Len(t, keys, 1)
}

func TestAgentList_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.SetListError(errors.New("list failed"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentKeyNotFound)
	assert.Nil(t, keys)
}

func TestAgentList_SkipsUnsupportedKeyTypes(t *testing.T) {
	mockClient := NewMockClient()
	// Add an unsupported key type
	mockClient.AddKeyWithType("software", "aes-key", "aes")
	// Add a supported key type
	require.NoError(t, mockClient.AddEd25519Key("software", "ed25519-key"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	// Should only return the Ed25519 key, not the AES key
	assert.Len(t, keys, 1)
	assert.Equal(t, "ed25519-key", keys[0].Comment)
}

func TestAgentList_SkipsKeysWithInvalidPEM(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.AddKeyWithInvalidPEM("software", "invalid-key", "ed25519")
	require.NoError(t, mockClient.AddEd25519Key("software", "valid-key"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	// Should only return the valid key
	assert.Len(t, keys, 1)
	assert.Equal(t, "valid-key", keys[0].Comment)
}

func TestAgentList_SkipsKeysWithEmptyPEM(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.AddKeyWithEmptyPEM("software", "empty-key", "ed25519")
	require.NoError(t, mockClient.AddEd25519Key("software", "valid-key"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "valid-key", keys[0].Comment)
}

func TestAgentSign_Ed25519(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	// First list to populate cache
	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	// Parse the public key
	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	// Sign data
	data := []byte("test data to sign")
	sig, err := ag.Sign(pubKey, data)
	require.NoError(t, err)
	require.NotNil(t, sig)
	assert.NotEmpty(t, sig.Blob)
	assert.Equal(t, ssh.KeyAlgoED25519, sig.Format)
}

func TestAgentSign_RSA(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddRSAKey("software", "test-key", 2048))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	data := []byte("test data to sign")
	sig, err := ag.Sign(pubKey, data)
	require.NoError(t, err)
	require.NotNil(t, sig)
	assert.NotEmpty(t, sig.Blob)
}

func TestAgentSign_ECDSA(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddECDSAKey("software", "test-key", elliptic.P256()))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	data := []byte("test data to sign")
	sig, err := ag.Sign(pubKey, data)
	require.NoError(t, err)
	require.NotNil(t, sig)
	assert.NotEmpty(t, sig.Blob)
}

func TestAgentSignWithFlags_RSA_SHA256(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddRSAKey("software", "test-key", 2048))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	data := []byte("test data to sign")
	sig, err := ag.SignWithFlags(pubKey, data, agent.SignatureFlagRsaSha256)
	require.NoError(t, err)
	require.NotNil(t, sig)
	assert.Equal(t, ssh.KeyAlgoRSASHA256, sig.Format)
}

func TestAgentSignWithFlags_RSA_SHA512(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddRSAKey("software", "test-key", 2048))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	data := []byte("test data to sign")
	sig, err := ag.SignWithFlags(pubKey, data, agent.SignatureFlagRsaSha512)
	require.NoError(t, err)
	require.NotNil(t, sig)
	assert.Equal(t, ssh.KeyAlgoRSASHA512, sig.Format)
}

func TestAgentSign_WhenLocked(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	// Lock the agent
	err = ag.Lock([]byte("passphrase"))
	require.NoError(t, err)

	// Sign should fail when locked
	_, err = ag.Sign(pubKey, []byte("test data"))
	assert.ErrorIs(t, err, ErrAgentLocked)
}

func TestAgentSign_KeyNotFound(t *testing.T) {
	mockClient := NewMockClient()

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	// Create a fake public key that doesn't exist in the agent
	_, priv, _ := ed25519.GenerateKey(nil)
	pub, _ := ssh.NewPublicKey(priv.Public())

	_, err := ag.Sign(pub, []byte("test data"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentKeyNotFound)
}

func TestAgentSign_RefreshesCache(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	// Get keys without calling List first
	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	// Clear the cache manually
	ag.mu.Lock()
	ag.keyCache = make(map[string]*cachedKey)
	ag.mu.Unlock()

	// Sign should still work by refreshing the cache
	sig, err := ag.Sign(pubKey, []byte("test data"))
	require.NoError(t, err)
	require.NotNil(t, sig)
}

func TestAgentSign_WithTouchRequired(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))

	touchHandler := NewMockTouchHandler()
	ag := createTestAgentWithMock(t, mockClient, touchHandler, true)

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	// Sign with touch required
	sig, err := ag.Sign(pubKey, []byte("test data"))
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Verify touch was requested
	assert.True(t, touchHandler.WasTouchCalled())
}

func TestAgentSign_TouchDenied(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))

	touchHandler := NewMockTouchHandler()
	touchHandler.SetTouchError(errors.New("user denied touch"))
	ag := createTestAgentWithMock(t, mockClient, touchHandler, true)

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	// Sign should fail when touch is denied
	_, err = ag.Sign(pubKey, []byte("test data"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentTouchDenied)
}

func TestAgentSign_SigningError(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))
	mockClient.SetSignError(errors.New("signing failed"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	_, err = ag.Sign(pubKey, []byte("test data"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentSignFailed)
}

func TestAgentAdd_NotSupported(t *testing.T) {
	mockClient := NewMockClient()
	ag := createTestAgentWithMock(t, mockClient, nil, false)

	err := ag.Add(agent.AddedKey{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentUnsupportedOp)
	assert.Contains(t, err.Error(), "xkey ssh keys import")
}

func TestAgentRemove_NotSupported(t *testing.T) {
	mockClient := NewMockClient()
	ag := createTestAgentWithMock(t, mockClient, nil, false)

	_, priv, _ := ed25519.GenerateKey(nil)
	pub, _ := ssh.NewPublicKey(priv.Public())

	err := ag.Remove(pub)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentUnsupportedOp)
	assert.Contains(t, err.Error(), "xkey ssh keys delete")
}

func TestAgentRemoveAll_NotSupported(t *testing.T) {
	mockClient := NewMockClient()
	ag := createTestAgentWithMock(t, mockClient, nil, false)

	err := ag.RemoveAll()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentUnsupportedOp)
	assert.Contains(t, err.Error(), "xkey ssh keys delete")
}

func TestAgentLockUnlock(t *testing.T) {
	mockClient := NewMockClient()
	ag := createTestAgentWithMock(t, mockClient, nil, false)

	// Initially unlocked
	assert.False(t, ag.locked.Load())

	// Lock
	err := ag.Lock([]byte("passphrase"))
	require.NoError(t, err)
	assert.True(t, ag.locked.Load())

	// Unlock
	err = ag.Unlock([]byte("passphrase"))
	require.NoError(t, err)
	assert.False(t, ag.locked.Load())
}

func TestAgentSigners(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "key1"))
	require.NoError(t, mockClient.AddRSAKey("software", "key2", 2048))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	signers, err := ag.Signers()
	require.NoError(t, err)
	assert.Len(t, signers, 2)

	// Verify signers can produce signatures
	for _, signer := range signers {
		sig, err := signer.Sign(nil, []byte("test data"))
		require.NoError(t, err)
		require.NotNil(t, sig)
	}
}

func TestAgentSigners_WhenLocked(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "key1"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	// Lock the agent
	err := ag.Lock([]byte("passphrase"))
	require.NoError(t, err)

	// Signers should return empty when locked
	signers, err := ag.Signers()
	require.NoError(t, err)
	assert.Empty(t, signers)
}

func TestAgentSigners_ListError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.SetListError(errors.New("list failed"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	signers, err := ag.Signers()
	assert.Error(t, err)
	assert.Nil(t, signers)
}

func TestAgentExtension_NotSupported(t *testing.T) {
	mockClient := NewMockClient()
	ag := createTestAgentWithMock(t, mockClient, nil, false)

	_, err := ag.Extension("test-extension", []byte("data"))
	assert.ErrorIs(t, err, agent.ErrExtensionUnsupported)
}

func TestAgentClose(t *testing.T) {
	mockClient := NewMockClient()
	ag := createTestAgentWithMock(t, mockClient, nil, false)

	err := ag.Close()
	assert.NoError(t, err)
}

func TestAgentClose_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.SetCloseError(errors.New("close failed"))
	ag := createTestAgentWithMock(t, mockClient, nil, false)

	err := ag.Close()
	assert.Error(t, err)
}

func TestXKMSSigner_PublicKey(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	signer := &xkmsSigner{
		agent:   ag,
		pubKey:  pubKey,
		comment: "test-key",
	}

	assert.Equal(t, pubKey, signer.PublicKey())
}

func TestXKMSSigner_Sign(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	signer := &xkmsSigner{
		agent:   ag,
		pubKey:  pubKey,
		comment: "test-key",
	}

	sig, err := signer.Sign(nil, []byte("test data"))
	require.NoError(t, err)
	require.NotNil(t, sig)
}

func TestInterfaceCompliance(t *testing.T) {
	// Verify that XKMSAgent implements the required interfaces
	var _ agent.Agent = (*XKMSAgent)(nil)
	var _ agent.ExtendedAgent = (*XKMSAgent)(nil)
}

func TestAgentList_GetKeyError(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))
	mockClient.SetGetKeyError(errors.New("get key failed"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	// Should return empty list when GetKey fails for all keys
	keys, err := ag.List()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestAgentList_InvalidDERContent(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.AddKeyWithInvalidDER("software", "invalid-der-key", "ed25519")
	require.NoError(t, mockClient.AddEd25519Key("software", "valid-key"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	keys, err := ag.List()
	require.NoError(t, err)
	// Should skip the invalid key and return only the valid one
	assert.Len(t, keys, 1)
	assert.Equal(t, "valid-key", keys[0].Comment)
}

func TestAgentSign_CacheRefreshFails(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	// Get the key first
	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	require.NoError(t, err)

	// Clear cache and set list error
	ag.mu.Lock()
	ag.keyCache = make(map[string]*cachedKey)
	ag.mu.Unlock()
	mockClient.SetListError(errors.New("list failed"))

	// Sign should fail when cache refresh fails
	_, err = ag.Sign(pubKey, []byte("test data"))
	assert.Error(t, err)
}

func TestMockTouchHandler_Reset(t *testing.T) {
	handler := NewMockTouchHandler()

	// Call touch
	ctx := context.Background()
	err := handler.RequestTouch(ctx, "ssh-sign", "test-key")
	require.NoError(t, err)
	assert.True(t, handler.WasTouchCalled())

	// Reset
	handler.Reset()
	assert.False(t, handler.WasTouchCalled())
}

func TestMockClient_DeleteKey(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "test-key"))

	// Verify key exists
	resp, err := mockClient.ListKeys(context.Background(), "software")
	require.NoError(t, err)
	assert.Len(t, resp.Keys, 1)

	// Delete key
	delResp, err := mockClient.DeleteKey(context.Background(), "software", "test-key")
	require.NoError(t, err)
	assert.True(t, delResp.Success)

	// Verify key is deleted
	resp, err = mockClient.ListKeys(context.Background(), "software")
	require.NoError(t, err)
	assert.Empty(t, resp.Keys)
}

func TestAgentList_DifferentBackends(t *testing.T) {
	mockClient := NewMockClient()
	require.NoError(t, mockClient.AddEd25519Key("software", "software-key"))
	require.NoError(t, mockClient.AddEd25519Key("tpm2", "tpm2-key"))

	ag := createTestAgentWithMock(t, mockClient, nil, false)

	// Agent is configured for "software" backend only
	keys, err := ag.List()
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "software-key", keys[0].Comment)
}
