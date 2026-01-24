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

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	client "github.com/jeremyhahn/go-keychain/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for Execute() function in root.go

func TestExecute_Success(t *testing.T) {
	// Test Execute() returns error for unknown command
	rootCmd.SetArgs([]string{"nonexistent-command"})
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	err := Execute()
	assert.Error(t, err) // Unknown command returns error
}

func TestExecute_HelpCommand(t *testing.T) {
	// Test Execute() works with help
	rootCmd.SetArgs([]string{"--help"})
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	err := Execute()
	assert.NoError(t, err)
}

func TestExecute_VersionCommand(t *testing.T) {
	// Test Execute() works with version subcommand
	rootCmd.SetArgs([]string{"version"})
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	err := Execute()
	assert.NoError(t, err)
}

// Tests for DeleteCertificate - "no backends available" error path

func TestAPIServiceAdapter_DeleteCertificate_NoBackendsAvailable(t *testing.T) {
	// Reset without setting up any backends
	keychain.Reset()
	// Do not defer Reset() here - we need to set up properly for the adapter

	// First set up a service so we can create the adapter
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)
	config := &keychain.ServiceConfig{
		Backends:       map[string]keychain.KeyStore{"software": ks},
		DefaultBackend: "software",
	}
	err := keychain.Initialize(config)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Now reset to clear backends
	keychain.Reset()

	// Re-initialize with empty backends map to simulate "no backends available"
	// Since we can't have a truly empty map (validation prevents it),
	// we need to test the path differently - by resetting after creating adapter
	// The function checks keychain.Backends() which returns nil when not initialized

	err = adapter.DeleteCertificate(context.Background(), "software", "test-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no backends available")
}

// Tests for CertificateExists - "no backends available" error path

func TestAPIServiceAdapter_CertificateExists_NoBackendsAvailable(t *testing.T) {
	// Reset without setting up any backends
	keychain.Reset()

	// First set up a service so we can create the adapter
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)
	config := &keychain.ServiceConfig{
		Backends:       map[string]keychain.KeyStore{"software": ks},
		DefaultBackend: "software",
	}
	err := keychain.Initialize(config)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Now reset to clear backends
	keychain.Reset()

	exists, err := adapter.CertificateExists(context.Background(), "software", "test-key")
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Contains(t, err.Error(), "no backends available")
}

// Tests for GetCertificate - "no backends available" error path

func TestAPIServiceAdapter_GetCertificate_NoBackendsAvailable(t *testing.T) {
	keychain.Reset()

	// First set up a service so we can create the adapter
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)
	config := &keychain.ServiceConfig{
		Backends:       map[string]keychain.KeyStore{"software": ks},
		DefaultBackend: "software",
	}
	err := keychain.Initialize(config)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Now reset to clear backends
	keychain.Reset()

	resp, err := adapter.GetCertificate(context.Background(), "software", "test-key")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "no backends available")
}

// Tests for SaveCertificate - "no backends available" error path

func TestAPIServiceAdapter_SaveCertificate_NoBackendsAvailable(t *testing.T) {
	keychain.Reset()

	// First set up a service so we can create the adapter
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)
	config := &keychain.ServiceConfig{
		Backends:       map[string]keychain.KeyStore{"software": ks},
		DefaultBackend: "software",
	}
	err := keychain.Initialize(config)
	require.NoError(t, err)

	// Generate a cert for testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := createTestCert(t, "test-key", privKey)
	certPEM := encodeCertToPEM(cert)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Now reset to clear backends
	keychain.Reset()

	req := &client.SaveCertificateRequest{
		KeyID:          "test-key",
		CertificatePEM: certPEM,
	}

	err = adapter.SaveCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no backends available")
}

// Tests for ListCertificates - "no backends available" error path

func TestAPIServiceAdapter_ListCertificates_NoBackendsAvailable(t *testing.T) {
	keychain.Reset()

	// First set up a service so we can create the adapter
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)
	config := &keychain.ServiceConfig{
		Backends:       map[string]keychain.KeyStore{"software": ks},
		DefaultBackend: "software",
	}
	err := keychain.Initialize(config)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Now reset to clear backends
	keychain.Reset()

	resp, err := adapter.ListCertificates(context.Background(), "software")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "no backends available")
}

// Tests for SaveCertificateChain - "no backends available" error path

func TestAPIServiceAdapter_SaveCertificateChain_NoBackendsAvailable(t *testing.T) {
	keychain.Reset()

	// First set up a service so we can create the adapter
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)
	config := &keychain.ServiceConfig{
		Backends:       map[string]keychain.KeyStore{"software": ks},
		DefaultBackend: "software",
	}
	err := keychain.Initialize(config)
	require.NoError(t, err)

	// Generate a cert for testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := createTestCert(t, "test-key", privKey)
	certPEM := encodeCertToPEM(cert)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Now reset to clear backends
	keychain.Reset()

	req := &client.SaveCertificateChainRequest{
		KeyID:    "test-key",
		ChainPEM: []string{certPEM},
	}

	err = adapter.SaveCertificateChain(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no backends available")
}

// Tests for GetCertificateChain - "no backends available" error path

func TestAPIServiceAdapter_GetCertificateChain_NoBackendsAvailable(t *testing.T) {
	keychain.Reset()

	// First set up a service so we can create the adapter
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)
	config := &keychain.ServiceConfig{
		Backends:       map[string]keychain.KeyStore{"software": ks},
		DefaultBackend: "software",
	}
	err := keychain.Initialize(config)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Now reset to clear backends
	keychain.Reset()

	resp, err := adapter.GetCertificateChain(context.Background(), "software", "test-key")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "no backends available")
}

// Tests for WrapKey - "no backends available" error path

func TestAPIServiceAdapter_WrapKey_NoBackendsAvailable(t *testing.T) {
	keychain.Reset()

	// First set up a service so we can create the adapter
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)
	config := &keychain.ServiceConfig{
		Backends:       map[string]keychain.KeyStore{"software": ks},
		DefaultBackend: "software",
	}
	err := keychain.Initialize(config)
	require.NoError(t, err)

	// Generate a wrapping key for testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Now reset to clear backends
	keychain.Reset()

	req := &client.WrapKeyRequest{
		KeyMaterial:       []byte("key-material"),
		WrappingPublicKey: pubKeyBytes,
		Algorithm:         "RSA-OAEP-256",
	}

	resp, err := adapter.WrapKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "no backends available")
}

// Tests for UnwrapKey - "no backends available" error path

func TestAPIServiceAdapter_UnwrapKey_NoBackendsAvailable(t *testing.T) {
	keychain.Reset()

	// First set up a service so we can create the adapter
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)
	config := &keychain.ServiceConfig{
		Backends:       map[string]keychain.KeyStore{"software": ks},
		DefaultBackend: "software",
	}
	err := keychain.Initialize(config)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Now reset to clear backends
	keychain.Reset()

	req := &client.UnwrapKeyRequest{
		WrappedKeyMaterial: []byte("wrapped-key-material"),
		Algorithm:          "RSA-OAEP-256",
	}

	resp, err := adapter.UnwrapKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "no backends available")
}

// Tests for extractPublicKeyPEM - unsupported key type path

func TestExtractPublicKeyPEM_UnsupportedKeyType(t *testing.T) {
	// Test with an unsupported key type (nil)
	_, err := extractPublicKeyPEM(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestExtractPublicKeyPEM_RSAKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pem, err := extractPublicKeyPEM(privKey)
	assert.NoError(t, err)
	assert.Contains(t, pem, "-----BEGIN PUBLIC KEY-----")
}

func TestExtractPublicKeyPEM_ECDSAKey(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pem, err := extractPublicKeyPEM(privKey)
	assert.NoError(t, err)
	assert.Contains(t, pem, "-----BEGIN PUBLIC KEY-----")
}

func TestExtractPublicKeyPEM_Ed25519Key(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pem, err := extractPublicKeyPEM(privKey)
	assert.NoError(t, err)
	assert.Contains(t, pem, "-----BEGIN PUBLIC KEY-----")
}

// Tests for parseCertFromPEM - additional error cases

func TestParseCertFromPEM_InvalidPEMType(t *testing.T) {
	invalidPEM := `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7
-----END PRIVATE KEY-----`

	_, err := parseCertFromPEM(invalidPEM)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid PEM type")
}

func TestParseCertFromPEM_InvalidCertData(t *testing.T) {
	invalidPEM := `-----BEGIN CERTIFICATE-----
not valid base64 data here
-----END CERTIFICATE-----`

	_, err := parseCertFromPEM(invalidPEM)
	assert.Error(t, err)
}

// Tests for findKeyAttributes - error path when key not found

func TestFindKeyAttributes_KeyNotFound(t *testing.T) {
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)

	_, err := findKeyAttributes(ks, "nonexistent-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key nonexistent-key not found")
}

func TestFindKeyAttributes_ListKeysError(t *testing.T) {
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)
	ks.listKeysErr = errors.New("database error")

	_, err := findKeyAttributes(ks, "any-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database error")
}

// Tests for getAlgorithmString

func TestGetAlgorithmString_SymmetricAlgorithm(t *testing.T) {
	attrs := &types.KeyAttributes{
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	result := getAlgorithmString(attrs)
	assert.Equal(t, string(types.SymmetricAES256GCM), result)
}

func TestGetAlgorithmString_RSAAlgorithm(t *testing.T) {
	attrs := &types.KeyAttributes{
		KeyAlgorithm: x509.RSA,
	}
	result := getAlgorithmString(attrs)
	assert.Equal(t, "RSA", result)
}

func TestGetAlgorithmString_ECDSAAlgorithm(t *testing.T) {
	attrs := &types.KeyAttributes{
		KeyAlgorithm: x509.ECDSA,
	}
	result := getAlgorithmString(attrs)
	assert.Equal(t, "ECDSA", result)
}

func TestGetAlgorithmString_Ed25519Algorithm(t *testing.T) {
	attrs := &types.KeyAttributes{
		KeyAlgorithm: x509.Ed25519,
	}
	result := getAlgorithmString(attrs)
	assert.Equal(t, "Ed25519", result)
}

func TestGetAlgorithmString_UnknownAlgorithm(t *testing.T) {
	attrs := &types.KeyAttributes{
		KeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
	}
	result := getAlgorithmString(attrs)
	assert.Equal(t, "", result)
}

// Tests for parseHashAlgorithm

func TestParseHashAlgorithm_Empty(t *testing.T) {
	result := parseHashAlgorithm("")
	assert.Equal(t, crypto.SHA256, result)
}

func TestParseHashAlgorithm_SHA256(t *testing.T) {
	result := parseHashAlgorithm("sha256")
	assert.Equal(t, crypto.SHA256, result)
}

func TestParseHashAlgorithm_SHA384(t *testing.T) {
	result := parseHashAlgorithm("sha384")
	assert.Equal(t, crypto.SHA384, result)
}

func TestParseHashAlgorithm_SHA512(t *testing.T) {
	result := parseHashAlgorithm("sha512")
	assert.Equal(t, crypto.SHA512, result)
}

func TestParseHashAlgorithm_Invalid(t *testing.T) {
	result := parseHashAlgorithm("invalid")
	assert.Equal(t, crypto.SHA256, result) // Defaults to SHA256
}

// Tests for Decrypt - asymmetric decryption path

func TestAPIServiceAdapter_Decrypt_AsymmetricRSA(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create an RSA key
	attrs := &types.KeyAttributes{
		CN:           "rsa-decrypt-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeEncryption,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	_, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// We can't easily test RSA decryption in isolation here because the mock backend
	// doesn't fully implement the decryption path for asymmetric keys.
	// But we can verify the error path when trying to decrypt with invalid data.
	req := &client.DecryptRequest{
		Backend:    "software",
		KeyID:      "rsa-decrypt-key",
		Ciphertext: []byte("invalid-ciphertext"),
	}

	_, err = adapter.Decrypt(context.Background(), req)
	// This should fail because the mock doesn't support asymmetric decryption
	assert.Error(t, err)
}

// Tests for Verify - additional key types

func TestAPIServiceAdapter_Verify_SignerKeyType(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create an ECDSA key
	attrs := &types.KeyAttributes{
		CN:           "signer-verify-key",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeSigning,
	}
	key, err := ks.GenerateECDSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Sign some data
	signer := key.(*ecdsa.PrivateKey)
	data := []byte("test data for signing")
	hash := crypto.SHA256.New()
	hash.Write(data)
	digest := hash.Sum(nil)
	signature, err := ecdsa.SignASN1(rand.Reader, signer, digest)
	require.NoError(t, err)

	// Verify the signature
	req := &client.VerifyRequest{
		Backend:   "software",
		KeyID:     "signer-verify-key",
		Data:      data,
		Signature: signature,
		Hash:      "sha256",
	}

	resp, err := adapter.Verify(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.Valid)
}

// Tests for EncryptAsym - error cases

func TestAPIServiceAdapter_EncryptAsym_KeyDoesNotSupportPublicKeyExtraction(t *testing.T) {
	keychain.Reset()

	// Create a mock backend that returns a key that doesn't implement crypto.Signer
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := &mockKeyStoreWithNonSignerKey{
		mockKeyStore: newMockKeyStore("software", be),
		keyAttrs:     make(map[string]*types.KeyAttributes), // Initialize the map
	}

	config := &keychain.ServiceConfig{
		Backends:       map[string]keychain.KeyStore{"software": ks},
		DefaultBackend: "software",
	}
	err := keychain.Initialize(config)
	require.NoError(t, err)
	defer keychain.Reset()

	// Add a non-signer key
	ks.keys["non-signer-key"] = &nonSignerKey{}
	ks.keyAttrs["non-signer-key"] = &types.KeyAttributes{
		CN:           "non-signer-key",
		KeyAlgorithm: x509.RSA,
	}

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "non-signer-key",
		Plaintext: []byte("test data"),
	}

	resp, err := adapter.EncryptAsym(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key does not support public key extraction")
}

// nonSignerKey is a mock key that doesn't implement crypto.Signer
type nonSignerKey struct{}

// mockKeyStoreWithNonSignerKey extends mockKeyStore to support non-signer keys
type mockKeyStoreWithNonSignerKey struct {
	*mockKeyStore
	keyAttrs map[string]*types.KeyAttributes
}

func (m *mockKeyStoreWithNonSignerKey) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

func (m *mockKeyStoreWithNonSignerKey) ListKeys() ([]*types.KeyAttributes, error) {
	result := make([]*types.KeyAttributes, 0, len(m.keyAttrs))
	for _, attr := range m.keyAttrs {
		result = append(result, attr)
	}
	return result, nil
}

// Helper function to create test certificate
func createTestCert(t *testing.T, cn string, key crypto.Signer) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
