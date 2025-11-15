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

package grpc

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/certstore"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// mockKeyStore is a minimal mock implementation of keychain.KeyStore for testing
type mockKeyStore struct {
	backendType types.BackendType
	closed      bool
}

func (m *mockKeyStore) Backend() types.Backend {
	return &mockBackend{backendType: m.backendType}
}

func (m *mockKeyStore) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}

func (m *mockKeyStore) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}

func (m *mockKeyStore) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}

func (m *mockKeyStore) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}

func (m *mockKeyStore) ListKeys() ([]*types.KeyAttributes, error) {
	return nil, nil
}

func (m *mockKeyStore) DeleteKey(attrs *types.KeyAttributes) error {
	return nil
}

func (m *mockKeyStore) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}

func (m *mockKeyStore) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, nil
}

func (m *mockKeyStore) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, nil
}

func (m *mockKeyStore) SaveCert(keyID string, cert *x509.Certificate) error {
	return nil
}

func (m *mockKeyStore) GetCert(keyID string) (*x509.Certificate, error) {
	return nil, nil
}

func (m *mockKeyStore) DeleteCert(keyID string) error {
	return nil
}

func (m *mockKeyStore) ListCerts() ([]string, error) {
	return nil, nil
}

func (m *mockKeyStore) CertExists(keyID string) (bool, error) {
	return false, nil
}

func (m *mockKeyStore) SaveCertChain(keyID string, chain []*x509.Certificate) error {
	return nil
}

func (m *mockKeyStore) GetCertChain(keyID string) ([]*x509.Certificate, error) {
	return nil, nil
}

func (m *mockKeyStore) GetTLSCertificate(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}

func (m *mockKeyStore) CertStorage() certstore.CertificateStorageAdapter {
	return nil
}

func (m *mockKeyStore) GetSignerByID(keyID string) (crypto.Signer, error) {
	return nil, nil
}

func (m *mockKeyStore) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	return nil, nil
}

func (m *mockKeyStore) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
	return nil, nil
}

func (m *mockKeyStore) Close() error {
	m.closed = true
	return nil
}

// mockBackend is a minimal mock implementation of keychain.Backend
type mockBackend struct {
	backendType types.BackendType
}

func (m *mockBackend) Type() types.BackendType {
	return m.backendType
}

func (m *mockBackend) Capabilities() types.Capabilities {
	return types.Capabilities{
		HardwareBacked: false,
		Signing:        true,
		Decryption:     true,
		KeyRotation:    true,
	}
}

func (m *mockBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}

func (m *mockBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}

func (m *mockBackend) DeleteKey(attrs *types.KeyAttributes) error {
	return nil
}

func (m *mockBackend) ListKeys() ([]*types.KeyAttributes, error) {
	return nil, nil
}

func (m *mockBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, nil
}

func (m *mockBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, nil
}

func (m *mockBackend) RotateKey(attrs *types.KeyAttributes) error {
	return nil
}

func (m *mockBackend) Close() error {
	return nil
}

func TestNewBackendRegistry(t *testing.T) {
	manager := NewBackendRegistry()
	if manager == nil {
		t.Fatal("NewBackendRegistry returned nil")
	}
	if manager.keystores == nil {
		t.Error("keystores map not initialized")
	}
}

func TestBackendRegistry_Register(t *testing.T) {
	manager := NewBackendRegistry()
	ks := &mockKeyStore{backendType: types.BackendTypePKCS8}

	// Test successful registration
	err := manager.Register("test-backend", ks)
	if err != nil {
		t.Errorf("Register failed: %v", err)
	}

	// Test duplicate registration
	err = manager.Register("test-backend", ks)
	if err == nil {
		t.Error("Expected error when registering duplicate backend")
	}
}

func TestBackendRegistry_Get(t *testing.T) {
	manager := NewBackendRegistry()
	ks := &mockKeyStore{backendType: types.BackendTypePKCS8}

	// Test getting non-existent backend
	_, err := manager.Get("non-existent")
	if err == nil {
		t.Error("Expected error when getting non-existent backend")
	}

	// Register and test successful retrieval
	err = manager.Register("test-backend", ks)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	retrieved, err := manager.Get("test-backend")
	if err != nil {
		t.Errorf("Get failed: %v", err)
	}
	if retrieved == nil {
		t.Error("Retrieved keystore is nil")
	}
}

func TestBackendRegistry_List(t *testing.T) {
	manager := NewBackendRegistry()

	// Test empty list
	infos := manager.List()
	if len(infos) != 0 {
		t.Errorf("Expected empty list, got %d items", len(infos))
	}

	// Register multiple backends
	ks1 := &mockKeyStore{backendType: types.BackendTypePKCS8}
	ks2 := &mockKeyStore{backendType: types.BackendTypePKCS11}

	err := manager.Register("backend1", ks1)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	err = manager.Register("backend2", ks2)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Test list contains both backends
	infos = manager.List()
	if len(infos) != 2 {
		t.Errorf("Expected 2 backends, got %d", len(infos))
	}

	// Verify backend info
	foundBackend1 := false
	foundBackend2 := false
	for _, info := range infos {
		if info.Name == "backend1" {
			foundBackend1 = true
			if info.Type != string(types.BackendTypePKCS8) {
				t.Errorf("Expected type %s, got %s", types.BackendTypePKCS8, info.Type)
			}
		}
		if info.Name == "backend2" {
			foundBackend2 = true
			if info.Type != string(types.BackendTypePKCS11) {
				t.Errorf("Expected type %s, got %s", types.BackendTypePKCS11, info.Type)
			}
		}
	}
	if !foundBackend1 || !foundBackend2 {
		t.Error("Not all registered backends found in list")
	}
}

func TestBackendRegistry_Close(t *testing.T) {
	manager := NewBackendRegistry()
	ks := &mockKeyStore{backendType: types.BackendTypePKCS8}

	err := manager.Register("test-backend", ks)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Test close
	err = manager.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	if !ks.closed {
		t.Error("Keystore was not closed")
	}
}

func TestGetBackendDescription(t *testing.T) {
	tests := []struct {
		name        string
		backendType types.BackendType
		expected    string
	}{
		{
			name:        "PKCS8",
			backendType: types.BackendTypePKCS8,
			expected:    "Software-based PKCS#8 key storage",
		},
		{
			name:        "PKCS11",
			backendType: types.BackendTypePKCS11,
			expected:    "Hardware Security Module (PKCS#11)",
		},
		{
			name:        "TPM2",
			backendType: types.BackendTypeTPM2,
			expected:    "Trusted Platform Module 2.0",
		},
		{
			name:        "AWS KMS",
			backendType: types.BackendTypeAWSKMS,
			expected:    "AWS Key Management Service",
		},
		{
			name:        "GCP KMS",
			backendType: types.BackendTypeGCPKMS,
			expected:    "Google Cloud Key Management Service",
		},
		{
			name:        "Azure KV",
			backendType: types.BackendTypeAzureKV,
			expected:    "Azure Key Vault",
		},
		{
			name:        "Vault",
			backendType: types.BackendTypeVault,
			expected:    "HashiCorp Vault",
		},
		{
			name:        "Unknown",
			backendType: types.BackendType("unknown"),
			expected:    "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := getBackendDescription(tt.backendType)
			if desc != tt.expected {
				t.Errorf("Expected description %q, got %q", tt.expected, desc)
			}
		})
	}
}
