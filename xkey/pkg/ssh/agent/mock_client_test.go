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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockKey stores a test key.
type mockKey struct {
	keyID        string
	keyType      string // algorithm string used as KeyType in transport (e.g., "Ed25519", "RSA", "ECDSA")
	algorithm    string // algorithm string used as Algorithm in transport (e.g., "Ed25519", "RSA", "ECDSA")
	publicKey    crypto.PublicKey
	privateKey   crypto.PrivateKey
	publicKeyPEM string
}

// MockClient implements xkms.Client for testing.
type MockClient struct {
	mu            sync.RWMutex
	connected     bool
	healthError   error
	keys          map[string]*mockKey // backend:keyID -> key
	listError     error
	getKeyError   error
	signError     error
	closeError    error
	connectError  error
	generateError error
	importError   error
	deleteError   error
}

// NewMockClient creates a new mock client.
func NewMockClient() *MockClient {
	return &MockClient{
		keys: make(map[string]*mockKey),
	}
}

// AddEd25519Key adds an Ed25519 key for testing.
func (m *MockClient) AddEd25519Key(backend, keyID string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys[backend+":"+keyID] = &mockKey{
		keyID:        keyID,
		keyType:      "Ed25519",
		algorithm:    "Ed25519",
		publicKey:    pub,
		privateKey:   priv,
		publicKeyPEM: string(pemBlock),
	}
	return nil
}

// AddRSAKey adds an RSA key for testing.
func (m *MockClient) AddRSAKey(backend, keyID string, bits int) error {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys[backend+":"+keyID] = &mockKey{
		keyID:        keyID,
		keyType:      "RSA",
		algorithm:    "RSA",
		publicKey:    &priv.PublicKey,
		privateKey:   priv,
		publicKeyPEM: string(pemBlock),
	}
	return nil
}

// AddECDSAKey adds an ECDSA key for testing.
func (m *MockClient) AddECDSAKey(backend, keyID string, curve elliptic.Curve) error {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys[backend+":"+keyID] = &mockKey{
		keyID:        keyID,
		keyType:      "ECDSA",
		algorithm:    "ECDSA",
		publicKey:    &priv.PublicKey,
		privateKey:   priv,
		publicKeyPEM: string(pemBlock),
	}
	return nil
}

// AddKeyWithInvalidPEM adds a key with invalid PEM for testing error paths.
func (m *MockClient) AddKeyWithInvalidPEM(backend, keyID, keyType string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys[backend+":"+keyID] = &mockKey{
		keyID:        keyID,
		keyType:      keyType,
		algorithm:    keyType,
		publicKeyPEM: "not-valid-pem",
	}
}

// AddKeyWithEmptyPEM adds a key with empty PEM for testing error paths.
func (m *MockClient) AddKeyWithEmptyPEM(backend, keyID, keyType string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys[backend+":"+keyID] = &mockKey{
		keyID:        keyID,
		keyType:      keyType,
		algorithm:    keyType,
		publicKeyPEM: "",
	}
}

// AddKeyWithInvalidDER adds a key with valid PEM but invalid DER content.
func (m *MockClient) AddKeyWithInvalidDER(backend, keyID, keyType string) {
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("invalid-der-content"),
	})

	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys[backend+":"+keyID] = &mockKey{
		keyID:        keyID,
		keyType:      keyType,
		algorithm:    keyType,
		publicKeyPEM: string(pemBlock),
	}
}

// AddKeyWithType adds a key with a specific type (for unsupported type testing).
func (m *MockClient) AddKeyWithType(backend, keyID, keyType string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys[backend+":"+keyID] = &mockKey{
		keyID:        keyID,
		keyType:      keyType,
		algorithm:    keyType,
		publicKeyPEM: "dummy",
	}
}

// SetConnected sets the connected state.
func (m *MockClient) SetConnected(connected bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = connected
}

// SetHealthError sets the health check error.
func (m *MockClient) SetHealthError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthError = err
}

// SetListError sets the list keys error.
func (m *MockClient) SetListError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listError = err
}

// SetGetKeyError sets the get key error.
func (m *MockClient) SetGetKeyError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getKeyError = err
}

// SetSignError sets the sign error.
func (m *MockClient) SetSignError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signError = err
}

// SetCloseError sets the close error.
func (m *MockClient) SetCloseError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeError = err
}

// SetConnectError sets the connect error.
func (m *MockClient) SetConnectError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectError = err
}

// SetGenerateError sets the generate key error.
func (m *MockClient) SetGenerateError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generateError = err
}

// SetImportError sets the import key error.
func (m *MockClient) SetImportError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.importError = err
}

// SetDeleteError sets the delete key error.
func (m *MockClient) SetDeleteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteError = err
}

// Connect implements xkms.Client.
func (m *MockClient) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.connectError != nil {
		return m.connectError
	}
	m.connected = true
	return nil
}

// Close implements xkms.Client.
func (m *MockClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closeError != nil {
		return m.closeError
	}
	m.connected = false
	return nil
}

// Health implements xkms.Client.
func (m *MockClient) Health(ctx context.Context) (*transport.HealthResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.healthError != nil {
		return nil, m.healthError
	}
	return &transport.HealthResponse{
		Status:  "healthy",
		Version: "test-1.0.0",
	}, nil
}

// ListBackends implements xkms.Client.
func (m *MockClient) ListBackends(ctx context.Context, _ ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	return &transport.ListBackendsResponse{
		Backends: []transport.BackendInfo{
			{ID: "software", Type: "software"},
		},
	}, nil
}

// GetBackend implements xkms.Client.
func (m *MockClient) GetBackend(ctx context.Context, backendID string) (*transport.BackendInfo, error) {
	return &transport.BackendInfo{
		ID:   backendID,
		Type: "software",
	}, nil
}

// GenerateKey implements xkms.Client.
func (m *MockClient) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.generateError != nil {
		return nil, m.generateError
	}

	// Generate the appropriate key based on type
	var pub crypto.PublicKey
	var priv crypto.PrivateKey
	var algorithm string

	// Normalize key type (handle both "ecdsa-p256" and "ecdsa-p-256" formats)
	normalizedType := strings.ReplaceAll(strings.ToLower(req.KeyType), "p-", "p")

	switch normalizedType {
	case "ed25519":
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pub = pubKey
		priv = privKey
		algorithm = "Ed25519"
	case "rsa":
		keySize := req.KeySize
		if keySize == 0 {
			keySize = 2048
		}
		privKey, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, err
		}
		pub = &privKey.PublicKey
		priv = privKey
		algorithm = "RSA"
	case "ecdsa-p256", "ecdsa":
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pub = &privKey.PublicKey
		priv = privKey
		algorithm = "ECDSA"
	case "ecdsa-p384":
		privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pub = &privKey.PublicKey
		priv = privKey
		algorithm = "ECDSA"
	case "ecdsa-p521":
		privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pub = &privKey.PublicKey
		priv = privKey
		algorithm = "ECDSA"
	default:
		return nil, errors.New("unsupported key type")
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	m.keys[req.Backend+":"+req.KeyID] = &mockKey{
		keyID:        req.KeyID,
		keyType:      algorithm,
		algorithm:    algorithm,
		publicKey:    pub,
		privateKey:   priv,
		publicKeyPEM: string(pemBlock),
	}

	return &transport.GenerateKeyResponse{
		KeyID:        req.KeyID,
		KeyType:      algorithm,
		PublicKeyPEM: string(pemBlock),
	}, nil
}

// ListKeys implements xkms.Client.
func (m *MockClient) ListKeys(ctx context.Context, backend string, _ ...transport.ListOption) (*transport.ListKeysResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listError != nil {
		return nil, m.listError
	}

	var keys []transport.KeyInfo
	for key, mk := range m.keys {
		// Extract backend from key
		parts := splitKey(key)
		if len(parts) == 2 && parts[0] == backend {
			keys = append(keys, transport.KeyInfo{
				KeyID:     mk.keyID,
				KeyType:   mk.keyType,
				Algorithm: mk.algorithm,
				Backend:   backend,
			})
		}
	}

	return &transport.ListKeysResponse{Keys: keys}, nil
}

// splitKey splits a "backend:keyID" string.
func splitKey(key string) []string {
	for i, c := range key {
		if c == ':' {
			return []string{key[:i], key[i+1:]}
		}
	}
	return []string{key}
}

// GetKey implements xkms.Client.
func (m *MockClient) GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getKeyError != nil {
		return nil, m.getKeyError
	}

	mk, ok := m.keys[backend+":"+keyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	return &transport.GetKeyResponse{
		KeyInfo: transport.KeyInfo{
			KeyID:     mk.keyID,
			KeyType:   mk.keyType,
			Algorithm: mk.algorithm,
			Backend:   backend,
		},
		PublicKeyPEM: mk.publicKeyPEM,
	}, nil
}

// DeleteKey implements xkms.Client.
func (m *MockClient) DeleteKey(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteError != nil {
		return nil, m.deleteError
	}

	delete(m.keys, backend+":"+keyID)
	return &transport.DeleteKeyResponse{Success: true}, nil
}

// Sign implements xkms.Client.
func (m *MockClient) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.signError != nil {
		return nil, m.signError
	}

	mk, ok := m.keys[req.Backend+":"+req.KeyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	var signature []byte
	var err error

	switch priv := mk.privateKey.(type) {
	case ed25519.PrivateKey:
		signature = ed25519.Sign(priv, req.Data)
	case *rsa.PrivateKey:
		// For RSA, we use PKCS1v15 signing
		signature, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashData(req.Data))
		if err != nil {
			return nil, err
		}
	case *ecdsa.PrivateKey:
		signature, err = ecdsa.SignASN1(rand.Reader, priv, hashData(req.Data))
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported key type for signing")
	}

	return &transport.SignResponse{
		Signature: signature,
		Algorithm: req.Hash,
	}, nil
}

// hashData computes SHA256 hash for signing.
func hashData(data []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(data)
	return h.Sum(nil)
}

// Verify implements xkms.Client.
func (m *MockClient) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return &transport.VerifyResponse{Valid: true}, nil
}

// Encrypt implements xkms.Client.
func (m *MockClient) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return nil, errors.New("not implemented")
}

// Decrypt implements xkms.Client.
func (m *MockClient) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return nil, errors.New("not implemented")
}

// EncryptAsym implements xkms.Client.
func (m *MockClient) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return nil, errors.New("not implemented")
}

// GetCertificate implements xkms.Client.
func (m *MockClient) GetCertificate(ctx context.Context, backend, keyID string) (*transport.GetCertificateResponse, error) {
	return nil, errors.New("not implemented")
}

// SaveCertificate implements xkms.Client.
func (m *MockClient) SaveCertificate(ctx context.Context, req *transport.SaveCertificateRequest) error {
	return errors.New("not implemented")
}

// DeleteCertificate implements xkms.Client.
func (m *MockClient) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	return errors.New("not implemented")
}

// CertificateExists implements xkms.Client.
func (m *MockClient) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	return false, nil
}

// ImportKey implements xkms.Client.
func (m *MockClient) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.importError != nil {
		return nil, m.importError
	}

	// For testing, we simulate import by generating a key based on algorithm
	var pub crypto.PublicKey
	var priv crypto.PrivateKey
	var algorithm string

	normalizedType := strings.ToLower(req.KeyType)

	switch {
	case normalizedType == "ed25519":
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pub = pubKey
		priv = privKey
		algorithm = "Ed25519"
	case normalizedType == "rsa":
		keySize := req.KeySize
		if keySize == 0 {
			keySize = 2048
		}
		privKey, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, err
		}
		pub = &privKey.PublicKey
		priv = privKey
		algorithm = "RSA"
	case strings.HasPrefix(normalizedType, "ecdsa"):
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pub = &privKey.PublicKey
		priv = privKey
		algorithm = "ECDSA"
	default:
		return nil, errors.New("unsupported key type")
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	m.keys[req.Backend+":"+req.KeyID] = &mockKey{
		keyID:        req.KeyID,
		keyType:      algorithm,
		algorithm:    algorithm,
		publicKey:    pub,
		privateKey:   priv,
		publicKeyPEM: string(pemBlock),
	}

	return &transport.ImportKeyResponse{
		Success:      true,
		KeyID:        req.KeyID,
		PublicKeyPEM: string(pemBlock),
	}, nil
}

// ExportKey implements xkms.Client.
func (m *MockClient) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	return nil, errors.New("not implemented")
}

// RotateKey implements xkms.Client.
func (m *MockClient) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	return nil, errors.New("not implemented")
}

// GetImportParameters implements xkms.Client.
// Returns mock wrapping parameters for BYOK import testing.
func (m *MockClient) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	// Generate a temporary RSA wrapping key for the mock
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	wrappingPubBytes, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	if err != nil {
		return nil, err
	}

	importToken := []byte("mock-import-token")

	return &transport.GetImportParametersResponse{
		WrappingPublicKey: wrappingPubBytes,
		ImportToken:       importToken,
		Algorithm:         req.Algorithm,
	}, nil
}

// WrapKey implements xkms.Client.
// Returns mock wrapped key material for BYOK import testing.
func (m *MockClient) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	// For testing purposes, return the key material as "wrapped" (not truly encrypted).
	// In a real implementation, the key would be encrypted with the wrapping public key.
	return &transport.WrapKeyResponse{
		WrappedKeyMaterial: req.KeyMaterial,
		Algorithm:          req.Algorithm,
	}, nil
}

// UnwrapKey implements xkms.Client.
func (m *MockClient) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	return nil, errors.New("not implemented")
}

// CopyKey implements xkms.Client.
func (m *MockClient) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	return nil, errors.New("not implemented")
}

// ListCertificates implements xkms.Client.
func (m *MockClient) ListCertificates(ctx context.Context, backend string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	return nil, errors.New("not implemented")
}

// SaveCertificateChain implements xkms.Client.
func (m *MockClient) SaveCertificateChain(ctx context.Context, req *transport.SaveCertificateChainRequest) error {
	return errors.New("not implemented")
}

// GetCertificateChain implements xkms.Client.
func (m *MockClient) GetCertificateChain(ctx context.Context, backend, keyID string) (*transport.GetCertificateChainResponse, error) {
	return nil, errors.New("not implemented")
}

// GetTLSCertificate implements xkms.Client.
func (m *MockClient) GetTLSCertificate(ctx context.Context, backend, keyID string) (*transport.GetTLSCertificateResponse, error) {
	return nil, errors.New("not implemented")
}

// Seal implements xkms.Client.
func (m *MockClient) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	return nil, errors.New("not implemented")
}

// Unseal implements xkms.Client.
func (m *MockClient) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	return nil, errors.New("not implemented")
}

// CanSeal implements xkms.Client.
func (m *MockClient) CanSeal(ctx context.Context, backend string) (*transport.CanSealResponse, error) {
	return &transport.CanSealResponse{CanSeal: false}, nil
}

// AttestKey implements xkms.Client.
func (m *MockClient) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return nil, nil
}

// ListUsers implements xkms.Client.
func (m *MockClient) ListUsers(ctx context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return nil, errors.New("not implemented")
}

// GetUser implements xkms.Client.
func (m *MockClient) GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error) {
	return nil, errors.New("not implemented")
}

// DeleteUser implements xkms.Client.
func (m *MockClient) DeleteUser(ctx context.Context, username string) error {
	return errors.New("not implemented")
}

// EnableUser implements xkms.Client.
func (m *MockClient) EnableUser(ctx context.Context, username string) error {
	return errors.New("not implemented")
}

// DisableUser implements xkms.Client.
func (m *MockClient) DisableUser(ctx context.Context, username string) error {
	return errors.New("not implemented")
}

// ListUserCredentials implements xkms.Client.
func (m *MockClient) ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error) {
	return nil, errors.New("not implemented")
}

// BeginRegistration implements xkms.Client.
func (m *MockClient) BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return nil, errors.New("not implemented")
}

// FinishRegistration implements xkms.Client.
func (m *MockClient) FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return nil, errors.New("not implemented")
}

// BeginAuthentication implements xkms.Client.
func (m *MockClient) BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return nil, errors.New("not implemented")
}

// FinishAuthentication implements xkms.Client.
func (m *MockClient) FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return nil, errors.New("not implemented")
}

// DeriveKey implements xkms.Client.
func (m *MockClient) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return nil, errors.New("not implemented")
}

// CA bundle methods

func (m *MockClient) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return nil, errors.New("not implemented")
}

// PIV operations

// ListPIVSlots implements xkms.Client.
func (m *MockClient) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return nil, errors.New("not implemented")
}

// GetPIVCertificate implements xkms.Client.
func (m *MockClient) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, errors.New("not implemented")
}

// StorePIVCertificate implements xkms.Client.
func (m *MockClient) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return errors.New("not implemented")
}

// DeletePIVCertificate implements xkms.Client.
func (m *MockClient) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return errors.New("not implemented")
}

// GeneratePIVKey implements xkms.Client.
func (m *MockClient) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, errors.New("not implemented")
}

// ImportPIVCertificate implements xkms.Client.
func (m *MockClient) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return errors.New("not implemented")
}

// ExportPIVCertificate implements xkms.Client.
func (m *MockClient) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, errors.New("not implemented")
}

// GeneratePIVCSR implements xkms.Client.
func (m *MockClient) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, errors.New("not implemented")
}

// MockTouchHandler implements TouchHandler for testing.
type MockTouchHandler struct {
	mu            sync.Mutex
	touchError    error
	touchCalled   bool
	lastKeyID     string
	lastOperation string
}

// NewMockTouchHandler creates a new mock touch handler.
func NewMockTouchHandler() *MockTouchHandler {
	return &MockTouchHandler{}
}

// RequestTouch implements TouchHandler.
func (m *MockTouchHandler) RequestTouch(ctx context.Context, operation, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.touchCalled = true
	m.lastOperation = operation
	m.lastKeyID = keyID
	return m.touchError
}

// SetTouchError sets the error to return from RequestTouch.
func (m *MockTouchHandler) SetTouchError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touchError = err
}

// WasTouchCalled returns whether RequestTouch was called.
func (m *MockTouchHandler) WasTouchCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.touchCalled
}

// Reset resets the mock state.
func (m *MockTouchHandler) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touchCalled = false
	m.touchError = nil
	m.lastKeyID = ""
	m.lastOperation = ""
}

// Verify MockClient implements the Client interface at compile time.
var _ transport.Client = (*MockClient)(nil)

// Verify MockTouchHandler implements the TouchHandler interface at compile time.
var _ TouchHandler = (*MockTouchHandler)(nil)

// Barrier operations

func (m *MockClient) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) BarrierSeal(ctx context.Context) error {
	return errors.New("not implemented")
}

func (m *MockClient) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	return errors.New("not implemented")
}

// BarrierShamirListShares returns Shamir share metadata.
func (m *MockClient) BarrierShamirListShares(_ context.Context) (*transport.BarrierShamirSharesResponse, error) {
	return nil, errors.New("not implemented")
}

// BarrierShamirDeleteShare deletes a Shamir share by index.
func (m *MockClient) BarrierShamirDeleteShare(_ context.Context, _ *transport.BarrierShamirDeleteShareRequest) error {
	return errors.New("not implemented")
}

// BarrierShamirDeleteAllShares deletes all Shamir shares.
func (m *MockClient) BarrierShamirDeleteAllShares(_ context.Context) error {
	return errors.New("not implemented")
}

// BarrierShamirVerify verifies Shamir share integrity.
func (m *MockClient) BarrierShamirVerify(_ context.Context) error {
	return errors.New("not implemented")
}

// BarrierRekey re-encrypts the barrier with a new root key.
func (m *MockClient) BarrierRekey(_ context.Context, _ *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	return nil, errors.New("not implemented")
}

// BarrierGenerateRecoveryKeys generates recovery keys.
func (m *MockClient) BarrierGenerateRecoveryKeys(_ context.Context, _ *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	return nil, errors.New("not implemented")
}

// BarrierRecoverWithKeys recovers the barrier using recovery keys.
func (m *MockClient) BarrierRecoverWithKeys(_ context.Context, _ *transport.BarrierRecoverWithKeysRequest) error {
	return errors.New("not implemented")
}

// BarrierDeleteRecoveryKeys deletes all recovery keys.
func (m *MockClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return errors.New("not implemented")
}

// BarrierHasRecoveryKeys checks if recovery keys exist.
func (m *MockClient) BarrierHasRecoveryKeys(_ context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	return nil, errors.New("not implemented")
}

// BarrierGenerateRootToken generates a root token.
func (m *MockClient) BarrierGenerateRootToken(_ context.Context, _ *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	return nil, errors.New("not implemented")
}

// PIN operations

func (m *MockClient) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	return errors.New("not implemented")
}

// Password operations

func (m *MockClient) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) PasswordStoreLock(ctx context.Context) error {
	return errors.New("not implemented")
}

func (m *MockClient) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, errors.New("not implemented")
}

// PlatformStore operations

func (m *MockClient) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, errors.New("not implemented")
}

// Policy operations

func (m *MockClient) PolicyCreate(ctx context.Context, req *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) PolicyGet(ctx context.Context, req *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) PolicyList(ctx context.Context) (*transport.PolicyListResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) PolicyDelete(ctx context.Context, req *transport.PolicyDeleteRequest) error {
	return errors.New("not implemented")
}

func (m *MockClient) PolicyRefresh(ctx context.Context, req *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) PolicyVerify(ctx context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) PolicyExport(ctx context.Context, req *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	return nil, errors.New("not implemented")
}

// Custodian group operations

func (m *MockClient) CreateCustodianGroup(ctx context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	return nil, nil
}

func (m *MockClient) GetCustodianGroup(ctx context.Context, groupID string) (*transport.GetCustodianGroupResponse, error) {
	return nil, nil
}

func (m *MockClient) ListCustodianGroups(ctx context.Context) (*transport.ListCustodianGroupsResponse, error) {
	return nil, nil
}

func (m *MockClient) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	return nil
}

func (m *MockClient) AddCustodianMember(ctx context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	return nil, nil
}

func (m *MockClient) RemoveCustodianMember(ctx context.Context, req *transport.RemoveCustodianMemberRequest) error {
	return nil
}

// Share operations

func (m *MockClient) DistributeShares(ctx context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	return nil, nil
}

func (m *MockClient) SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	return nil, nil
}

func (m *MockClient) ListShares(ctx context.Context) (*transport.ListSharesResponse, error) {
	return nil, nil
}

func (m *MockClient) GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error) {
	return nil, nil
}

// Tenant operations

func (m *MockClient) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, nil
}

func (m *MockClient) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	return nil, nil
}

func (m *MockClient) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	return nil, nil
}

func (m *MockClient) DeleteTenant(ctx context.Context, tenantID string) error {
	return nil
}

func (m *MockClient) TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error {
	return nil
}

func (m *MockClient) TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error {
	return nil
}

// InitCeremonyService methods

func (m *MockClient) GetInitStatus(ctx context.Context) (*transport.InitStatusResponse, error) {
	return nil, nil
}

func (m *MockClient) ClaimCertBegin(ctx context.Context, req *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	return nil, nil
}

func (m *MockClient) ClaimCertComplete(ctx context.Context, req *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	return nil, nil
}

func (m *MockClient) ClaimShare(ctx context.Context, req *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	return nil, nil
}

func (m *MockClient) SignCSRInit(ctx context.Context, req *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	return nil, nil
}

// CredentialManagementService methods

func (m *MockClient) SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, nil
}

func (m *MockClient) GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, nil
}

func (m *MockClient) IssueEKCertificate(_ context.Context, _ *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, nil
}

func (m *MockClient) IssueAKCertificate(_ context.Context, _ *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, nil
}

func (m *MockClient) SignTCGCSR(_ context.Context, _ *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, nil
}

func (m *MockClient) EnrollDevice(_ context.Context, _ *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, nil
}
