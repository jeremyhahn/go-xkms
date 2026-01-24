//go:build integration

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

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	keychain "github.com/jeremyhahn/go-keychain/sdk/go"
)

// ErrUserNotFound is returned when a user is not found.
var ErrUserNotFound = errors.New("user not found")

// ErrNotImplemented is returned for operations not implemented in the test service.
var ErrNotImplemented = errors.New("not implemented in test service")

// TestKeychainService is a real implementation of KeychainServicer for integration tests.
// It uses in-memory storage to avoid external dependencies.
type TestKeychainService struct {
	mu           sync.RWMutex
	keys         map[string]*testKey
	certificates map[string][]byte
	users        map[string]*testUser
	sealKey      []byte
}

type testKey struct {
	keyID      string
	keyType    string
	curve      string
	algorithm  string
	privateKey interface{}
	publicKey  interface{}
	symmetric  []byte
	exportable bool
}

type testUser struct {
	username    string
	displayName string
	role        string
	enabled     bool
	createdAt   time.Time
	lastLogin   *time.Time
	credentials []testCredential
}

type testCredential struct {
	id          string
	displayName string
	createdAt   time.Time
	lastUsed    *time.Time
}

// NewTestKeychainService creates a new test service with in-memory storage.
func NewTestKeychainService() (*TestKeychainService, error) {
	// Generate a random seal key
	sealKey := make([]byte, 32)
	if _, err := rand.Read(sealKey); err != nil {
		return nil, fmt.Errorf("failed to generate seal key: %w", err)
	}

	return &TestKeychainService{
		keys:         make(map[string]*testKey),
		certificates: make(map[string][]byte),
		users:        make(map[string]*testUser),
		sealKey:      sealKey,
	}, nil
}

func (s *TestKeychainService) Health(ctx context.Context) (string, string, error) {
	return "healthy", "1.0.0-test", nil
}

func (s *TestKeychainService) ListBackends(ctx context.Context) ([]keychain.BackendInfo, error) {
	return []keychain.BackendInfo{
		{ID: "software", Type: "software", HardwareBacked: false},
	}, nil
}

func (s *TestKeychainService) GetBackend(ctx context.Context, backendID string) (*keychain.BackendInfo, error) {
	if backendID != "software" {
		return nil, errors.New("backend not found")
	}
	return &keychain.BackendInfo{ID: "software", Type: "software", HardwareBacked: false}, nil
}

func (s *TestKeychainService) GenerateKey(ctx context.Context, req *keychain.GenerateKeyRequest) (*keychain.GenerateKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := &testKey{
		keyID:      req.KeyID,
		keyType:    req.KeyType,
		curve:      req.Curve,
		algorithm:  req.Algorithm,
		exportable: req.Exportable,
	}

	switch req.KeyType {
	case "EC", "ec", "ecdsa":
		var curve elliptic.Curve
		switch req.Curve {
		case "P-256", "prime256v1":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate EC key: %w", err)
		}
		key.privateKey = privateKey
		key.publicKey = &privateKey.PublicKey

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
		pubKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		})

		s.keys[req.KeyID] = key
		return &keychain.GenerateKeyResponse{
			KeyID:        req.KeyID,
			KeyType:      req.KeyType,
			PublicKeyPEM: string(pubKeyPEM),
		}, nil

	case "symmetric", "aes", "aes256-gcm":
		symKey := make([]byte, 32) // 256-bit key
		if _, err := rand.Read(symKey); err != nil {
			return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
		}
		key.symmetric = symKey
		key.keyType = "symmetric"
		s.keys[req.KeyID] = key
		return &keychain.GenerateKeyResponse{
			KeyID:   req.KeyID,
			KeyType: "symmetric",
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", req.KeyType)
	}
}

func (s *TestKeychainService) ListKeys(ctx context.Context, backend string) (*keychain.ListKeysResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []keychain.KeyInfo
	for _, k := range s.keys {
		keys = append(keys, keychain.KeyInfo{
			KeyID:   k.keyID,
			KeyType: k.keyType,
		})
	}
	return &keychain.ListKeysResponse{Keys: keys}, nil
}

func (s *TestKeychainService) GetKey(ctx context.Context, backend, keyID string) (*keychain.GetKeyResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[keyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	return &keychain.GetKeyResponse{
		KeyInfo: keychain.KeyInfo{
			KeyID:   key.keyID,
			KeyType: key.keyType,
		},
	}, nil
}

func (s *TestKeychainService) DeleteKey(ctx context.Context, backend, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.keys[keyID]; !ok {
		return errors.New("key not found")
	}
	delete(s.keys, keyID)
	return nil
}

func (s *TestKeychainService) Sign(ctx context.Context, req *keychain.SignRequest) (*keychain.SignResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[req.KeyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	ecdsaKey, ok := key.privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not an ECDSA key")
	}

	hash := sha256.Sum256(req.Data)
	signature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return &keychain.SignResponse{Signature: signature}, nil
}

func (s *TestKeychainService) Verify(ctx context.Context, req *keychain.VerifyRequest) (*keychain.VerifyResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[req.KeyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	ecdsaKey, ok := key.publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not an ECDSA key")
	}

	hash := sha256.Sum256(req.Data)
	valid := ecdsa.VerifyASN1(ecdsaKey, hash[:], req.Signature)

	return &keychain.VerifyResponse{Valid: valid}, nil
}

func (s *TestKeychainService) Encrypt(ctx context.Context, req *keychain.EncryptRequest) (*keychain.EncryptResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[req.KeyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	if key.symmetric == nil {
		return nil, errors.New("key is not a symmetric key")
	}

	// Simple XOR encryption for testing (NOT secure, just for integration test)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(req.Plaintext))
	for i := range req.Plaintext {
		ciphertext[i] = req.Plaintext[i] ^ key.symmetric[i%len(key.symmetric)] ^ nonce[i%len(nonce)]
	}

	// Simple tag (hash of ciphertext + nonce)
	tagData := append(ciphertext, nonce...)
	tagHash := sha256.Sum256(tagData)
	tag := tagHash[:16]

	return &keychain.EncryptResponse{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
	}, nil
}

func (s *TestKeychainService) Decrypt(ctx context.Context, req *keychain.DecryptRequest) (*keychain.DecryptResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[req.KeyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	if key.symmetric == nil {
		return nil, errors.New("key is not a symmetric key")
	}

	// Verify tag
	tagData := append(req.Ciphertext, req.Nonce...)
	tagHash := sha256.Sum256(tagData)
	expectedTag := tagHash[:16]
	for i := range expectedTag {
		if expectedTag[i] != req.Tag[i] {
			return nil, errors.New("authentication failed")
		}
	}

	// Simple XOR decryption (matches encryption above)
	plaintext := make([]byte, len(req.Ciphertext))
	for i := range req.Ciphertext {
		plaintext[i] = req.Ciphertext[i] ^ key.symmetric[i%len(key.symmetric)] ^ req.Nonce[i%len(req.Nonce)]
	}

	return &keychain.DecryptResponse{Plaintext: plaintext}, nil
}

func (s *TestKeychainService) EncryptAsym(ctx context.Context, req *keychain.EncryptAsymRequest) (*keychain.EncryptAsymResponse, error) {
	return nil, errors.New("asymmetric encryption not implemented in test service")
}

func (s *TestKeychainService) GetCertificate(ctx context.Context, backend, keyID string) (*keychain.GetCertificateResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, ok := s.certificates[keyID]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return &keychain.GetCertificateResponse{KeyID: keyID, CertificatePEM: string(cert)}, nil
}

func (s *TestKeychainService) SaveCertificate(ctx context.Context, req *keychain.SaveCertificateRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certificates[req.KeyID] = []byte(req.CertificatePEM)
	return nil
}

func (s *TestKeychainService) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.certificates, keyID)
	return nil
}

func (s *TestKeychainService) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.certificates[keyID]
	return ok, nil
}

func (s *TestKeychainService) ImportKey(ctx context.Context, req *keychain.ImportKeyRequest) (*keychain.ImportKeyResponse, error) {
	return &keychain.ImportKeyResponse{Success: true, KeyID: req.KeyID}, nil
}

func (s *TestKeychainService) ExportKey(ctx context.Context, req *keychain.ExportKeyRequest) (*keychain.ExportKeyResponse, error) {
	return &keychain.ExportKeyResponse{KeyID: req.KeyID}, nil
}

func (s *TestKeychainService) RotateKey(ctx context.Context, req *keychain.RotateKeyRequest) (*keychain.RotateKeyResponse, error) {
	return &keychain.RotateKeyResponse{Success: true, KeyID: req.KeyID}, nil
}

func (s *TestKeychainService) ListKeyVersions(ctx context.Context, req *keychain.ListKeyVersionsRequest) (*keychain.ListKeyVersionsResponse, error) {
	return &keychain.ListKeyVersionsResponse{KeyID: req.KeyID}, nil
}

func (s *TestKeychainService) EnableKeyVersion(ctx context.Context, req *keychain.EnableKeyVersionRequest) (*keychain.EnableKeyVersionResponse, error) {
	return &keychain.EnableKeyVersionResponse{KeyID: req.KeyID}, nil
}

func (s *TestKeychainService) DisableKeyVersion(ctx context.Context, req *keychain.DisableKeyVersionRequest) (*keychain.DisableKeyVersionResponse, error) {
	return &keychain.DisableKeyVersionResponse{KeyID: req.KeyID}, nil
}

func (s *TestKeychainService) EnableAllKeyVersions(ctx context.Context, req *keychain.EnableAllKeyVersionsRequest) (*keychain.EnableAllKeyVersionsResponse, error) {
	return &keychain.EnableAllKeyVersionsResponse{KeyID: req.KeyID}, nil
}

func (s *TestKeychainService) DisableAllKeyVersions(ctx context.Context, req *keychain.DisableAllKeyVersionsRequest) (*keychain.DisableAllKeyVersionsResponse, error) {
	return &keychain.DisableAllKeyVersionsResponse{KeyID: req.KeyID}, nil
}

func (s *TestKeychainService) GetImportParameters(ctx context.Context, req *keychain.GetImportParametersRequest) (*keychain.GetImportParametersResponse, error) {
	return &keychain.GetImportParametersResponse{}, nil
}

func (s *TestKeychainService) WrapKey(ctx context.Context, req *keychain.WrapKeyRequest) (*keychain.WrapKeyResponse, error) {
	return &keychain.WrapKeyResponse{}, nil
}

func (s *TestKeychainService) UnwrapKey(ctx context.Context, req *keychain.UnwrapKeyRequest) (*keychain.UnwrapKeyResponse, error) {
	return &keychain.UnwrapKeyResponse{}, nil
}

func (s *TestKeychainService) CopyKey(ctx context.Context, req *keychain.CopyKeyRequest) (*keychain.CopyKeyResponse, error) {
	return &keychain.CopyKeyResponse{Success: true}, nil
}

func (s *TestKeychainService) ListCertificates(ctx context.Context, backend string) (*keychain.ListCertificatesResponse, error) {
	return &keychain.ListCertificatesResponse{}, nil
}

func (s *TestKeychainService) SaveCertificateChain(ctx context.Context, req *keychain.SaveCertificateChainRequest) error {
	return nil
}

func (s *TestKeychainService) GetCertificateChain(ctx context.Context, backend, keyID string) (*keychain.GetCertificateChainResponse, error) {
	return &keychain.GetCertificateChainResponse{KeyID: keyID}, nil
}

func (s *TestKeychainService) GetTLSCertificate(ctx context.Context, backend, keyID string) (*keychain.GetTLSCertificateResponse, error) {
	return &keychain.GetTLSCertificateResponse{KeyID: keyID}, nil
}

func (s *TestKeychainService) Seal(ctx context.Context, req *keychain.SealRequest) (*keychain.SealResponse, error) {
	// Simple seal using XOR with seal key
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(req.Data))
	for i := range req.Data {
		ciphertext[i] = req.Data[i] ^ s.sealKey[i%len(s.sealKey)] ^ nonce[i%len(nonce)]
	}

	tagData := append(ciphertext, nonce...)
	tagHash := sha256.Sum256(tagData)
	tag := tagHash[:16]

	return &keychain.SealResponse{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
	}, nil
}

func (s *TestKeychainService) Unseal(ctx context.Context, req *keychain.UnsealRequest) (*keychain.UnsealResponse, error) {
	// Verify tag
	tagData := append(req.Ciphertext, req.Nonce...)
	tagHash := sha256.Sum256(tagData)
	expectedTag := tagHash[:16]
	for i := range expectedTag {
		if expectedTag[i] != req.Tag[i] {
			return nil, errors.New("authentication failed")
		}
	}

	plaintext := make([]byte, len(req.Ciphertext))
	for i := range req.Ciphertext {
		plaintext[i] = req.Ciphertext[i] ^ s.sealKey[i%len(s.sealKey)] ^ req.Nonce[i%len(req.Nonce)]
	}

	return &keychain.UnsealResponse{Plaintext: plaintext}, nil
}

func (s *TestKeychainService) CanSeal(ctx context.Context, backend string) (*keychain.CanSealResponse, error) {
	return &keychain.CanSealResponse{CanSeal: true, Backend: backend}, nil
}

// User management operations

func (s *TestKeychainService) ListUsers(ctx context.Context) (*keychain.ListUsersResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]keychain.UserInfo, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, keychain.UserInfo{
			Username:    u.username,
			DisplayName: u.displayName,
			Role:        u.role,
			Enabled:     u.enabled,
			CreatedAt:   u.createdAt,
			LastLogin:   u.lastLogin,
		})
	}
	return &keychain.ListUsersResponse{Users: users}, nil
}

func (s *TestKeychainService) GetUser(ctx context.Context, username string) (*keychain.GetUserResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}

	return &keychain.GetUserResponse{
		User: keychain.UserInfo{
			Username:    u.username,
			DisplayName: u.displayName,
			Role:        u.role,
			Enabled:     u.enabled,
			CreatedAt:   u.createdAt,
			LastLogin:   u.lastLogin,
		},
	}, nil
}

func (s *TestKeychainService) DeleteUser(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[username]; !ok {
		return ErrUserNotFound
	}
	delete(s.users, username)
	return nil
}

func (s *TestKeychainService) EnableUser(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[username]
	if !ok {
		return ErrUserNotFound
	}
	u.enabled = true
	return nil
}

func (s *TestKeychainService) DisableUser(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[username]
	if !ok {
		return ErrUserNotFound
	}
	u.enabled = false
	return nil
}

func (s *TestKeychainService) ListUserCredentials(ctx context.Context, username string) (*keychain.ListUserCredentialsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}

	credentials := make([]keychain.CredentialInfo, len(u.credentials))
	for i, c := range u.credentials {
		credentials[i] = keychain.CredentialInfo{
			ID:          c.id,
			DisplayName: c.displayName,
			CreatedAt:   c.createdAt,
			LastUsed:    c.lastUsed,
		}
	}

	return &keychain.ListUserCredentialsResponse{Credentials: credentials}, nil
}

// Authentication flow operations (FIDO2/WebAuthn server-side)

func (s *TestKeychainService) BeginRegistration(ctx context.Context, req *keychain.BeginRegistrationRequest) (*keychain.BeginRegistrationResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create user if not exists
	if _, exists := s.users[req.Username]; !exists {
		s.users[req.Username] = &testUser{
			username:    req.Username,
			displayName: req.DisplayName,
			role:        "user",
			enabled:     true,
			createdAt:   time.Now(),
			credentials: make([]testCredential, 0),
		}
	}

	// Generate challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Generate user ID
	userID := make([]byte, 16)
	if _, err := rand.Read(userID); err != nil {
		return nil, fmt.Errorf("failed to generate user ID: %w", err)
	}

	return &keychain.BeginRegistrationResponse{
		Challenge: string(challenge),
		UserID:    string(userID),
		RPID:      req.RPID,
		RPName:    req.RPName,
		CredentialParams: []keychain.CredentialParam{
			{Type: "public-key", Alg: -7},   // ES256
			{Type: "public-key", Alg: -257}, // RS256
		},
	}, nil
}

func (s *TestKeychainService) FinishRegistration(ctx context.Context, req *keychain.FinishRegistrationRequest) (*keychain.FinishRegistrationResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[req.Username]
	if !ok {
		return nil, ErrUserNotFound
	}

	// Add credential
	u.credentials = append(u.credentials, testCredential{
		id:          req.CredentialID,
		displayName: "WebAuthn Credential",
		createdAt:   time.Now(),
	})

	return &keychain.FinishRegistrationResponse{
		Success:      true,
		CredentialID: req.CredentialID,
		Message:      "Registration successful",
	}, nil
}

func (s *TestKeychainService) BeginAuthentication(ctx context.Context, req *keychain.BeginAuthenticationRequest) (*keychain.BeginAuthenticationResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[req.Username]
	if !ok {
		return nil, ErrUserNotFound
	}

	// Generate challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Get credential IDs
	credentialIDs := make([]string, len(u.credentials))
	for i, c := range u.credentials {
		credentialIDs[i] = c.id
	}

	return &keychain.BeginAuthenticationResponse{
		Challenge:     string(challenge),
		RPID:          req.RPID,
		CredentialIDs: credentialIDs,
	}, nil
}

func (s *TestKeychainService) FinishAuthentication(ctx context.Context, req *keychain.FinishAuthenticationRequest) (*keychain.FinishAuthenticationResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[req.Username]
	if !ok {
		return nil, ErrUserNotFound
	}

	// Find and update credential
	credentialFound := false
	for i := range u.credentials {
		if u.credentials[i].id == req.CredentialID {
			now := time.Now()
			u.credentials[i].lastUsed = &now
			credentialFound = true
			break
		}
	}

	if !credentialFound {
		return &keychain.FinishAuthenticationResponse{
			Success: false,
			Message: "Credential not found",
		}, nil
	}

	// Update last login
	now := time.Now()
	u.lastLogin = &now

	// Generate mock JWT token
	token := fmt.Sprintf("test-jwt-token-%s-%d", req.Username, time.Now().Unix())

	return &keychain.FinishAuthenticationResponse{
		Success: true,
		Token:   token,
		Message: "Authentication successful",
	}, nil
}
