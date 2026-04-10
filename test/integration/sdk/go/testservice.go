//go:build integration

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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// ErrUserNotFound is returned when a user is not found.
var ErrUserNotFound = errors.New("user not found")

// ErrNotImplemented is returned for operations not implemented in the test service.
var ErrNotImplemented = errors.New("not implemented in test service")

// TestXKMSService is a real implementation of XKMSServicer for integration tests.
// It uses in-memory storage to avoid external dependencies.
type TestXKMSService struct {
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

// NewTestXKMSService creates a new test service with in-memory storage.
func NewTestXKMSService() (*TestXKMSService, error) {
	// Generate a random seal key
	sealKey := make([]byte, 32)
	if _, err := rand.Read(sealKey); err != nil {
		return nil, fmt.Errorf("failed to generate seal key: %w", err)
	}

	return &TestXKMSService{
		keys:         make(map[string]*testKey),
		certificates: make(map[string][]byte),
		users:        make(map[string]*testUser),
		sealKey:      sealKey,
	}, nil
}

func (s *TestXKMSService) Health(ctx context.Context) (string, string, error) {
	return "healthy", "1.0.0-test", nil
}

func (s *TestXKMSService) ListBackends(ctx context.Context, _ ...transport.ListOption) ([]xkms.BackendInfo, error) {
	return []xkms.BackendInfo{
		{ID: "software", Type: "software", HardwareBacked: false},
	}, nil
}

func (s *TestXKMSService) GetBackend(ctx context.Context, backendID string) (*xkms.BackendInfo, error) {
	if backendID != "software" {
		return nil, errors.New("backend not found")
	}
	return &xkms.BackendInfo{ID: "software", Type: "software", HardwareBacked: false}, nil
}

func (s *TestXKMSService) GenerateKey(ctx context.Context, req *xkms.GenerateKeyRequest) (*xkms.GenerateKeyResponse, error) {
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
		return &xkms.GenerateKeyResponse{
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
		return &xkms.GenerateKeyResponse{
			KeyID:   req.KeyID,
			KeyType: "symmetric",
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", req.KeyType)
	}
}

func (s *TestXKMSService) ListKeys(ctx context.Context, backend string, _ ...transport.ListOption) (*xkms.ListKeysResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []xkms.KeyInfo
	for _, k := range s.keys {
		keys = append(keys, xkms.KeyInfo{
			KeyID:   k.keyID,
			KeyType: k.keyType,
		})
	}
	return &xkms.ListKeysResponse{Keys: keys}, nil
}

func (s *TestXKMSService) GetKey(ctx context.Context, backend, keyID string) (*xkms.GetKeyResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[keyID]
	if !ok {
		return nil, errors.New("key not found")
	}

	return &xkms.GetKeyResponse{
		KeyInfo: xkms.KeyInfo{
			KeyID:   key.keyID,
			KeyType: key.keyType,
		},
	}, nil
}

func (s *TestXKMSService) DeleteKey(ctx context.Context, backend, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.keys[keyID]; !ok {
		return errors.New("key not found")
	}
	delete(s.keys, keyID)
	return nil
}

func (s *TestXKMSService) Sign(ctx context.Context, req *xkms.SignRequest) (*xkms.SignResponse, error) {
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

	return &xkms.SignResponse{Signature: signature}, nil
}

func (s *TestXKMSService) Verify(ctx context.Context, req *xkms.VerifyRequest) (*xkms.VerifyResponse, error) {
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

	return &xkms.VerifyResponse{Valid: valid}, nil
}

func (s *TestXKMSService) Encrypt(ctx context.Context, req *xkms.EncryptRequest) (*xkms.EncryptResponse, error) {
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

	return &xkms.EncryptResponse{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
	}, nil
}

func (s *TestXKMSService) Decrypt(ctx context.Context, req *xkms.DecryptRequest) (*xkms.DecryptResponse, error) {
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

	return &xkms.DecryptResponse{Plaintext: plaintext}, nil
}

func (s *TestXKMSService) EncryptAsym(ctx context.Context, req *xkms.EncryptAsymRequest) (*xkms.EncryptAsymResponse, error) {
	return nil, errors.New("asymmetric encryption not implemented in test service")
}

func (s *TestXKMSService) GetCertificate(ctx context.Context, backend, keyID string) (*xkms.GetCertificateResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, ok := s.certificates[keyID]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return &xkms.GetCertificateResponse{KeyID: keyID, CertificatePEM: string(cert)}, nil
}

func (s *TestXKMSService) SaveCertificate(ctx context.Context, req *xkms.SaveCertificateRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certificates[req.KeyID] = []byte(req.CertificatePEM)
	return nil
}

func (s *TestXKMSService) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.certificates, keyID)
	return nil
}

func (s *TestXKMSService) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.certificates[keyID]
	return ok, nil
}

func (s *TestXKMSService) ImportKey(ctx context.Context, req *xkms.ImportKeyRequest) (*xkms.ImportKeyResponse, error) {
	return &xkms.ImportKeyResponse{Success: true, KeyID: req.KeyID}, nil
}

func (s *TestXKMSService) ExportKey(ctx context.Context, req *xkms.ExportKeyRequest) (*xkms.ExportKeyResponse, error) {
	return &xkms.ExportKeyResponse{KeyID: req.KeyID}, nil
}

func (s *TestXKMSService) RotateKey(ctx context.Context, req *xkms.RotateKeyRequest) (*xkms.RotateKeyResponse, error) {
	return &xkms.RotateKeyResponse{Success: true, KeyID: req.KeyID}, nil
}

func (s *TestXKMSService) GetImportParameters(ctx context.Context, req *xkms.GetImportParametersRequest) (*xkms.GetImportParametersResponse, error) {
	return &xkms.GetImportParametersResponse{}, nil
}

func (s *TestXKMSService) WrapKey(ctx context.Context, req *xkms.WrapKeyRequest) (*xkms.WrapKeyResponse, error) {
	return &xkms.WrapKeyResponse{}, nil
}

func (s *TestXKMSService) UnwrapKey(ctx context.Context, req *xkms.UnwrapKeyRequest) (*xkms.UnwrapKeyResponse, error) {
	return &xkms.UnwrapKeyResponse{}, nil
}

func (s *TestXKMSService) CopyKey(ctx context.Context, req *xkms.CopyKeyRequest) (*xkms.CopyKeyResponse, error) {
	return &xkms.CopyKeyResponse{Success: true}, nil
}

func (s *TestXKMSService) ListCertificates(ctx context.Context, backend string, _ ...transport.ListOption) (*xkms.ListCertificatesResponse, error) {
	return &xkms.ListCertificatesResponse{}, nil
}

func (s *TestXKMSService) SaveCertificateChain(ctx context.Context, req *xkms.SaveCertificateChainRequest) error {
	return nil
}

func (s *TestXKMSService) GetCertificateChain(ctx context.Context, backend, keyID string) (*xkms.GetCertificateChainResponse, error) {
	return &xkms.GetCertificateChainResponse{KeyID: keyID}, nil
}

func (s *TestXKMSService) GetTLSCertificate(ctx context.Context, backend, keyID string) (*xkms.GetTLSCertificateResponse, error) {
	return &xkms.GetTLSCertificateResponse{KeyID: keyID}, nil
}

func (s *TestXKMSService) Seal(ctx context.Context, req *xkms.SealRequest) (*xkms.SealResponse, error) {
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

	return &xkms.SealResponse{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
	}, nil
}

func (s *TestXKMSService) Unseal(ctx context.Context, req *xkms.UnsealRequest) (*xkms.UnsealResponse, error) {
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

	return &xkms.UnsealResponse{Plaintext: plaintext}, nil
}

func (s *TestXKMSService) CanSeal(ctx context.Context, backend string) (*xkms.CanSealResponse, error) {
	return &xkms.CanSealResponse{CanSeal: true, Backend: backend}, nil
}

// User management operations

func (s *TestXKMSService) ListUsers(ctx context.Context, _ ...transport.ListOption) (*xkms.ListUsersResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]xkms.UserInfo, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, xkms.UserInfo{
			Username:    u.username,
			DisplayName: u.displayName,
			Role:        u.role,
			Enabled:     u.enabled,
			CreatedAt:   u.createdAt,
			LastLogin:   u.lastLogin,
		})
	}
	return &xkms.ListUsersResponse{Users: users}, nil
}

func (s *TestXKMSService) GetUser(ctx context.Context, username string) (*xkms.GetUserResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}

	return &xkms.GetUserResponse{
		User: xkms.UserInfo{
			Username:    u.username,
			DisplayName: u.displayName,
			Role:        u.role,
			Enabled:     u.enabled,
			CreatedAt:   u.createdAt,
			LastLogin:   u.lastLogin,
		},
	}, nil
}

func (s *TestXKMSService) DeleteUser(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[username]; !ok {
		return ErrUserNotFound
	}
	delete(s.users, username)
	return nil
}

func (s *TestXKMSService) EnableUser(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[username]
	if !ok {
		return ErrUserNotFound
	}
	u.enabled = true
	return nil
}

func (s *TestXKMSService) DisableUser(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[username]
	if !ok {
		return ErrUserNotFound
	}
	u.enabled = false
	return nil
}

func (s *TestXKMSService) ListUserCredentials(ctx context.Context, username string) (*xkms.ListUserCredentialsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}

	credentials := make([]xkms.CredentialInfo, len(u.credentials))
	for i, c := range u.credentials {
		credentials[i] = xkms.CredentialInfo{
			ID:          c.id,
			DisplayName: c.displayName,
			CreatedAt:   c.createdAt,
			LastUsed:    c.lastUsed,
		}
	}

	return &xkms.ListUserCredentialsResponse{Credentials: credentials}, nil
}

// Authentication flow operations (FIDO2/WebAuthn server-side)

func (s *TestXKMSService) BeginRegistration(ctx context.Context, req *xkms.BeginRegistrationRequest) (*xkms.BeginRegistrationResponse, error) {
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

	return &xkms.BeginRegistrationResponse{
		Challenge: string(challenge),
		UserID:    string(userID),
		RPID:      req.RPID,
		RPName:    req.RPName,
		CredentialParams: []xkms.CredentialParam{
			{Type: "public-key", Alg: -7},   // ES256
			{Type: "public-key", Alg: -257}, // RS256
		},
	}, nil
}

func (s *TestXKMSService) FinishRegistration(ctx context.Context, req *xkms.FinishRegistrationRequest) (*xkms.FinishRegistrationResponse, error) {
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

	return &xkms.FinishRegistrationResponse{
		Success:      true,
		CredentialID: req.CredentialID,
		Message:      "Registration successful",
	}, nil
}

func (s *TestXKMSService) BeginAuthentication(ctx context.Context, req *xkms.BeginAuthenticationRequest) (*xkms.BeginAuthenticationResponse, error) {
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

	return &xkms.BeginAuthenticationResponse{
		Challenge:     string(challenge),
		RPID:          req.RPID,
		CredentialIDs: credentialIDs,
	}, nil
}

func (s *TestXKMSService) FinishAuthentication(ctx context.Context, req *xkms.FinishAuthenticationRequest) (*xkms.FinishAuthenticationResponse, error) {
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
		return &xkms.FinishAuthenticationResponse{
			Success: false,
			Message: "Credential not found",
		}, nil
	}

	// Update last login
	now := time.Now()
	u.lastLogin = &now

	// Generate mock JWT token
	token := fmt.Sprintf("test-jwt-token-%s-%d", req.Username, time.Now().Unix())

	return &xkms.FinishAuthenticationResponse{
		Success: true,
		Token:   token,
		Message: "Authentication successful",
	}, nil
}

// DeriveKey derives a key using the specified algorithm and parameters.
func (s *TestXKMSService) DeriveKey(ctx context.Context, req *xkms.DeriveKeyRequest) (*xkms.DeriveKeyResponse, error) {
	// For integration testing, return a mock derived key
	// In a real implementation, this would use proper KDF algorithms
	derivedKey := make([]byte, req.KeyLength)
	if _, err := rand.Read(derivedKey); err != nil {
		return nil, fmt.Errorf("failed to generate derived key: %w", err)
	}

	return &xkms.DeriveKeyResponse{
		DerivedKey: derivedKey,
		Algorithm:  req.Algorithm,
		KeyLength:  req.KeyLength,
	}, nil
}

// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key.
func (s *TestXKMSService) DeriveKeyECDH(ctx context.Context, req *xkms.DeriveKeyECDHRequest) (*xkms.DeriveKeyECDHResponse, error) {
	s.mu.RLock()
	key, exists := s.keys[req.KeyID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("key not found: %s", req.KeyID)
	}

	ecKey, ok := key.privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key %s is not an ECDSA key", req.KeyID)
	}

	// Parse peer public key
	peerPubKey, err := x509.ParsePKIXPublicKey(req.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer public key: %w", err)
	}

	peerECKey, ok := peerPubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("peer public key is not an ECDSA key")
	}

	// Perform ECDH
	sharedX, _ := ecKey.Curve.ScalarMult(peerECKey.X, peerECKey.Y, ecKey.D.Bytes())

	// Derive key using simple hash (in production, use proper KDF)
	keyLength := req.KeyLength
	if keyLength == 0 {
		keyLength = 32
	}

	hash := sha256.Sum256(sharedX.Bytes())
	derivedKey := hash[:keyLength]

	return &xkms.DeriveKeyECDHResponse{
		DerivedKey: derivedKey,
	}, nil
}

// ExportKeyMaterial exports raw symmetric key bytes for extractable keys.
func (s *TestXKMSService) ExportKeyMaterial(ctx context.Context, req *xkms.ExportKeyMaterialRequest) (*xkms.ExportKeyMaterialResponse, error) {
	s.mu.RLock()
	key, exists := s.keys[req.KeyID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("key not found: %s", req.KeyID)
	}

	if key.symmetric == nil {
		return nil, fmt.Errorf("key %s is not a symmetric key", req.KeyID)
	}

	if !key.exportable {
		return nil, fmt.Errorf("key %s is not extractable", req.KeyID)
	}

	return &xkms.ExportKeyMaterialResponse{
		KeyMaterial: key.symmetric,
	}, nil
}

// WrapKeyByID wraps a target key using a wrapping key, both identified by key IDs.
func (s *TestXKMSService) WrapKeyByID(ctx context.Context, req *xkms.WrapKeyByIDRequest) (*xkms.WrapKeyByIDResponse, error) {
	// For integration testing, return a mock wrapped key
	return &xkms.WrapKeyByIDResponse{
		WrappedKey: []byte("mock-wrapped-key-material"),
	}, nil
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
func (s *TestXKMSService) UnwrapKeyByID(ctx context.Context, req *xkms.UnwrapKeyByIDRequest) (*xkms.UnwrapKeyByIDResponse, error) {
	// For integration testing, create a new key from the "unwrapped" material
	return &xkms.UnwrapKeyByIDResponse{
		KeyID:   req.TargetKeyID,
		Backend: req.TargetKeyBackend,
		Success: true,
	}, nil
}

// AttestKey requests key attestation from a backend.
func (s *TestXKMSService) AttestKey(ctx context.Context, req *xkms.AttestKeyRequest) (*xkms.AttestKeyResponse, error) {
	return &xkms.AttestKeyResponse{}, nil
}

// GetCABundle retrieves the CA certificate bundle.
func (s *TestXKMSService) GetCABundle(ctx context.Context, req *xkms.GetCABundleRequest) (*xkms.GetCABundleResponse, error) {
	return &xkms.GetCABundleResponse{}, nil
}

// GetCACertificate retrieves the CA certificate.
func (s *TestXKMSService) GetCACertificate(ctx context.Context, req *xkms.GetCACertificateRequest) (*xkms.GetCACertificateResponse, error) {
	return &xkms.GetCACertificateResponse{}, nil
}

// SignCSR signs a certificate signing request.
func (s *TestXKMSService) SignCSR(ctx context.Context, req *xkms.SignCSRRequest) (*xkms.SignCSRResponse, error) {
	return &xkms.SignCSRResponse{}, nil
}

// IssueCertificate issues a new certificate.
func (s *TestXKMSService) IssueCertificate(ctx context.Context, req *xkms.IssueCertificateRequest) (*xkms.IssueCertificateResponse, error) {
	return &xkms.IssueCertificateResponse{}, nil
}

// RevokeCertificate revokes a certificate.
func (s *TestXKMSService) RevokeCertificate(ctx context.Context, req *xkms.RevokeCertificateRequest) (*xkms.RevokeCertificateResponse, error) {
	return &xkms.RevokeCertificateResponse{}, nil
}

// GenerateCRL generates a certificate revocation list.
func (s *TestXKMSService) GenerateCRL(ctx context.Context, req *xkms.GenerateCRLRequest) (*xkms.GenerateCRLResponse, error) {
	return &xkms.GenerateCRLResponse{}, nil
}

// IsRevoked checks if a certificate is revoked.
func (s *TestXKMSService) IsRevoked(ctx context.Context, req *xkms.IsRevokedRequest) (*xkms.IsRevokedResponse, error) {
	return &xkms.IsRevokedResponse{}, nil
}

// TCG CA operations

// IssueEKCertificate issues an Endorsement Key certificate.
func (s *TestXKMSService) IssueEKCertificate(ctx context.Context, req *xkms.IssueEKCertificateRequest) (*xkms.IssueEKCertificateResponse, error) {
	return nil, ErrNotImplemented
}

// IssueAKCertificate issues an Attestation Key certificate.
func (s *TestXKMSService) IssueAKCertificate(ctx context.Context, req *xkms.IssueAKCertificateRequest) (*xkms.IssueAKCertificateResponse, error) {
	return nil, ErrNotImplemented
}

// SignTCGCSR signs a TCG-CSR-IDEVID.
func (s *TestXKMSService) SignTCGCSR(ctx context.Context, req *xkms.SignTCGCSRRequest) (*xkms.SignTCGCSRResponse, error) {
	return nil, ErrNotImplemented
}

// EnrollDevice performs complete TCG device enrollment.
func (s *TestXKMSService) EnrollDevice(ctx context.Context, req *xkms.EnrollDeviceRequest) (*xkms.EnrollDeviceResponse, error) {
	return nil, ErrNotImplemented
}

// PIV operations

func (s *TestXKMSService) ListPIVSlots(ctx context.Context, req *xkms.ListPIVSlotsRequest) (*xkms.ListPIVSlotsResponse, error) {
	return &xkms.ListPIVSlotsResponse{}, nil
}

func (s *TestXKMSService) GetPIVCertificate(ctx context.Context, req *xkms.GetPIVCertificateRequest) (*xkms.GetPIVCertificateResponse, error) {
	return &xkms.GetPIVCertificateResponse{Slot: req.Slot}, nil
}

func (s *TestXKMSService) StorePIVCertificate(ctx context.Context, req *xkms.StorePIVCertificateRequest) error {
	return nil
}

func (s *TestXKMSService) DeletePIVCertificate(ctx context.Context, req *xkms.DeletePIVCertificateRequest) error {
	return nil
}

func (s *TestXKMSService) GeneratePIVKey(ctx context.Context, req *xkms.GeneratePIVKeyRequest) (*xkms.GeneratePIVKeyResponse, error) {
	return &xkms.GeneratePIVKeyResponse{Slot: req.Slot}, nil
}

func (s *TestXKMSService) ImportPIVCertificate(ctx context.Context, req *xkms.StorePIVCertificateRequest) error {
	return nil
}

func (s *TestXKMSService) ExportPIVCertificate(ctx context.Context, req *xkms.GetPIVCertificateRequest) (*xkms.GetPIVCertificateResponse, error) {
	return &xkms.GetPIVCertificateResponse{Slot: req.Slot}, nil
}

func (s *TestXKMSService) GeneratePIVCSR(ctx context.Context, req *xkms.GeneratePIVCSRRequest) (*xkms.GeneratePIVCSRResponse, error) {
	return &xkms.GeneratePIVCSRResponse{Slot: req.Slot}, nil
}

// Barrier operations

func (s *TestXKMSService) BarrierInitialize(ctx context.Context, req *xkms.BarrierInitializeRequest) error {
	return nil
}

func (s *TestXKMSService) BarrierUnseal(ctx context.Context, req *xkms.BarrierUnsealRequest) error {
	return nil
}

func (s *TestXKMSService) BarrierSeal(ctx context.Context) error {
	return nil
}

func (s *TestXKMSService) BarrierStatus(ctx context.Context) (*xkms.BarrierStatusResponse, error) {
	return &xkms.BarrierStatusResponse{Sealed: false, Strategy: "test"}, nil
}

func (s *TestXKMSService) BarrierInitializeShamir(ctx context.Context, req *xkms.BarrierInitializeShamirRequest) (*xkms.BarrierInitializeShamirResponse, error) {
	return &xkms.BarrierInitializeShamirResponse{
		Threshold:   req.Threshold,
		TotalShares: req.TotalShares,
	}, nil
}

func (s *TestXKMSService) BarrierUnsealWithShare(ctx context.Context, req *xkms.BarrierUnsealShareRequest) (*xkms.BarrierUnsealShareResponse, error) {
	return &xkms.BarrierUnsealShareResponse{Required: 1, Submitted: 1, Complete: true}, nil
}

func (s *TestXKMSService) BarrierUnsealWithShares(ctx context.Context, req *xkms.BarrierUnsealSharesRequest) error {
	return nil
}

// BarrierShamirListShares returns Shamir share metadata.
func (s *TestXKMSService) BarrierShamirListShares(_ context.Context) (*xkms.BarrierShamirSharesResponse, error) {
	return nil, nil
}

// BarrierShamirDeleteShare deletes a Shamir share by index.
func (s *TestXKMSService) BarrierShamirDeleteShare(_ context.Context, _ *xkms.BarrierShamirDeleteShareRequest) error {
	return nil
}

// BarrierShamirDeleteAllShares deletes all Shamir shares.
func (s *TestXKMSService) BarrierShamirDeleteAllShares(_ context.Context) error {
	return nil
}

// BarrierShamirVerify verifies Shamir share integrity.
func (s *TestXKMSService) BarrierShamirVerify(_ context.Context) error {
	return nil
}

// BarrierRekey re-encrypts the barrier with a new root key.
func (s *TestXKMSService) BarrierRekey(_ context.Context, _ *xkms.BarrierRekeyRequest) (*xkms.BarrierRekeyResponse, error) {
	return nil, nil
}

// BarrierGenerateRecoveryKeys generates recovery keys.
func (s *TestXKMSService) BarrierGenerateRecoveryKeys(_ context.Context, _ *xkms.BarrierGenerateRecoveryKeysRequest) (*xkms.BarrierRecoveryKeysResponse, error) {
	return nil, nil
}

// BarrierRecoverWithKeys recovers the barrier using recovery keys.
func (s *TestXKMSService) BarrierRecoverWithKeys(_ context.Context, _ *xkms.BarrierRecoverWithKeysRequest) error {
	return nil
}

// BarrierDeleteRecoveryKeys deletes all recovery keys.
func (s *TestXKMSService) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return nil
}

// BarrierHasRecoveryKeys checks if recovery keys exist.
func (s *TestXKMSService) BarrierHasRecoveryKeys(_ context.Context) (*xkms.BarrierHasRecoveryKeysResponse, error) {
	return nil, nil
}

// BarrierGenerateRootToken generates a root token.
func (s *TestXKMSService) BarrierGenerateRootToken(_ context.Context, _ *xkms.BarrierGenerateRootTokenRequest) (*xkms.BarrierRootTokenResponse, error) {
	return nil, nil
}

// PIN operations

func (s *TestXKMSService) SetSOPIN(ctx context.Context, req *xkms.SetSOPINRequest) error {
	return nil
}

func (s *TestXKMSService) SetUserPIN(ctx context.Context, req *xkms.SetUserPINRequest) error {
	return nil
}

func (s *TestXKMSService) ChangeSOPIN(ctx context.Context, req *xkms.ChangeSOPINRequest) error {
	return nil
}

func (s *TestXKMSService) ChangeUserPIN(ctx context.Context, req *xkms.ChangeUserPINRequest) error {
	return nil
}

func (s *TestXKMSService) VerifySOPIN(ctx context.Context, req *xkms.VerifySOPINRequest) error {
	return nil
}

func (s *TestXKMSService) VerifyUserPIN(ctx context.Context, req *xkms.VerifyUserPINRequest) error {
	return nil
}

func (s *TestXKMSService) GetLockoutStatus(ctx context.Context) (*xkms.LockoutStatusResponse, error) {
	return &xkms.LockoutStatusResponse{MaxAttempts: 10}, nil
}

func (s *TestXKMSService) ResetLockout(ctx context.Context, req *xkms.ResetLockoutRequest) error {
	return nil
}

// Password store operations

func (s *TestXKMSService) PasswordAdd(ctx context.Context, req *xkms.PasswordAddRequest) (*xkms.PasswordAddResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) PasswordGet(ctx context.Context, req *xkms.PasswordGetRequest) (*xkms.PasswordGetResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) PasswordList(ctx context.Context, req *xkms.PasswordListRequest) (*xkms.PasswordListResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) PasswordUpdate(ctx context.Context, req *xkms.PasswordUpdateRequest) error {
	return ErrNotImplemented
}

func (s *TestXKMSService) PasswordDelete(ctx context.Context, req *xkms.PasswordDeleteRequest) error {
	return ErrNotImplemented
}

func (s *TestXKMSService) PasswordStoreUnlock(ctx context.Context, req *xkms.PasswordStoreUnlockRequest) error {
	return ErrNotImplemented
}

func (s *TestXKMSService) PasswordStoreLock(ctx context.Context) error {
	return ErrNotImplemented
}

func (s *TestXKMSService) PasswordStoreStatus(ctx context.Context) (*xkms.PasswordStoreStatusResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) PasswordStoreSetAccessMode(ctx context.Context, req *xkms.PasswordStoreSetAccessModeRequest) error {
	return ErrNotImplemented
}

func (s *TestXKMSService) PasswordGenerate(ctx context.Context, req *xkms.PasswordGenerateRequest) (*xkms.PasswordGenerateResponse, error) {
	return nil, ErrNotImplemented
}

// Platform store operations

func (s *TestXKMSService) SealStorePut(ctx context.Context, req *xkms.SealStorePutRequest) error {
	return ErrNotImplemented
}

func (s *TestXKMSService) SealStoreGet(ctx context.Context, req *xkms.SealStoreGetRequest) (*xkms.SealStoreGetResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) SealStoreDelete(ctx context.Context, req *xkms.SealStoreDeleteRequest) error {
	return ErrNotImplemented
}

func (s *TestXKMSService) SealStoreList(ctx context.Context) (*xkms.SealStoreListResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) SealStoreReseal(ctx context.Context, req *xkms.SealStoreResealRequest) error {
	return ErrNotImplemented
}

func (s *TestXKMSService) SealStoreStatus(ctx context.Context) (*xkms.SealStoreStatusResponse, error) {
	return nil, ErrNotImplemented
}

// Policy operations

func (s *TestXKMSService) PolicyCreate(ctx context.Context, req *xkms.PolicyCreateRequest) (*xkms.PolicyCreateResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) PolicyGet(ctx context.Context, req *xkms.PolicyGetRequest) (*xkms.PolicyGetResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) PolicyList(ctx context.Context) (*xkms.PolicyListResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) PolicyDelete(ctx context.Context, req *xkms.PolicyDeleteRequest) error {
	return ErrNotImplemented
}

func (s *TestXKMSService) PolicyRefresh(ctx context.Context, req *xkms.PolicyRefreshRequest) (*xkms.PolicyGetResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) PolicyVerify(ctx context.Context, req *xkms.PolicyVerifyRequest) (*xkms.PolicyVerifyResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) PolicyExport(ctx context.Context, req *xkms.PolicyExportRequest) (*xkms.PolicyExportResponse, error) {
	return nil, ErrNotImplemented
}

// Custodian group operations

// CreateCustodianGroup creates a new custodian group.
func (s *TestXKMSService) CreateCustodianGroup(ctx context.Context, req *xkms.CreateCustodianGroupRequest) (*xkms.CreateCustodianGroupResponse, error) {
	return nil, ErrNotImplemented
}

// GetCustodianGroup retrieves a custodian group by ID.
func (s *TestXKMSService) GetCustodianGroup(ctx context.Context, groupID string) (*xkms.GetCustodianGroupResponse, error) {
	return nil, ErrNotImplemented
}

// ListCustodianGroups lists all custodian groups.
func (s *TestXKMSService) ListCustodianGroups(ctx context.Context) (*xkms.ListCustodianGroupsResponse, error) {
	return nil, ErrNotImplemented
}

// DeleteCustodianGroup deletes a custodian group.
func (s *TestXKMSService) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	return ErrNotImplemented
}

// AddCustodianMember adds a member to a custodian group.
func (s *TestXKMSService) AddCustodianMember(ctx context.Context, req *xkms.AddCustodianMemberRequest) (*xkms.AddCustodianMemberResponse, error) {
	return nil, ErrNotImplemented
}

// RemoveCustodianMember removes a member from a custodian group.
func (s *TestXKMSService) RemoveCustodianMember(ctx context.Context, req *xkms.RemoveCustodianMemberRequest) error {
	return ErrNotImplemented
}

// DistributeShares distributes Shamir shares to custodian group members.
func (s *TestXKMSService) DistributeShares(ctx context.Context, req *xkms.DistributeSharesRequest) (*xkms.DistributeSharesResponse, error) {
	return nil, ErrNotImplemented
}

// Share operations

// SubmitShare submits a received Shamir share back to the server.
func (s *TestXKMSService) SubmitShare(ctx context.Context, req *xkms.SubmitShareRequest) (*xkms.SubmitShareResponse, error) {
	return nil, ErrNotImplemented
}

// ListShares lists shares available for the authenticated user.
func (s *TestXKMSService) ListShares(ctx context.Context) (*xkms.ListSharesResponse, error) {
	return nil, ErrNotImplemented
}

// GetShareCollectionStatus returns the collection status for a group.
func (s *TestXKMSService) GetShareCollectionStatus(ctx context.Context, groupID string) (*xkms.ShareCollectionStatus, error) {
	return nil, ErrNotImplemented
}

// Tenant operations

// CreateTenant creates a new tenant.
func (s *TestXKMSService) CreateTenant(ctx context.Context, req *xkms.CreateTenantRequest) (*xkms.CreateTenantResponse, error) {
	return nil, ErrNotImplemented
}

// GetTenant retrieves a tenant by ID.
func (s *TestXKMSService) GetTenant(ctx context.Context, tenantID string) (*xkms.GetTenantResponse, error) {
	return nil, ErrNotImplemented
}

// ListTenants lists all tenants.
func (s *TestXKMSService) ListTenants(ctx context.Context) (*xkms.ListTenantsResponse, error) {
	return nil, ErrNotImplemented
}

// DeleteTenant deletes a tenant.
func (s *TestXKMSService) DeleteTenant(ctx context.Context, tenantID string) error {
	return ErrNotImplemented
}

// TenantBarrierInit initializes a per-tenant barrier.
func (s *TestXKMSService) TenantBarrierInit(ctx context.Context, req *xkms.TenantBarrierInitRequest) error {
	return ErrNotImplemented
}

// TenantBarrierUnseal unseals a per-tenant barrier.
func (s *TestXKMSService) TenantBarrierUnseal(ctx context.Context, req *xkms.TenantBarrierUnsealRequest) error {
	return ErrNotImplemented
}

// Init ceremony operations

// GetInitStatus returns the current init ceremony state.
func (s *TestXKMSService) GetInitStatus(ctx context.Context) (*xkms.InitStatusResponse, error) {
	return nil, ErrNotImplemented
}

// ClaimCertBegin begins the certificate claim process for an officer.
func (s *TestXKMSService) ClaimCertBegin(ctx context.Context, req *xkms.ClaimCertBeginRequest) (*xkms.ClaimCertBeginResponse, error) {
	return nil, ErrNotImplemented
}

// ClaimCertComplete completes the certificate claim by verifying the officer's signature.
func (s *TestXKMSService) ClaimCertComplete(ctx context.Context, req *xkms.ClaimCertCompleteRequest) (*xkms.ClaimCertCompleteResponse, error) {
	return nil, ErrNotImplemented
}

// ClaimShare retrieves the Shamir share for the named officer.
func (s *TestXKMSService) ClaimShare(ctx context.Context, req *xkms.ClaimShareRequest) (*xkms.ClaimShareResponse, error) {
	return nil, ErrNotImplemented
}

// SignCSRInit signs a CSR during initialization with SO authorization.
func (s *TestXKMSService) SignCSRInit(ctx context.Context, req *xkms.SignCSRInitRequest) (*xkms.SignCSRInitResponse, error) {
	return nil, ErrNotImplemented
}

// Credential management operations

// SubmitCredential submits a credential for manual mode.
func (s *TestXKMSService) SubmitCredential(ctx context.Context, req *xkms.CredentialSubmitRequest) (*xkms.CredentialSubmitResponse, error) {
	return nil, ErrNotImplemented
}

// GetCredentialStrategy returns the configured credential strategy.
func (s *TestXKMSService) GetCredentialStrategy(ctx context.Context) (*xkms.CredentialStrategyResponse, error) {
	return nil, ErrNotImplemented
}
