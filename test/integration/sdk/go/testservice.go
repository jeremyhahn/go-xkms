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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	xkmssvc "github.com/jeremyhahn/go-xkms/pkg/xkms"
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
	regSessions  map[string]string // session ID -> username (WebAuthn registration)
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
		return nil, &errs.Wrapped{Msg: "failed to generate seal key", Err: err}
	}

	return &TestXKMSService{
		keys:         make(map[string]*testKey),
		certificates: make(map[string][]byte),
		users:        make(map[string]*testUser),
		regSessions:  make(map[string]string),
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

// Algorithms answers with the algorithm discovery for the one backend this
// service advertises, built by the same function the daemon uses from the
// software backend's declared capability set, so the SDK client sees the
// daemon's shape for a software-only deployment and the discovery agrees
// with ListBackends. The daemon's global capability lookup needs an
// initialised backend registry, which this in-process service replaces, so
// the capabilities are supplied directly.
func (s *TestXKMSService) Algorithms(ctx context.Context) (*transport.AlgorithmsResponse, error) {
	softwareCapabilities := func(name string) (xkms.Capabilities, error) {
		if name != string(xkms.ServiceBackendSoftware) {
			return xkms.Capabilities{}, errors.New("backend not found")
		}
		return xkms.NewSoftwareCapabilities(), nil
	}
	return xkms.ServiceBuildAlgorithmsResponse(
		[]xkms.ServiceBackendType{xkms.ServiceBackendSoftware},
		softwareCapabilities,
	), nil
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
			return nil, &errs.Wrapped{Msg: "failed to generate EC key", Err: err}
		}
		key.privateKey = privateKey
		key.publicKey = &privateKey.PublicKey

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to marshal public key", Err: err}
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
			return nil, &errs.Wrapped{Msg: "failed to generate symmetric key", Err: err}
		}
		key.symmetric = symKey
		key.keyType = "symmetric"
		s.keys[req.KeyID] = key
		return &xkms.GenerateKeyResponse{
			KeyID:   req.KeyID,
			KeyType: "symmetric",
		}, nil

	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported key type: %s", req.KeyType)}
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
		return nil, &errs.Wrapped{Msg: "failed to sign", Err: err}
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

// CreateUser creates a new user record in the in-memory test store.
func (s *TestXKMSService) CreateUser(ctx context.Context, req *xkms.CreateUserRequest) (*xkms.GetUserResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[req.Username]; exists {
		return nil, &errs.Message{Msg: fmt.Sprintf("user %q already exists", req.Username)}
	}

	role := req.Role
	if role == "" {
		role = "user"
	}
	u := &testUser{
		username:    req.Username,
		displayName: req.DisplayName,
		role:        role,
		enabled:     true,
		createdAt:   time.Now(),
		credentials: make([]testCredential, 0),
	}
	s.users[req.Username] = u

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
	if _, exists := s.users[req.Email]; !exists {
		s.users[req.Email] = &testUser{
			username:    req.Email,
			displayName: req.DisplayName,
			role:        "user",
			enabled:     true,
			createdAt:   time.Now(),
			credentials: make([]testCredential, 0),
		}
	}

	// Generate a session ID for the lossless ceremony.
	sessionBytes := make([]byte, 16)
	if _, err := rand.Read(sessionBytes); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate session id", Err: err}
	}
	sessionID := base64.RawURLEncoding.EncodeToString(sessionBytes)

	// Generate challenge and embed it in JSON-marshaled WebAuthn options.
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate challenge", Err: err}
	}
	optionsJSON := fmt.Sprintf(
		`{"publicKey":{"challenge":%q,"rp":{"name":%q},"pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}]}}`,
		base64.RawURLEncoding.EncodeToString(challenge), req.Email,
	)

	// Remember which user this ceremony session belongs to.
	s.regSessions[sessionID] = req.Email

	return &xkms.BeginRegistrationResponse{
		SessionID:   sessionID,
		OptionsJSON: optionsJSON,
	}, nil
}

func (s *TestXKMSService) FinishRegistration(ctx context.Context, req *xkms.FinishRegistrationRequest) (*xkms.FinishRegistrationResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	username, ok := s.regSessions[req.SessionID]
	if !ok {
		return nil, ErrUserNotFound
	}
	delete(s.regSessions, req.SessionID)

	u, ok := s.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}

	// Derive a stable credential ID from the attestation JSON.
	credSum := sha256.Sum256([]byte(req.AttestationJSON))
	credID := base64.RawURLEncoding.EncodeToString(credSum[:])

	// Add credential
	u.credentials = append(u.credentials, testCredential{
		id:          credID,
		displayName: "WebAuthn Credential",
		createdAt:   time.Now(),
	})

	return &xkms.FinishRegistrationResponse{
		Success:      true,
		CredentialID: credID,
		Token:        "test-token",
		Message:      "Registration successful",
	}, nil
}

func (s *TestXKMSService) BeginAuthentication(ctx context.Context, req *xkms.BeginAuthenticationRequest) (*xkms.BeginAuthenticationResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[req.Email]
	if !ok {
		return nil, ErrUserNotFound
	}

	// Generate challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate challenge", Err: err}
	}

	// Get credential IDs
	credentialIDs := make([]string, len(u.credentials))
	for i, c := range u.credentials {
		credentialIDs[i] = c.id
	}

	// The transport now carries an opaque session id plus the JSON-marshaled
	// assertion options (PublicKeyCredentialRequestOptions) rather than the
	// raw challenge/rpid/credential fields. Mirror that session-based shape.
	sessionID := base64.RawURLEncoding.EncodeToString(challenge[:16])
	options := map[string]any{
		"publicKey": map[string]any{
			"challenge":        base64.RawURLEncoding.EncodeToString(challenge),
			"allowCredentials": credentialIDs,
		},
	}
	optsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal authentication options", Err: err}
	}

	return &xkms.BeginAuthenticationResponse{
		SessionID:   sessionID,
		OptionsJSON: string(optsJSON),
	}, nil
}

func (s *TestXKMSService) FinishAuthentication(ctx context.Context, req *xkms.FinishAuthenticationRequest) (*xkms.FinishAuthenticationResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[req.Email]
	if !ok {
		return nil, ErrUserNotFound
	}

	// The asserted credential id now travels inside req.AssertionJSON rather
	// than a dedicated request field; the test double treats any registered
	// credential for the user as a successful assertion.
	credentialFound := len(u.credentials) > 0
	if credentialFound {
		now := time.Now()
		u.credentials[0].lastUsed = &now
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
	token := fmt.Sprintf("test-jwt-token-%s-%d", req.Email, time.Now().Unix())

	return &xkms.FinishAuthenticationResponse{
		Success: true,
		Token:   token,
		Message: "Authentication successful",
	}, nil
}

// Enrollment-invitation redemption (go-xkms#1294 part B). This test double
// creates every account active (see CreateUser) and models no invitation
// lifecycle, so there is nothing for these to delegate to.

// GetInvite resolves invitation metadata.
func (s *TestXKMSService) GetInvite(ctx context.Context, req *xkms.GetInviteRequest) (*xkms.GetInviteResponse, error) {
	return nil, ErrNotImplemented
}

// BeginInviteRegistration opens the invite-authorized WebAuthn registration ceremony.
func (s *TestXKMSService) BeginInviteRegistration(ctx context.Context, req *xkms.BeginInviteRegistrationRequest) (*xkms.BeginInviteRegistrationResponse, error) {
	return nil, ErrNotImplemented
}

// FinishInviteRegistration completes the invite-authorized WebAuthn registration ceremony.
func (s *TestXKMSService) FinishInviteRegistration(ctx context.Context, req *xkms.FinishInviteRegistrationRequest) (*xkms.FinishInviteRegistrationResponse, error) {
	return nil, ErrNotImplemented
}

// ActivateInvitePIV activates an invited account with a presented PIV certificate.
func (s *TestXKMSService) ActivateInvitePIV(ctx context.Context, req *xkms.ActivateInvitePIVRequest) (*xkms.ActivateInvitePIVResponse, error) {
	return nil, ErrNotImplemented
}

// BindUserCert binds an mTLS certificate SPKI thumbprint to a user. The test
// double records nothing and reports success.
func (s *TestXKMSService) BindUserCert(ctx context.Context, username, thumbprint string, notAfterUnix int64) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.users[username]; !ok {
		return ErrUserNotFound
	}
	return nil
}

// DeriveKey derives a key using the specified algorithm and parameters.
func (s *TestXKMSService) DeriveKey(ctx context.Context, req *xkms.DeriveKeyRequest) (*xkms.DeriveKeyResponse, error) {
	// For integration testing, return a mock derived key
	// In a real implementation, this would use proper KDF algorithms
	derivedKey := make([]byte, req.KeyLength)
	if _, err := rand.Read(derivedKey); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate derived key", Err: err}
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
		return nil, &errs.Message{Msg: fmt.Sprintf("key not found: %s", req.KeyID)}
	}

	ecKey, ok := key.privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, &errs.Message{Msg: fmt.Sprintf("key %s is not an ECDSA key", req.KeyID)}
	}

	// Parse peer public key
	peerPubKey, err := x509.ParsePKIXPublicKey(req.PeerPublicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse peer public key", Err: err}
	}

	peerECKey, ok := peerPubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, &errs.Message{Msg: "peer public key is not an ECDSA key"}
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
		return nil, &errs.Message{Msg: fmt.Sprintf("key not found: %s", req.KeyID)}
	}

	if key.symmetric == nil {
		return nil, &errs.Message{Msg: fmt.Sprintf("key %s is not a symmetric key", req.KeyID)}
	}

	if !key.exportable {
		return nil, &errs.Message{Msg: fmt.Sprintf("key %s is not extractable", req.KeyID)}
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

// IssueLAKCertificate issues a Local Attestation Key certificate in the
// WebAuthn Level 2 section 8.3.1 profile (go-xkms#715).
func (s *TestXKMSService) IssueLAKCertificate(ctx context.Context, req *xkms.IssueLAKCertificateRequest) (*xkms.IssueLAKCertificateResponse, error) {
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

// BootstrapListenerKeys reports that no trust-bootstrap listener runs in the
// in-memory test service, which is the contract's answer for a server whose
// listener is not enabled.
func (s *TestXKMSService) BootstrapListenerKeys(ctx context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	return nil, xkmssvc.ErrBootstrapListenerNotEnabled
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

func (s *TestXKMSService) PasswordUpdate(ctx context.Context, req *xkms.PasswordUpdateRequest) (*xkms.PasswordGetResponse, error) {
	return nil, ErrNotImplemented
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

func (s *TestXKMSService) PasswordVaultStatus(ctx context.Context) (*xkms.PasswordVaultStatusResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) PasswordVaultEnroll(ctx context.Context, req *xkms.PasswordVaultEnrollRequest) (*xkms.PasswordVaultEnrollResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) PasswordVaultRotate(ctx context.Context, req *xkms.PasswordVaultRotateRequest) (*xkms.PasswordVaultEnrollResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) PasswordVaultRemoveFactor(ctx context.Context, req *xkms.PasswordVaultRemoveFactorRequest) error {
	return ErrNotImplemented
}

func (s *TestXKMSService) PasswordVaultRecover(ctx context.Context, req *xkms.PasswordVaultRecoverRequest) (*xkms.PasswordVaultEnrollResponse, error) {
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

// Escrow operations

func (s *TestXKMSService) EscrowKey(ctx context.Context, req *xkms.EscrowRequest) ([]*xkms.EscrowReceipt, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) RecoverKey(ctx context.Context, req *xkms.RecoverRequest) (*xkms.RecoverResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) ListEscrowed(ctx context.Context) ([]xkms.EscrowRecord, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) RevokeEscrow(ctx context.Context, escrowID string) error {
	return ErrNotImplemented
}

// Policy operations

func (s *TestXKMSService) ListKeyVersions(context.Context, *xkms.ListKeyVersionsRequest) (*xkms.ListKeyVersionsResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) EnableKeyVersion(context.Context, *xkms.KeyVersionRequest) (*xkms.KeyVersionStateResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) DisableKeyVersion(context.Context, *xkms.KeyVersionRequest) (*xkms.KeyVersionStateResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) RetireKeyVersion(context.Context, *xkms.KeyVersionRequest) (*xkms.KeyVersionStateResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) EnableAllKeyVersions(context.Context, *xkms.AllKeyVersionsRequest) (*xkms.AllKeyVersionsResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) DisableAllKeyVersions(context.Context, *xkms.AllKeyVersionsRequest) (*xkms.AllKeyVersionsResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) RotateScopeKeys(context.Context, *xkms.RotateScopeKeysRequest) (*xkms.RotateScopeKeysResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TPMPolicyCreate(context.Context, *xkms.TPMPolicyCreateRequest) (*xkms.TPMPolicy, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TPMPolicyGet(context.Context, *xkms.TPMPolicyRequest) (*xkms.TPMPolicy, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TPMPolicyList(context.Context, *xkms.TPMPolicyListRequest) (*xkms.TPMPolicyListResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TPMPolicyUpdate(context.Context, *xkms.TPMPolicyRequest) (*xkms.TPMPolicy, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TPMPolicyRevoke(context.Context, *xkms.TPMPolicyRequest) (*xkms.TPMPolicy, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TPMPolicyVerify(context.Context, *xkms.TPMPolicyRequest) (*xkms.TPMPolicyVerifyResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TPMPolicyDelete(context.Context, *xkms.TPMPolicyDeleteRequest) error {
	return ErrNotImplemented
}

func (s *TestXKMSService) TPMPolicyObjects(context.Context, *xkms.TPMPolicyRequest) (*xkms.TPMPolicyObjectsResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TPMPolicySetAutoUnseal(context.Context, *xkms.TPMPolicyAutoUnsealRequest) (*xkms.TPMPolicy, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TPMPolicySetDescription(context.Context, *xkms.TPMPolicyDescriptionRequest) (*xkms.TPMPolicy, error) {
	return nil, ErrNotImplemented
}

// OIDC credential operations are not exercised by this double.
func (*TestXKMSService) OIDCCredentialCreate(context.Context, *xkms.OIDCCredentialCreateRequest) (*xkms.OIDCCredential, error) {
	return nil, ErrNotImplemented
}
func (*TestXKMSService) OIDCCredentialImport(context.Context, *xkms.OIDCCredentialImportRequest) (*xkms.OIDCCredential, error) {
	return nil, ErrNotImplemented
}
func (*TestXKMSService) OIDCCredentialGet(context.Context, *xkms.OIDCCredentialRef) (*xkms.OIDCCredential, error) {
	return nil, ErrNotImplemented
}
func (*TestXKMSService) OIDCCredentialList(context.Context, *xkms.OIDCCredentialListRequest) (*xkms.OIDCCredentialListResponse, error) {
	return nil, ErrNotImplemented
}
func (*TestXKMSService) TrustRootList(context.Context, *xkms.TrustRootListRequest) (*xkms.TrustRootListResponse, error) {
	return nil, ErrNotImplemented
}
func (*TestXKMSService) TrustRootGet(context.Context, *xkms.TrustRootRequest) (*xkms.TrustRoot, error) {
	return nil, ErrNotImplemented
}
func (*TestXKMSService) TrustRootImport(context.Context, *xkms.TrustRootImportRequest) (*xkms.TrustRootImportResponse, error) {
	return nil, ErrNotImplemented
}
func (*TestXKMSService) TrustRootQuarantine(context.Context, *xkms.TrustRootRequest) (*xkms.TrustRoot, error) {
	return nil, ErrNotImplemented
}
func (*TestXKMSService) TrustRootRemove(context.Context, *xkms.TrustRootRequest) error {
	return ErrNotImplemented
}
func (*TestXKMSService) OIDCCredentialDelete(context.Context, *xkms.OIDCCredentialRef) error {
	return ErrNotImplemented
}
func (*TestXKMSService) OIDCCredentialRefresh(context.Context, *xkms.OIDCCredentialRef) (*xkms.OIDCCredential, error) {
	return nil, ErrNotImplemented
}
func (*TestXKMSService) OIDCCredentialGetAccessToken(context.Context, *xkms.OIDCCredentialRef) (*xkms.OIDCAccessToken, error) {
	return nil, ErrNotImplemented
}
func (*TestXKMSService) OIDCCredentialDeviceStart(context.Context, *xkms.OIDCCredentialRef) (*xkms.OIDCCredential, error) {
	return nil, ErrNotImplemented
}
func (*TestXKMSService) OIDCCredentialDevicePoll(context.Context, *xkms.OIDCCredentialRef) (*xkms.OIDCCredential, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TPMObjectPolicy(context.Context, *xkms.TPMObjectPolicyRequest) (*xkms.TPMObjectPolicyResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TPMPolicyRotateAuthority(context.Context, *xkms.TPMAuthorityRotateRequest) (*xkms.TPMAuthorityRotateResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) GetTenantTPMMode(context.Context, string) (*xkms.TenantTPMModeResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) SetTenantTPMMode(context.Context, *xkms.SetTenantTPMModeRequest) (*xkms.TenantTPMModeResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TenantVTPMStatus(context.Context, string) (*xkms.TenantVTPMStatusResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TenantVTPMStart(context.Context, string) (*xkms.TenantVTPMStatusResponse, error) {
	return nil, ErrNotImplemented
}

func (s *TestXKMSService) TenantVTPMStop(context.Context, string) (*xkms.TenantVTPMStatusResponse, error) {
	return nil, ErrNotImplemented
}

// Backup operations (go-xkms#728)

// Custodian group operations

// Share operations

// Audit operations

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

// UpdateTenantEntitlements updates a tenant's feature entitlements. No-op in the
// in-memory test service; satisfies the transport.XKMSServicer interface.
func (s *TestXKMSService) UpdateTenantEntitlements(_ context.Context, _ *xkms.UpdateTenantEntitlementsRequest) (*xkms.UpdateTenantEntitlementsResponse, error) {
	return &xkms.UpdateTenantEntitlementsResponse{}, nil
}

// UpdateTenantQuotas updates a tenant's resource quotas. No-op in the in-memory
// test service; satisfies the transport.XKMSServicer interface.
func (s *TestXKMSService) UpdateTenantQuotas(_ context.Context, _ *xkms.UpdateTenantQuotasRequest) (*xkms.UpdateTenantQuotasResponse, error) {
	return &xkms.UpdateTenantQuotasResponse{}, nil
}

// Init ceremony operations

// Credential management operations

// SubmitCredential submits a credential for manual mode.
func (s *TestXKMSService) SubmitCredential(ctx context.Context, req *xkms.CredentialSubmitRequest) (*xkms.CredentialSubmitResponse, error) {
	return nil, ErrNotImplemented
}

// GetCredentialStrategy returns the configured credential strategy.
func (s *TestXKMSService) GetCredentialStrategy(ctx context.Context) (*xkms.CredentialStrategyResponse, error) {
	return nil, ErrNotImplemented
}
