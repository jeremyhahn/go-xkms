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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// MockKeyBackend is a test implementation of KeyBackend for interface compliance tests.
type MockKeyBackend struct {
	mu     sync.RWMutex
	keys   map[string]*mockStoredKey
	closed bool
}

type mockStoredKey struct {
	info       *KeyInfo
	privateKey interface{} // crypto.PrivateKey
}

// NewMockKeyBackend creates a new mock backend for testing.
func NewMockKeyBackend() *MockKeyBackend {
	return &MockKeyBackend{
		keys: make(map[string]*mockStoredKey),
	}
}

func (m *MockKeyBackend) ListKeys(ctx context.Context) ([]*KeyInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrBackendClosed
	}

	result := make([]*KeyInfo, 0, len(m.keys))
	for _, k := range m.keys {
		result = append(result, k.info)
	}
	return result, nil
}

func (m *MockKeyBackend) GetPublicKey(ctx context.Context, keyID string) (ssh.PublicKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrBackendClosed
	}

	k, ok := m.keys[keyID]
	if !ok {
		return nil, ErrBackendKeyNotFound
	}
	return k.info.PublicKey, nil
}

func (m *MockKeyBackend) Sign(ctx context.Context, keyID string, data []byte, algorithm string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrBackendClosed
	}

	k, ok := m.keys[keyID]
	if !ok {
		return nil, ErrBackendKeyNotFound
	}

	// For mock, we just return a dummy signature
	// Real implementations would use the private key
	_ = k.privateKey
	return []byte("mock-signature"), nil
}

func (m *MockKeyBackend) GenerateKey(ctx context.Context, keyID string, keyType KeyType, opts *GenerateOptions) (*KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrBackendClosed
	}

	if _, exists := m.keys[keyID]; exists {
		return nil, ErrBackendKeyExists
	}

	if !IsValidKeyType(keyType) {
		return nil, ErrBackendInvalidKeyType
	}

	if opts != nil {
		if err := opts.Validate(keyType); err != nil {
			return nil, err
		}
	}

	var privateKey interface{}
	var sshPubKey ssh.PublicKey
	var err error

	switch keyType {
	case KeyTypeEd25519:
		pubKey, privKey, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return nil, ErrBackendGenerateFailed
		}
		privateKey = privKey
		sshPubKey, err = ssh.NewPublicKey(pubKey)
	case KeyTypeRSA:
		bits := types.RSAKeySize3072
		if opts != nil && opts.Bits != 0 {
			bits = opts.Bits
		}
		privKey, genErr := rsa.GenerateKey(rand.Reader, bits)
		if genErr != nil {
			return nil, ErrBackendGenerateFailed
		}
		privateKey = privKey
		sshPubKey, err = ssh.NewPublicKey(&privKey.PublicKey)
	case KeyTypeECDSA:
		curve := elliptic.P256()
		if opts != nil && opts.Curve != "" {
			switch opts.Curve {
			case types.CurveP256.String():
				curve = elliptic.P256()
			case types.CurveP384.String():
				curve = elliptic.P384()
			case types.CurveP521.String():
				curve = elliptic.P521()
			}
		}
		privKey, genErr := ecdsa.GenerateKey(curve, rand.Reader)
		if genErr != nil {
			return nil, ErrBackendGenerateFailed
		}
		privateKey = privKey
		sshPubKey, err = ssh.NewPublicKey(&privKey.PublicKey)
	default:
		return nil, ErrBackendInvalidKeyType
	}

	if err != nil {
		return nil, ErrBackendGenerateFailed
	}

	var comment string
	if opts != nil {
		comment = opts.Comment
	}

	info := &KeyInfo{
		KeyID:       keyID,
		KeyType:     keyType,
		Fingerprint: ssh.FingerprintSHA256(sshPubKey),
		PublicKey:   sshPubKey,
		Comment:     comment,
		CreatedAt:   time.Now().Unix(),
	}

	m.keys[keyID] = &mockStoredKey{
		info:       info,
		privateKey: privateKey,
	}

	return info, nil
}

func (m *MockKeyBackend) ImportKey(ctx context.Context, keyID string, privateKeyPEM []byte) (*KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrBackendClosed
	}

	if _, exists := m.keys[keyID]; exists {
		return nil, ErrBackendKeyExists
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, ErrBackendInvalidKeyData
	}

	var privateKey interface{}
	var sshPubKey ssh.PublicKey
	var keyType KeyType
	var err error

	// Try parsing as PKCS8 first
	privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 (RSA)
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try EC private key
			privateKey, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, ErrBackendInvalidKeyData
			}
		}
	}

	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		keyType = KeyTypeRSA
		sshPubKey, err = ssh.NewPublicKey(&k.PublicKey)
	case *ecdsa.PrivateKey:
		keyType = KeyTypeECDSA
		sshPubKey, err = ssh.NewPublicKey(&k.PublicKey)
	case ed25519.PrivateKey:
		keyType = KeyTypeEd25519
		sshPubKey, err = ssh.NewPublicKey(k.Public())
	default:
		return nil, ErrBackendInvalidKeyData
	}

	if err != nil {
		return nil, ErrBackendImportFailed
	}

	info := &KeyInfo{
		KeyID:       keyID,
		KeyType:     keyType,
		Fingerprint: ssh.FingerprintSHA256(sshPubKey),
		PublicKey:   sshPubKey,
		CreatedAt:   time.Now().Unix(),
	}

	m.keys[keyID] = &mockStoredKey{
		info:       info,
		privateKey: privateKey,
	}

	return info, nil
}

func (m *MockKeyBackend) DeleteKey(ctx context.Context, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrBackendClosed
	}

	if _, exists := m.keys[keyID]; !exists {
		return ErrBackendKeyNotFound
	}

	delete(m.keys, keyID)
	return nil
}

func (m *MockKeyBackend) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	m.keys = nil
	return nil
}

// Verify MockKeyBackend implements KeyBackend at compile time.
var _ KeyBackend = (*MockKeyBackend)(nil)

// TestKeyBackendInterface tests the KeyBackend interface contract.
func TestKeyBackendInterface(t *testing.T) {
	t.Run("ListKeys", func(t *testing.T) {
		testBackendListKeys(t, NewMockKeyBackend())
	})

	t.Run("GetPublicKey", func(t *testing.T) {
		testBackendGetPublicKey(t, NewMockKeyBackend())
	})

	t.Run("Sign", func(t *testing.T) {
		testBackendSign(t, NewMockKeyBackend())
	})

	t.Run("GenerateKey", func(t *testing.T) {
		testBackendGenerateKey(t, NewMockKeyBackend())
	})

	t.Run("ImportKey", func(t *testing.T) {
		testBackendImportKey(t, NewMockKeyBackend())
	})

	t.Run("DeleteKey", func(t *testing.T) {
		testBackendDeleteKey(t, NewMockKeyBackend())
	})

	t.Run("Close", func(t *testing.T) {
		testBackendClose(t, NewMockKeyBackend())
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		testBackendConcurrentAccess(t, NewMockKeyBackend())
	})
}

func testBackendListKeys(t *testing.T, backend KeyBackend) {
	ctx := context.Background()

	// Empty backend should return empty list
	keys, err := backend.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys on empty backend failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}

	// Generate a key and list again
	_, err = backend.GenerateKey(ctx, "test-key-1", KeyTypeEd25519, nil)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keys, err = backend.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}

	// Generate another key
	_, err = backend.GenerateKey(ctx, "test-key-2", KeyTypeRSA, &GenerateOptions{Bits: 2048})
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keys, err = backend.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func testBackendGetPublicKey(t *testing.T, backend KeyBackend) {
	ctx := context.Background()

	// Non-existent key should return ErrBackendKeyNotFound
	_, err := backend.GetPublicKey(ctx, "non-existent")
	if !errors.Is(err, ErrBackendKeyNotFound) {
		t.Errorf("expected ErrBackendKeyNotFound, got %v", err)
	}

	// Generate a key and retrieve its public key
	info, err := backend.GenerateKey(ctx, "test-key", KeyTypeEd25519, nil)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	pubKey, err := backend.GetPublicKey(ctx, "test-key")
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}

	// Verify the public key matches
	if ssh.FingerprintSHA256(pubKey) != ssh.FingerprintSHA256(info.PublicKey) {
		t.Errorf("fingerprint mismatch")
	}
}

func testBackendSign(t *testing.T, backend KeyBackend) {
	ctx := context.Background()

	// Sign with non-existent key should fail
	_, err := backend.Sign(ctx, "non-existent", []byte("data"), "ed25519")
	if !errors.Is(err, ErrBackendKeyNotFound) {
		t.Errorf("expected ErrBackendKeyNotFound, got %v", err)
	}

	// Generate key and sign
	_, err = backend.GenerateKey(ctx, "sign-key", KeyTypeEd25519, nil)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	sig, err := backend.Sign(ctx, "sign-key", []byte("test data"), "ed25519")
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Error("signature is empty")
	}
}

func testBackendGenerateKey(t *testing.T, backend KeyBackend) {
	ctx := context.Background()

	testCases := []struct {
		name    string
		keyID   string
		keyType KeyType
		opts    *GenerateOptions
		wantErr error
	}{
		{
			name:    "Ed25519 key",
			keyID:   "ed25519-key",
			keyType: KeyTypeEd25519,
			opts:    nil,
		},
		{
			name:    "RSA 2048 key",
			keyID:   "rsa-2048-key",
			keyType: KeyTypeRSA,
			opts:    &GenerateOptions{Bits: 2048},
		},
		{
			name:    "RSA 3072 key",
			keyID:   "rsa-3072-key",
			keyType: KeyTypeRSA,
			opts:    &GenerateOptions{Bits: 3072},
		},
		{
			name:    "RSA 4096 key",
			keyID:   "rsa-4096-key",
			keyType: KeyTypeRSA,
			opts:    &GenerateOptions{Bits: 4096},
		},
		{
			name:    "ECDSA P-256 key",
			keyID:   "ecdsa-p256-key",
			keyType: KeyTypeECDSA,
			opts:    &GenerateOptions{Curve: "P-256"},
		},
		{
			name:    "ECDSA P-384 key",
			keyID:   "ecdsa-p384-key",
			keyType: KeyTypeECDSA,
			opts:    &GenerateOptions{Curve: "P-384"},
		},
		{
			name:    "ECDSA P-521 key",
			keyID:   "ecdsa-p521-key",
			keyType: KeyTypeECDSA,
			opts:    &GenerateOptions{Curve: "P-521"},
		},
		{
			name:    "invalid key type",
			keyID:   "invalid-key",
			keyType: KeyType("invalid"),
			wantErr: ErrBackendInvalidKeyType,
		},
		{
			name:    "invalid RSA bits",
			keyID:   "invalid-rsa",
			keyType: KeyTypeRSA,
			opts:    &GenerateOptions{Bits: 1024},
			wantErr: ErrBackendInvalidKeySize,
		},
		{
			name:    "invalid curve",
			keyID:   "invalid-curve",
			keyType: KeyTypeECDSA,
			opts:    &GenerateOptions{Curve: "P-128"},
			wantErr: ErrBackendInvalidCurve,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := backend.GenerateKey(ctx, tc.keyID, tc.keyType, tc.opts)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			if info.KeyID != tc.keyID {
				t.Errorf("KeyID mismatch: got %s, want %s", info.KeyID, tc.keyID)
			}
			if info.KeyType != tc.keyType {
				t.Errorf("KeyType mismatch: got %s, want %s", info.KeyType, tc.keyType)
			}
			if info.PublicKey == nil {
				t.Error("PublicKey is nil")
			}
		})
	}

	// Test duplicate key ID
	_, err := backend.GenerateKey(ctx, "ed25519-key", KeyTypeEd25519, nil)
	if !errors.Is(err, ErrBackendKeyExists) {
		t.Errorf("expected ErrBackendKeyExists for duplicate key ID, got %v", err)
	}
}

func testBackendImportKey(t *testing.T, backend KeyBackend) {
	ctx := context.Background()

	// Generate a test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	rsaPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	// Import RSA key
	info, err := backend.ImportKey(ctx, "imported-rsa", rsaPEM)
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}
	if info.KeyType != KeyTypeRSA {
		t.Errorf("expected RSA key type, got %s", info.KeyType)
	}

	// Generate a test ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	ecBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("failed to marshal ECDSA key: %v", err)
	}

	ecPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecBytes,
	})

	// Import ECDSA key
	info, err = backend.ImportKey(ctx, "imported-ecdsa", ecPEM)
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}
	if info.KeyType != KeyTypeECDSA {
		t.Errorf("expected ECDSA key type, got %s", info.KeyType)
	}

	// Generate a test Ed25519 key
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	ed25519Bytes, err := x509.MarshalPKCS8PrivateKey(ed25519Key)
	if err != nil {
		t.Fatalf("failed to marshal Ed25519 key: %v", err)
	}

	ed25519PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: ed25519Bytes,
	})

	// Import Ed25519 key
	info, err = backend.ImportKey(ctx, "imported-ed25519", ed25519PEM)
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}
	if info.KeyType != KeyTypeEd25519 {
		t.Errorf("expected Ed25519 key type, got %s", info.KeyType)
	}

	// Test duplicate key ID
	_, err = backend.ImportKey(ctx, "imported-rsa", rsaPEM)
	if !errors.Is(err, ErrBackendKeyExists) {
		t.Errorf("expected ErrBackendKeyExists for duplicate key ID, got %v", err)
	}

	// Test invalid PEM data
	_, err = backend.ImportKey(ctx, "invalid-key", []byte("not a pem"))
	if !errors.Is(err, ErrBackendInvalidKeyData) {
		t.Errorf("expected ErrBackendInvalidKeyData, got %v", err)
	}

	// Test invalid key data in PEM
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("not a valid key"),
	})
	_, err = backend.ImportKey(ctx, "invalid-key-data", invalidPEM)
	if !errors.Is(err, ErrBackendInvalidKeyData) {
		t.Errorf("expected ErrBackendInvalidKeyData, got %v", err)
	}
}

func testBackendDeleteKey(t *testing.T, backend KeyBackend) {
	ctx := context.Background()

	// Delete non-existent key should fail
	err := backend.DeleteKey(ctx, "non-existent")
	if !errors.Is(err, ErrBackendKeyNotFound) {
		t.Errorf("expected ErrBackendKeyNotFound, got %v", err)
	}

	// Generate and delete a key
	_, err = backend.GenerateKey(ctx, "delete-test", KeyTypeEd25519, nil)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	err = backend.DeleteKey(ctx, "delete-test")
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Verify key is gone
	_, err = backend.GetPublicKey(ctx, "delete-test")
	if !errors.Is(err, ErrBackendKeyNotFound) {
		t.Errorf("expected ErrBackendKeyNotFound after delete, got %v", err)
	}
}

func testBackendClose(t *testing.T, backend KeyBackend) {
	ctx := context.Background()

	// Generate a key before closing
	_, err := backend.GenerateKey(ctx, "close-test", KeyTypeEd25519, nil)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Close the backend
	err = backend.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// All operations should fail with ErrBackendClosed
	_, err = backend.ListKeys(ctx)
	if !errors.Is(err, ErrBackendClosed) {
		t.Errorf("ListKeys after close: expected ErrBackendClosed, got %v", err)
	}

	_, err = backend.GetPublicKey(ctx, "close-test")
	if !errors.Is(err, ErrBackendClosed) {
		t.Errorf("GetPublicKey after close: expected ErrBackendClosed, got %v", err)
	}

	_, err = backend.Sign(ctx, "close-test", []byte("data"), "ed25519")
	if !errors.Is(err, ErrBackendClosed) {
		t.Errorf("Sign after close: expected ErrBackendClosed, got %v", err)
	}

	_, err = backend.GenerateKey(ctx, "new-key", KeyTypeEd25519, nil)
	if !errors.Is(err, ErrBackendClosed) {
		t.Errorf("GenerateKey after close: expected ErrBackendClosed, got %v", err)
	}

	_, err = backend.ImportKey(ctx, "import-key", []byte("pem"))
	if !errors.Is(err, ErrBackendClosed) {
		t.Errorf("ImportKey after close: expected ErrBackendClosed, got %v", err)
	}

	err = backend.DeleteKey(ctx, "close-test")
	if !errors.Is(err, ErrBackendClosed) {
		t.Errorf("DeleteKey after close: expected ErrBackendClosed, got %v", err)
	}
}

func testBackendConcurrentAccess(t *testing.T, backend KeyBackend) {
	ctx := context.Background()
	const numGoroutines = 10
	const numOperations = 20

	var wg sync.WaitGroup

	// Generate initial keys
	for i := 0; i < numGoroutines; i++ {
		keyID := string(rune('a'+i)) + "-concurrent"
		_, err := backend.GenerateKey(ctx, keyID, KeyTypeEd25519, nil)
		if err != nil {
			t.Fatalf("failed to generate initial key %s: %v", keyID, err)
		}
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			keyID := string(rune('a'+idx)) + "-concurrent"
			for j := 0; j < numOperations; j++ {
				_, err := backend.GetPublicKey(ctx, keyID)
				if err != nil {
					t.Errorf("concurrent GetPublicKey failed: %v", err)
					return
				}
			}
		}(i)
	}

	// Concurrent list operations
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				_, err := backend.ListKeys(ctx)
				if err != nil {
					t.Errorf("concurrent ListKeys failed: %v", err)
					return
				}
			}
		}()
	}

	// Concurrent sign operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			keyID := string(rune('a'+idx)) + "-concurrent"
			for j := 0; j < numOperations; j++ {
				_, err := backend.Sign(ctx, keyID, []byte("test data"), "ed25519")
				if err != nil {
					t.Errorf("concurrent Sign failed: %v", err)
					return
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestGenerateOptionsValidation tests the GenerateOptions.Validate method.
func TestGenerateOptionsValidation(t *testing.T) {
	testCases := []struct {
		name    string
		keyType KeyType
		opts    *GenerateOptions
		wantErr error
	}{
		{
			name:    "nil options valid for Ed25519",
			keyType: KeyTypeEd25519,
			opts:    nil,
			wantErr: nil,
		},
		{
			name:    "nil options valid for RSA",
			keyType: KeyTypeRSA,
			opts:    nil,
			wantErr: nil,
		},
		{
			name:    "nil options valid for ECDSA",
			keyType: KeyTypeECDSA,
			opts:    nil,
			wantErr: nil,
		},
		{
			name:    "RSA 2048 bits valid",
			keyType: KeyTypeRSA,
			opts:    &GenerateOptions{Bits: 2048},
			wantErr: nil,
		},
		{
			name:    "RSA 3072 bits valid",
			keyType: KeyTypeRSA,
			opts:    &GenerateOptions{Bits: 3072},
			wantErr: nil,
		},
		{
			name:    "RSA 4096 bits valid",
			keyType: KeyTypeRSA,
			opts:    &GenerateOptions{Bits: 4096},
			wantErr: nil,
		},
		{
			name:    "RSA 1024 bits invalid",
			keyType: KeyTypeRSA,
			opts:    &GenerateOptions{Bits: 1024},
			wantErr: ErrBackendInvalidKeySize,
		},
		{
			name:    "RSA 512 bits invalid",
			keyType: KeyTypeRSA,
			opts:    &GenerateOptions{Bits: 512},
			wantErr: ErrBackendInvalidKeySize,
		},
		{
			name:    "ECDSA P-256 valid",
			keyType: KeyTypeECDSA,
			opts:    &GenerateOptions{Curve: "P-256"},
			wantErr: nil,
		},
		{
			name:    "ECDSA P-384 valid",
			keyType: KeyTypeECDSA,
			opts:    &GenerateOptions{Curve: "P-384"},
			wantErr: nil,
		},
		{
			name:    "ECDSA P-521 valid",
			keyType: KeyTypeECDSA,
			opts:    &GenerateOptions{Curve: "P-521"},
			wantErr: nil,
		},
		{
			name:    "ECDSA invalid curve",
			keyType: KeyTypeECDSA,
			opts:    &GenerateOptions{Curve: "P-128"},
			wantErr: ErrBackendInvalidCurve,
		},
		{
			name:    "invalid key type",
			keyType: KeyType("invalid"),
			opts:    &GenerateOptions{},
			wantErr: ErrBackendInvalidKeyType,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.opts.Validate(tc.keyType)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected error %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestDefaultGenerateOptions tests the DefaultGenerateOptions function.
func TestDefaultGenerateOptions(t *testing.T) {
	opts := DefaultGenerateOptions()

	if opts.Bits != types.RSAKeySize3072 {
		t.Errorf("expected default bits %d, got %d", types.RSAKeySize3072, opts.Bits)
	}

	if opts.Curve != types.CurveP256.String() {
		t.Errorf("expected default curve %s, got %s", types.CurveP256.String(), opts.Curve)
	}
}

// TestSignatureAlgorithmForKey tests the SignatureAlgorithmForKey function.
func TestSignatureAlgorithmForKey(t *testing.T) {
	testCases := []struct {
		keyType KeyType
		want    SignatureAlgorithm
	}{
		{KeyTypeEd25519, SigAlgoEd25519},
		{KeyTypeRSA, SigAlgoRSASHA256},
		{KeyTypeECDSA, SigAlgoECDSASHA256},
		{KeyType("unknown"), ""},
	}

	for _, tc := range testCases {
		t.Run(string(tc.keyType), func(t *testing.T) {
			got := SignatureAlgorithmForKey(tc.keyType)
			if got != tc.want {
				t.Errorf("SignatureAlgorithmForKey(%s) = %s, want %s", tc.keyType, got, tc.want)
			}
		})
	}
}

// TestSignatureAlgorithmFromSSH tests the SignatureAlgorithmFromSSH function.
func TestSignatureAlgorithmFromSSH(t *testing.T) {
	testCases := []struct {
		sshKeyType string
		want       SignatureAlgorithm
	}{
		{ssh.KeyAlgoED25519, SigAlgoEd25519},
		{ssh.KeyAlgoRSA, SigAlgoRSASHA256},
		{ssh.KeyAlgoRSASHA256, SigAlgoRSASHA256},
		{ssh.KeyAlgoRSASHA512, SigAlgoRSASHA512},
		{ssh.KeyAlgoECDSA256, SigAlgoECDSASHA256},
		{ssh.KeyAlgoECDSA384, SigAlgoECDSASHA384},
		{ssh.KeyAlgoECDSA521, SigAlgoECDSASHA512},
		{"unknown", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.sshKeyType, func(t *testing.T) {
			got := SignatureAlgorithmFromSSH(tc.sshKeyType)
			if got != tc.want {
				t.Errorf("SignatureAlgorithmFromSSH(%s) = %s, want %s", tc.sshKeyType, got, tc.want)
			}
		})
	}
}

// TestIsValidKeyType tests the IsValidKeyType function.
func TestIsValidKeyType(t *testing.T) {
	testCases := []struct {
		keyType KeyType
		want    bool
	}{
		{KeyTypeRSA, true},
		{KeyTypeECDSA, true},
		{KeyTypeEd25519, true},
		{KeyType("DSA"), false},
		{KeyType("unknown"), false},
		{KeyType(""), false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.keyType), func(t *testing.T) {
			got := IsValidKeyType(tc.keyType)
			if got != tc.want {
				t.Errorf("IsValidKeyType(%s) = %v, want %v", tc.keyType, got, tc.want)
			}
		})
	}
}

// TestKeyTypeFromSSH tests the KeyTypeFromSSH function.
func TestKeyTypeFromSSH(t *testing.T) {
	testCases := []struct {
		sshKeyType string
		want       KeyType
	}{
		{ssh.KeyAlgoRSA, KeyTypeRSA},
		{ssh.KeyAlgoRSASHA256, KeyTypeRSA},
		{ssh.KeyAlgoRSASHA512, KeyTypeRSA},
		{ssh.KeyAlgoECDSA256, KeyTypeECDSA},
		{ssh.KeyAlgoECDSA384, KeyTypeECDSA},
		{ssh.KeyAlgoECDSA521, KeyTypeECDSA},
		{ssh.KeyAlgoED25519, KeyTypeEd25519},
		{"unknown", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.sshKeyType, func(t *testing.T) {
			got := KeyTypeFromSSH(tc.sshKeyType)
			if got != tc.want {
				t.Errorf("KeyTypeFromSSH(%s) = %s, want %s", tc.sshKeyType, got, tc.want)
			}
		})
	}
}

// TestCurveFromSSHKeyType tests the CurveFromSSHKeyType function.
func TestCurveFromSSHKeyType(t *testing.T) {
	testCases := []struct {
		sshKeyType string
		want       string
	}{
		{ssh.KeyAlgoECDSA256, types.CurveP256.String()},
		{ssh.KeyAlgoECDSA384, types.CurveP384.String()},
		{ssh.KeyAlgoECDSA521, types.CurveP521.String()},
		{ssh.KeyAlgoRSA, ""},
		{ssh.KeyAlgoED25519, ""},
		{"unknown", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.sshKeyType, func(t *testing.T) {
			got := CurveFromSSHKeyType(tc.sshKeyType)
			if got != tc.want {
				t.Errorf("CurveFromSSHKeyType(%s) = %s, want %s", tc.sshKeyType, got, tc.want)
			}
		})
	}
}

// TestSignatureAlgorithmString tests the SignatureAlgorithm.String method.
func TestSignatureAlgorithmString(t *testing.T) {
	testCases := []struct {
		algo SignatureAlgorithm
		want string
	}{
		{SigAlgoEd25519, "ed25519"},
		{SigAlgoRSASHA256, "rsa-sha256"},
		{SigAlgoRSASHA512, "rsa-sha512"},
		{SigAlgoECDSASHA256, "ecdsa-sha256"},
		{SigAlgoECDSASHA384, "ecdsa-sha384"},
		{SigAlgoECDSASHA512, "ecdsa-sha512"},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.algo.String()
			if got != tc.want {
				t.Errorf("String() = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestKeyInfoFields tests that KeyInfo struct fields are properly set.
func TestKeyInfoFields(t *testing.T) {
	backend := NewMockKeyBackend()
	ctx := context.Background()

	opts := &GenerateOptions{Comment: "test comment"}
	info, err := backend.GenerateKey(ctx, "field-test", KeyTypeEd25519, opts)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if info.KeyID != "field-test" {
		t.Errorf("KeyID = %s, want field-test", info.KeyID)
	}
	if info.KeyType != KeyTypeEd25519 {
		t.Errorf("KeyType = %s, want Ed25519", info.KeyType)
	}
	if info.Fingerprint == "" {
		t.Error("Fingerprint should not be empty")
	}
	if info.PublicKey == nil {
		t.Error("PublicKey should not be nil")
	}
	if info.Comment != "test comment" {
		t.Errorf("Comment = %s, want 'test comment'", info.Comment)
	}
	if info.CreatedAt == 0 {
		t.Error("CreatedAt should not be zero")
	}
}

// TestKeyTypeToString tests the KeyTypeToString function.
func TestKeyTypeToString(t *testing.T) {
	testCases := []struct {
		keyType KeyType
		want    string
	}{
		{KeyTypeEd25519, "Ed25519"},
		{KeyTypeRSA, "RSA"},
		{KeyTypeECDSA, "ECDSA"},
		{KeyType("unknown"), ""},
		{KeyType(""), ""},
	}

	for _, tc := range testCases {
		t.Run(string(tc.keyType), func(t *testing.T) {
			got := KeyTypeToString(tc.keyType)
			if got != tc.want {
				t.Errorf("KeyTypeToString(%s) = %s, want %s", tc.keyType, got, tc.want)
			}
		})
	}
}

// TestParseKeyType tests the ParseKeyType function.
func TestParseKeyType(t *testing.T) {
	testCases := []struct {
		input string
		want  KeyType
	}{
		{"ed25519", KeyTypeEd25519},
		{"Ed25519", KeyTypeEd25519},
		{"ED25519", KeyTypeEd25519},
		{ssh.KeyAlgoED25519, KeyTypeEd25519},
		{"rsa", KeyTypeRSA},
		{"RSA", KeyTypeRSA},
		{ssh.KeyAlgoRSA, KeyTypeRSA},
		{ssh.KeyAlgoRSASHA256, KeyTypeRSA},
		{ssh.KeyAlgoRSASHA512, KeyTypeRSA},
		{"ecdsa", KeyTypeECDSA},
		{"ECDSA", KeyTypeECDSA},
		{ssh.KeyAlgoECDSA256, KeyTypeECDSA},
		{ssh.KeyAlgoECDSA384, KeyTypeECDSA},
		{ssh.KeyAlgoECDSA521, KeyTypeECDSA},
		{"unknown", ""},
		{"", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			got := ParseKeyType(tc.input)
			if got != tc.want {
				t.Errorf("ParseKeyType(%s) = %s, want %s", tc.input, got, tc.want)
			}
		})
	}
}
