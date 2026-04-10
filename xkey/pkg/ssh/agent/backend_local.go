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
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

const (
	// keyStoragePrefix is the path prefix for SSH keys in storage.
	keyStoragePrefix = "ssh/keys/"

	// DefaultLocalRSABits is the default RSA key size for LocalBackend.
	DefaultLocalRSABits = 4096

	// DefaultLocalECDSACurve is the default ECDSA curve for LocalBackend.
	DefaultLocalECDSACurve = types.CurveP256
)

// LocalBackend errors.
var (
	ErrLocalBackendNilConfig   = errors.New("ssh/agent/local: config is nil")
	ErrLocalBackendNilStorage  = errors.New("ssh/agent/local: storage backend is nil")
	ErrLocalBackendMarshal     = errors.New("ssh/agent/local: marshal failed")
	ErrLocalBackendUnmarshal   = errors.New("ssh/agent/local: unmarshal failed")
	ErrLocalBackendUnsupported = errors.New("ssh/agent/local: unsupported operation")
)

// storedKey represents a key persisted to storage.
type storedKey struct {
	ID            string    `json:"id"`
	KeyType       string    `json:"key_type"`
	PrivateKeyPEM string    `json:"private_key_pem"`
	PublicKeyPEM  string    `json:"public_key_pem"`
	Comment       string    `json:"comment,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// LocalBackendConfig configures the LocalBackend.
type LocalBackendConfig struct {
	// Backend is the storage backend for persistence.
	Backend storage.Backend
}

// LocalBackend stores SSH keys locally using a storage.Backend.
// It implements the KeyBackend interface for standalone mode without
// requiring a xkmsd server.
type LocalBackend struct {
	mu      sync.RWMutex
	backend storage.Backend
	closed  bool
}

// NewLocalBackend creates a new LocalBackend with the given storage backend.
func NewLocalBackend(cfg *LocalBackendConfig) (*LocalBackend, error) {
	if cfg == nil {
		return nil, ErrLocalBackendNilConfig
	}
	if cfg.Backend == nil {
		return nil, ErrLocalBackendNilStorage
	}

	return &LocalBackend{
		backend: cfg.Backend,
	}, nil
}

// ListKeys returns all SSH-compatible keys managed by this backend.
func (b *LocalBackend) ListKeys(ctx context.Context) ([]*KeyInfo, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrBackendClosed
	}

	keys, err := b.backend.List(context.Background(), keyStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendListFailed, err)
	}

	var keyInfos []*KeyInfo
	for _, key := range keys {
		// Extract key ID from storage path
		keyID := extractKeyIDFromPath(key)
		if keyID == "" {
			continue
		}

		sk, err := b.loadKeyLocked(keyID)
		if err != nil {
			continue
		}

		// Parse the public key
		pubKey, err := b.parseStoredPublicKey(sk)
		if err != nil {
			continue
		}

		keyInfos = append(keyInfos, &KeyInfo{
			KeyID:       sk.ID,
			KeyType:     ParseKeyType(sk.KeyType),
			Fingerprint: ssh.FingerprintSHA256(pubKey),
			PublicKey:   pubKey,
			Comment:     sk.Comment,
			CreatedAt:   sk.CreatedAt.Unix(),
		})
	}

	// Sort by ID for consistent ordering
	sort.Slice(keyInfos, func(i, j int) bool {
		return keyInfos[i].KeyID < keyInfos[j].KeyID
	})

	return keyInfos, nil
}

// GetPublicKey returns the SSH public key for the given key ID.
func (b *LocalBackend) GetPublicKey(ctx context.Context, keyID string) (ssh.PublicKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrBackendClosed
	}

	sk, err := b.loadKeyLocked(keyID)
	if err != nil {
		return nil, err
	}

	return b.parseStoredPublicKey(sk)
}

// Sign signs data with the specified key using the given algorithm.
func (b *LocalBackend) Sign(ctx context.Context, keyID string, data []byte, algorithm string) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrBackendClosed
	}

	// Load the key
	sk, err := b.loadKeyLocked(keyID)
	if err != nil {
		return nil, err
	}

	// Parse the private key
	privateKey, err := parsePrivateKeyFromPEM([]byte(sk.PrivateKeyPEM))
	if err != nil {
		return nil, err
	}

	// Sign based on key type
	switch priv := privateKey.(type) {
	case ed25519.PrivateKey:
		// Ed25519 signs raw data, not a hash
		return ed25519.Sign(priv, data), nil

	case *rsa.PrivateKey:
		h, cryptoHash, err := getHashForRSASign(algorithm)
		if err != nil {
			return nil, err
		}
		h.Write(data)
		digest := h.Sum(nil)
		return rsa.SignPKCS1v15(rand.Reader, priv, cryptoHash, digest)

	case *ecdsa.PrivateKey:
		h, err := getHashForECDSASign(priv.Curve, algorithm)
		if err != nil {
			return nil, err
		}
		h.Write(data)
		digest := h.Sum(nil)
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBackendSignFailed, err)
		}
		return sig, nil

	default:
		return nil, fmt.Errorf("%w: %T", ErrBackendInvalidKeyType, privateKey)
	}
}

// GenerateKey generates a new SSH key with the specified parameters.
func (b *LocalBackend) GenerateKey(ctx context.Context, keyID string, keyType KeyType, opts *GenerateOptions) (*KeyInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrBackendClosed
	}

	if keyID == "" {
		return nil, ErrBackendEmptyKeyID
	}

	// Check if key already exists
	storageKey := keyStoragePath(keyID)
	exists, err := b.backend.Exists(context.Background(), storageKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendGenerateFailed, err)
	}
	if exists {
		return nil, ErrBackendKeyExists
	}

	// Validate key type
	if !IsValidKeyType(keyType) {
		return nil, ErrBackendInvalidKeyType
	}

	// Validate options
	if err := opts.Validate(keyType); err != nil {
		return nil, err
	}

	// Apply defaults
	if opts == nil {
		opts = DefaultGenerateOptions()
	}

	// Generate the key pair
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	var keyTypeStr string

	switch keyType {
	case KeyTypeEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("%w: ed25519 generation failed: %v", ErrBackendGenerateFailed, err)
		}
		privateKey = priv
		publicKey = pub
		keyTypeStr = "ed25519"

	case KeyTypeRSA:
		bits := opts.Bits
		if bits == 0 {
			bits = DefaultLocalRSABits
		}
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("%w: RSA generation failed: %v", ErrBackendGenerateFailed, err)
		}
		privateKey = priv
		publicKey = &priv.PublicKey
		keyTypeStr = "rsa"

	case KeyTypeECDSA:
		curveName := opts.Curve
		if curveName == "" {
			curveName = DefaultLocalECDSACurve.String()
		}
		curve, err := getCurveByName(curveName)
		if err != nil {
			return nil, err
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("%w: ECDSA generation failed: %v", ErrBackendGenerateFailed, err)
		}
		privateKey = priv
		publicKey = &priv.PublicKey
		keyTypeStr = "ecdsa"

	default:
		return nil, ErrBackendInvalidKeyType
	}

	// Encode keys to PEM
	privPEM, err := encodePrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, err
	}

	pubPEM, err := encodePublicKeyToPEM(publicKey)
	if err != nil {
		return nil, err
	}

	// Store the key
	now := time.Now().UTC()
	sk := &storedKey{
		ID:            keyID,
		KeyType:       keyTypeStr,
		PrivateKeyPEM: privPEM,
		PublicKeyPEM:  pubPEM,
		Comment:       opts.Comment,
		CreatedAt:     now,
	}

	if err := b.storeKeyLocked(sk); err != nil {
		return nil, err
	}

	// Convert to SSH public key
	sshPubKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to convert to SSH key: %v", ErrBackendGenerateFailed, err)
	}

	return &KeyInfo{
		KeyID:     keyID,
		KeyType:   ParseKeyType(keyTypeStr),
		PublicKey: sshPubKey,
	}, nil
}

// ImportKey imports an existing SSH private key.
func (b *LocalBackend) ImportKey(ctx context.Context, keyID string, privateKeyPEM []byte) (*KeyInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrBackendClosed
	}

	if keyID == "" {
		return nil, ErrBackendEmptyKeyID
	}

	// Check if key already exists
	storageKey := keyStoragePath(keyID)
	exists, err := b.backend.Exists(context.Background(), storageKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendImportFailed, err)
	}
	if exists {
		return nil, ErrBackendKeyExists
	}

	// Parse the private key
	privateKey, err := parsePrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendInvalidKeyData, err)
	}

	// Determine key type and extract public key
	var publicKey crypto.PublicKey
	var keyTypeStr string

	switch priv := privateKey.(type) {
	case ed25519.PrivateKey:
		publicKey = priv.Public()
		keyTypeStr = "ed25519"
	case *rsa.PrivateKey:
		publicKey = &priv.PublicKey
		keyTypeStr = "rsa"
	case *ecdsa.PrivateKey:
		publicKey = &priv.PublicKey
		keyTypeStr = "ecdsa"
	default:
		return nil, fmt.Errorf("%w: %T", ErrBackendInvalidKeyType, privateKey)
	}

	// Re-encode private key to normalize format
	privPEM, err := encodePrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, err
	}

	pubPEM, err := encodePublicKeyToPEM(publicKey)
	if err != nil {
		return nil, err
	}

	// Store the key
	now := time.Now().UTC()
	sk := &storedKey{
		ID:            keyID,
		KeyType:       keyTypeStr,
		PrivateKeyPEM: privPEM,
		PublicKeyPEM:  pubPEM,
		CreatedAt:     now,
	}

	if err := b.storeKeyLocked(sk); err != nil {
		return nil, err
	}

	// Convert to SSH public key
	sshPubKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to convert to SSH key: %v", ErrBackendImportFailed, err)
	}

	return &KeyInfo{
		KeyID:     keyID,
		KeyType:   ParseKeyType(keyTypeStr),
		PublicKey: sshPubKey,
	}, nil
}

// DeleteKey deletes the key with the given ID.
func (b *LocalBackend) DeleteKey(ctx context.Context, keyID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrBackendClosed
	}

	storageKey := keyStoragePath(keyID)
	exists, err := b.backend.Exists(context.Background(), storageKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackendDeleteFailed, err)
	}
	if !exists {
		return ErrBackendKeyNotFound
	}

	return b.backend.Delete(context.Background(), storageKey)
}

// Close releases resources held by the backend.
func (b *LocalBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	return b.backend.Close()
}

// storeKeyLocked stores a key to the backend.
// Must be called with the write lock held.
func (b *LocalBackend) storeKeyLocked(sk *storedKey) error {
	data, err := json.Marshal(sk)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLocalBackendMarshal, err)
	}

	storageKey := keyStoragePath(sk.ID)
	return b.backend.Put(context.Background(), storageKey, data)
}

// loadKeyLocked loads a key from the backend.
// Must be called with at least a read lock held.
func (b *LocalBackend) loadKeyLocked(keyID string) (*storedKey, error) {
	storageKey := keyStoragePath(keyID)
	data, err := b.backend.Get(context.Background(), storageKey)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrBackendKeyNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrBackendGetKeyFailed, err)
	}

	var sk storedKey
	if err := json.Unmarshal(data, &sk); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLocalBackendUnmarshal, err)
	}

	return &sk, nil
}

// parseStoredPublicKey parses the SSH public key from a stored key.
func (b *LocalBackend) parseStoredPublicKey(sk *storedKey) (ssh.PublicKey, error) {
	block, _ := pem.Decode([]byte(sk.PublicKeyPEM))
	if block == nil {
		return nil, ErrBackendInvalidPEM
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendParseFailed, err)
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to convert to SSH key: %v", ErrBackendParseFailed, err)
	}

	return sshPubKey, nil
}

// keyStoragePath returns the storage path for a key ID.
func keyStoragePath(keyID string) string {
	return keyStoragePrefix + keyID + ".json"
}

// extractKeyIDFromPath extracts the key ID from a storage path.
func extractKeyIDFromPath(storagePath string) string {
	if !strings.HasPrefix(storagePath, keyStoragePrefix) {
		return ""
	}
	name := strings.TrimPrefix(storagePath, keyStoragePrefix)
	return strings.TrimSuffix(name, ".json")
}

// getCurveByName returns the elliptic curve for the given curve name.
func getCurveByName(curveName string) (elliptic.Curve, error) {
	switch curveName {
	case types.CurveP256.String(), "P256", "p256":
		return elliptic.P256(), nil
	case types.CurveP384.String(), "P384", "p384":
		return elliptic.P384(), nil
	case types.CurveP521.String(), "P521", "p521":
		return elliptic.P521(), nil
	default:
		return nil, ErrBackendInvalidCurve
	}
}

// encodePrivateKeyToPEM encodes a private key to PEM format.
func encodePrivateKeyToPEM(privateKey crypto.PrivateKey) (string, error) {
	var block *pem.Block

	switch priv := privateKey.(type) {
	case ed25519.PrivateKey:
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrLocalBackendMarshal, err)
		}
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}

	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(priv)
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: der,
		}

	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrLocalBackendMarshal, err)
		}
		block = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		}

	default:
		return "", fmt.Errorf("%w: %T", ErrBackendInvalidKeyType, privateKey)
	}

	return string(pem.EncodeToMemory(block)), nil
}

// encodePublicKeyToPEM encodes a public key to PEM format.
func encodePublicKeyToPEM(publicKey crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrLocalBackendMarshal, err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// parsePrivateKeyFromPEM parses a PEM-encoded private key.
func parsePrivateKeyFromPEM(pemData []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrBackendInvalidPEM
	}

	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBackendInvalidKeyData, err)
		}
		return normalizePrivateKey(key)

	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBackendInvalidKeyData, err)
		}
		return key, nil

	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBackendInvalidKeyData, err)
		}
		return key, nil

	case "OPENSSH PRIVATE KEY":
		// Parse OpenSSH format
		key, err := ssh.ParseRawPrivateKey(pemData)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBackendInvalidKeyData, err)
		}
		return normalizePrivateKey(key)

	default:
		return nil, fmt.Errorf("%w: unsupported PEM type: %s", ErrBackendInvalidKeyData, block.Type)
	}
}

// normalizePrivateKey converts a parsed private key to a consistent type.
func normalizePrivateKey(key crypto.PrivateKey) (crypto.PrivateKey, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return k, nil
	case *ed25519.PrivateKey:
		return *k, nil
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrBackendInvalidKeyType, key)
	}
}

// getHashForRSASign returns the hash function for RSA signing.
func getHashForRSASign(algorithm string) (hash.Hash, crypto.Hash, error) {
	switch strings.ToLower(algorithm) {
	case "rsa-sha256", "sha256", "sha-256", "":
		return sha256.New(), crypto.SHA256, nil
	case "rsa-sha512", "sha512", "sha-512":
		return sha512.New(), crypto.SHA512, nil
	default:
		return nil, 0, fmt.Errorf("%w: unsupported hash algorithm: %s", ErrBackendSignFailed, algorithm)
	}
}

// getHashForECDSASign returns the hash function for ECDSA signing.
func getHashForECDSASign(curve elliptic.Curve, algorithm string) (hash.Hash, error) {
	// Use curve-appropriate hash if not specified
	if algorithm == "" {
		switch curve {
		case elliptic.P256():
			return sha256.New(), nil
		case elliptic.P384():
			return sha512.New384(), nil
		case elliptic.P521():
			return sha512.New(), nil
		default:
			return sha256.New(), nil
		}
	}

	switch strings.ToLower(algorithm) {
	case "ecdsa-sha256", "sha256", "sha-256":
		return sha256.New(), nil
	case "ecdsa-sha384", "sha384", "sha-384":
		return sha512.New384(), nil
	case "ecdsa-sha512", "sha512", "sha-512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("%w: unsupported hash algorithm: %s", ErrBackendSignFailed, algorithm)
	}
}

// Verify interface compliance at compile time.
var _ KeyBackend = (*LocalBackend)(nil)
