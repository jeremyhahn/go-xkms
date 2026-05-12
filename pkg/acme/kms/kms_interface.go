// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package kms

import (
	"context"
	"sync"
)

// KMSKeyAlgorithm represents supported key algorithms.
type KMSKeyAlgorithm string

const (
	// AlgorithmRSA2048 is RSA with 2048-bit key.
	AlgorithmRSA2048 KMSKeyAlgorithm = "RSA-2048"

	// AlgorithmRSA4096 is RSA with 4096-bit key.
	AlgorithmRSA4096 KMSKeyAlgorithm = "RSA-4096"

	// AlgorithmECDSAP256 is ECDSA with P-256 curve.
	AlgorithmECDSAP256 KMSKeyAlgorithm = "ECDSA-P256"

	// AlgorithmECDSAP384 is ECDSA with P-384 curve.
	AlgorithmECDSAP384 KMSKeyAlgorithm = "ECDSA-P384"

	// AlgorithmED25519 is Ed25519 signature algorithm.
	AlgorithmED25519 KMSKeyAlgorithm = "ED25519"
)

// KMSKeyUsage represents key usage types.
type KMSKeyUsage string

const (
	// KeyUsageSign allows signing operations.
	KeyUsageSign KMSKeyUsage = "sign"

	// KeyUsageVerify allows verification operations.
	KeyUsageVerify KMSKeyUsage = "verify"

	// KeyUsageEncrypt allows encryption operations.
	KeyUsageEncrypt KMSKeyUsage = "encrypt"

	// KeyUsageDecrypt allows decryption operations.
	KeyUsageDecrypt KMSKeyUsage = "decrypt"
)

// KMSKeyInfo contains information about a managed key.
type KMSKeyInfo struct {
	KeyID     string
	Name      string
	Algorithm KMSKeyAlgorithm
	Version   int
	Usage     []KMSKeyUsage
}

// KMSGenerateKeyRequest contains parameters for key generation.
type KMSGenerateKeyRequest struct {
	Name      string
	Algorithm KMSKeyAlgorithm
	Usage     []KMSKeyUsage
}

// KMSGenerateKeyResponse contains the result of key generation.
type KMSGenerateKeyResponse struct {
	KeyID   string
	Version int
}

// KMSRotateKeyResponse contains the result of key rotation.
type KMSRotateKeyResponse struct {
	KeyID      string
	NewVersion int
}

// KMSListKeysResponse contains the result of listing keys.
type KMSListKeysResponse struct {
	Keys []*KMSKeyInfo
}

// KMSClient provides key management operations.
type KMSClient interface {
	// GenerateKey generates a new signing key.
	GenerateKey(ctx context.Context, req *KMSGenerateKeyRequest) (*KMSGenerateKeyResponse, error)

	// GetKey retrieves key information.
	GetKey(ctx context.Context, keyID string) (*KMSKeyInfo, error)

	// ListKeys lists all keys.
	ListKeys(ctx context.Context) (*KMSListKeysResponse, error)

	// RotateKey rotates a key to a new version.
	RotateKey(ctx context.Context, keyID string) (*KMSRotateKeyResponse, error)

	// DeleteKey deletes a key.
	DeleteKey(ctx context.Context, keyID string) error
}

// CryptoHashAlgorithm represents hash algorithms.
type CryptoHashAlgorithm string

const (
	// HashSHA256 is SHA-256.
	HashSHA256 CryptoHashAlgorithm = "SHA-256"

	// HashSHA384 is SHA-384.
	HashSHA384 CryptoHashAlgorithm = "SHA-384"

	// HashSHA512 is SHA-512.
	HashSHA512 CryptoHashAlgorithm = "SHA-512"
)

// CryptoSignRequest contains parameters for signing.
type CryptoSignRequest struct {
	KeyID   string
	Data    []byte
	HashAlg CryptoHashAlgorithm
}

// CryptoSignResponse contains the signature.
type CryptoSignResponse struct {
	Signature []byte
}

// CryptoVerifyRequest contains parameters for verification.
type CryptoVerifyRequest struct {
	KeyID     string
	Data      []byte
	Signature []byte
	HashAlg   CryptoHashAlgorithm
}

// CryptoVerifyResponse contains the verification result.
type CryptoVerifyResponse struct {
	Valid bool
}

// CryptoClient provides cryptographic operations.
type CryptoClient interface {
	// Sign signs data with a key.
	Sign(ctx context.Context, req *CryptoSignRequest) (*CryptoSignResponse, error)

	// Verify verifies a signature.
	Verify(ctx context.Context, req *CryptoVerifyRequest) (*CryptoVerifyResponse, error)
}

// MemoryKMSClient provides an in-memory KMS implementation for testing.
type MemoryKMSClient struct {
	mu     sync.RWMutex
	keys   map[string]*KMSKeyInfo
	nextID int
}

// NewMemoryKMSClient creates a new in-memory KMS client for testing.
func NewMemoryKMSClient() *MemoryKMSClient {
	return &MemoryKMSClient{
		keys:   make(map[string]*KMSKeyInfo),
		nextID: 1,
	}
}

// GenerateKey generates a new key in memory.
func (c *MemoryKMSClient) GenerateKey(ctx context.Context, req *KMSGenerateKeyRequest) (*KMSGenerateKeyResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keyID := req.Name
	if keyID == "" {
		keyID = string(rune('k' + c.nextID))
		c.nextID++
	}

	c.keys[keyID] = &KMSKeyInfo{
		KeyID:     keyID,
		Name:      req.Name,
		Algorithm: req.Algorithm,
		Version:   1,
		Usage:     req.Usage,
	}

	return &KMSGenerateKeyResponse{
		KeyID:   keyID,
		Version: 1,
	}, nil
}

// GetKey retrieves key information.
func (c *MemoryKMSClient) GetKey(ctx context.Context, keyID string) (*KMSKeyInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info, ok := c.keys[keyID]
	if !ok {
		return nil, ErrNotFound.WithContext("key_id", keyID)
	}
	return info, nil
}

// ListKeys lists all keys.
func (c *MemoryKMSClient) ListKeys(ctx context.Context) (*KMSListKeysResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]*KMSKeyInfo, 0, len(c.keys))
	for _, k := range c.keys {
		keys = append(keys, k)
	}
	return &KMSListKeysResponse{Keys: keys}, nil
}

// RotateKey rotates a key.
func (c *MemoryKMSClient) RotateKey(ctx context.Context, keyID string) (*KMSRotateKeyResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	info, ok := c.keys[keyID]
	if !ok {
		return nil, ErrNotFound.WithContext("key_id", keyID)
	}

	info.Version++
	return &KMSRotateKeyResponse{
		KeyID:      keyID,
		NewVersion: info.Version,
	}, nil
}

// DeleteKey deletes a key.
func (c *MemoryKMSClient) DeleteKey(ctx context.Context, keyID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.keys[keyID]; !ok {
		return ErrNotFound.WithContext("key_id", keyID)
	}
	delete(c.keys, keyID)
	return nil
}

// MemoryCryptoClient provides an in-memory Crypto implementation for testing.
type MemoryCryptoClient struct{}

// NewMemoryCryptoClient creates a new in-memory crypto client for testing.
func NewMemoryCryptoClient() *MemoryCryptoClient {
	return &MemoryCryptoClient{}
}

// Sign signs data (returns a dummy signature for testing).
func (c *MemoryCryptoClient) Sign(ctx context.Context, req *CryptoSignRequest) (*CryptoSignResponse, error) {
	// In a real implementation, this would use the key to sign
	// For testing, return a dummy signature
	return &CryptoSignResponse{
		Signature: []byte("mock-signature"),
	}, nil
}

// Verify verifies a signature (always returns true for testing).
func (c *MemoryCryptoClient) Verify(ctx context.Context, req *CryptoVerifyRequest) (*CryptoVerifyResponse, error) {
	// For testing, always verify as true
	return &CryptoVerifyResponse{
		Valid: true,
	}, nil
}

// Verify interface compliance.
var (
	_ KMSClient    = (*MemoryKMSClient)(nil)
	_ CryptoClient = (*MemoryCryptoClient)(nil)
)
