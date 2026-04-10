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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/sdk/go"
)

// KeyInfo contains metadata about an SSH key managed by a KeyBackend.
// This is the canonical type used by the KeyBackend interface.
type KeyInfo struct {
	// KeyID is the unique identifier for this key.
	KeyID string

	// KeyType is the algorithm used by the key (RSA, ECDSA, Ed25519).
	KeyType KeyType

	// Fingerprint is the SSH fingerprint of the public key (SHA256 format).
	Fingerprint string

	// PublicKey is the parsed SSH public key.
	PublicKey ssh.PublicKey

	// Comment is an optional description or label for the key.
	Comment string

	// CreatedAt is the Unix timestamp when the key was created.
	CreatedAt int64
}

// XKMSdBackend provides SSH key operations using the xkmsd SDK client.
// It implements the KeyBackend interface to provide SSH-specific functionality
// including key listing, generation, import, deletion, and signing operations.
type XKMSdBackend struct {
	client  xkms.Client
	backend string
}

// NewXKMSdBackend creates a new XKMSdBackend instance.
// The client must be a connected xkms.Client, and backend specifies
// which xkmsd backend to use (e.g., "software", "tpm2").
func NewXKMSdBackend(client xkms.Client, backend string) (*XKMSdBackend, error) {
	if client == nil {
		return nil, ErrBackendNilClient
	}
	if backend == "" {
		return nil, ErrBackendEmptyName
	}
	return &XKMSdBackend{
		client:  client,
		backend: backend,
	}, nil
}

// Backend returns the backend name.
func (b *XKMSdBackend) Backend() string {
	return b.backend
}

// Client returns the underlying xkms client.
func (b *XKMSdBackend) Client() xkms.Client {
	return b.client
}

// ListKeys returns all SSH-compatible keys from the backend.
// Keys are filtered to only include SSH-compatible types: Ed25519, RSA, and ECDSA.
// Implements KeyBackend.ListKeys.
func (b *XKMSdBackend) ListKeys(ctx context.Context) ([]*KeyInfo, error) {
	resp, err := b.client.ListKeys(ctx, b.backend)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendListFailed, err)
	}

	var keys []*KeyInfo
	for _, ki := range resp.Keys {
		// Filter to SSH-compatible key algorithms only
		// Note: ki.KeyType is the key purpose (SIGNING, ENCRYPTION)
		// ki.Algorithm is the actual algorithm (Ed25519, RSA, ECDSA)
		if !isSSHCompatibleKeyType(ki.Algorithm) {
			continue
		}

		// Get the public key for this key
		pubKey, err := b.GetPublicKey(ctx, ki.KeyID)
		if err != nil {
			// Skip keys we cannot parse
			continue
		}

		fingerprint := ssh.FingerprintSHA256(pubKey)
		keys = append(keys, &KeyInfo{
			KeyID:       ki.KeyID,
			KeyType:     ParseKeyType(ki.Algorithm),
			Fingerprint: fingerprint,
			PublicKey:   pubKey,
			CreatedAt:   0, // xkmsd SDK doesn't expose creation time
		})
	}

	return keys, nil
}

// GetPublicKey retrieves the SSH public key for the specified key ID.
// Implements KeyBackend.GetPublicKey.
func (b *XKMSdBackend) GetPublicKey(ctx context.Context, keyID string) (ssh.PublicKey, error) {
	resp, err := b.client.GetKey(ctx, b.backend, keyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendGetKeyFailed, err)
	}

	if resp.PublicKeyPEM == "" {
		return nil, ErrBackendNoPublicKey
	}

	// Parse the PEM-encoded public key
	block, _ := pem.Decode([]byte(resp.PublicKeyPEM))
	if block == nil {
		return nil, ErrBackendInvalidPEM
	}

	// Parse as crypto.PublicKey first, then convert to ssh.PublicKey
	// Note: resp.KeyType is the key purpose (SIGNING, ENCRYPTION)
	// resp.Algorithm is the actual algorithm (Ed25519, RSA, ECDSA)
	cryptoPubKey, err := parsePublicKeyFromDER(block.Bytes, resp.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendParseFailed, err)
	}

	sshPubKey, err := ssh.NewPublicKey(cryptoPubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to convert to SSH key: %v", ErrBackendParseFailed, err)
	}

	return sshPubKey, nil
}

// Sign signs data with the specified key.
// The algorithm parameter specifies the signature scheme.
// Implements KeyBackend.Sign.
func (b *XKMSdBackend) Sign(ctx context.Context, keyID string, data []byte, algorithm string) ([]byte, error) {
	resp, err := b.client.Sign(ctx, &xkms.SignRequest{
		Backend: b.backend,
		KeyID:   keyID,
		Data:    data,
		Hash:    algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendSignFailed, err)
	}

	return resp.Signature, nil
}

// GenerateKey generates a new SSH key in the backend.
// Supported key types: ed25519, rsa, ecdsa.
// Implements KeyBackend.GenerateKey.
func (b *XKMSdBackend) GenerateKey(ctx context.Context, keyID string, keyType KeyType, opts *GenerateOptions) (*KeyInfo, error) {
	if keyID == "" {
		return nil, ErrBackendEmptyKeyID
	}

	// Validate key type is SSH-compatible
	if !IsValidKeyType(keyType) {
		return nil, fmt.Errorf("%w: %s", ErrBackendUnsupportedKeyType, keyType)
	}

	if opts != nil {
		if err := opts.Validate(keyType); err != nil {
			return nil, err
		}
	} else {
		opts = DefaultGenerateOptions()
	}

	req := &xkms.GenerateKeyRequest{
		KeyID:   keyID,
		Backend: b.backend,
		KeyType: KeyTypeToString(keyType),
	}

	// Set key size or curve based on key type
	switch keyType {
	case KeyTypeRSA:
		if opts.Bits == 0 {
			opts.Bits = types.RSAKeySize4096 // Default to 4096-bit RSA
		}
		req.KeySize = opts.Bits
	case KeyTypeECDSA:
		curve := opts.Curve
		if curve == "" {
			curve = types.CurveP256.String()
		}
		req.Curve = curve
		// KeyType stays as "ECDSA", curve is specified separately
	case KeyTypeEd25519:
		// Ed25519 has a fixed key size, no additional params needed
	}

	resp, err := b.client.GenerateKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendGenerateFailed, err)
	}

	// Use the public key from the response if available
	var pubKey ssh.PublicKey
	if resp.PublicKeyPEM != "" {
		// Parse the public key from the response
		block, _ := pem.Decode([]byte(resp.PublicKeyPEM))
		if block != nil {
			cryptoPubKey, err := parsePublicKeyFromDER(block.Bytes, resp.KeyType)
			if err == nil {
				pubKey, _ = ssh.NewPublicKey(cryptoPubKey)
			}
		}
	}

	// Fallback to GetPublicKey if not in response
	if pubKey == nil {
		pubKey, err = b.GetPublicKey(ctx, keyID)
		if err != nil {
			return nil, fmt.Errorf("%w: key generated but failed to retrieve public key: %v", ErrBackendGenerateFailed, err)
		}
	}

	fingerprint := ssh.FingerprintSHA256(pubKey)
	return &KeyInfo{
		KeyID:       resp.KeyID,
		KeyType:     ParseKeyType(resp.KeyType),
		Fingerprint: fingerprint,
		PublicKey:   pubKey,
		Comment:     opts.Comment,
		CreatedAt:   time.Now().Unix(),
	}, nil
}

// ImportKey imports an existing SSH private key using the BYOK protocol.
// The privateKeyPEM must be a PEM-encoded private key.
// Implements KeyBackend.ImportKey.
//
// The BYOK (Bring Your Own Key) protocol:
// 1. Parse SSH key and convert to PKCS8 DER format (xkmsd expects PKCS8)
// 2. GetImportParameters - Get wrapping public key and import token from xkmsd
// 3. WrapKey - Wrap the key material using the wrapping public key
// 4. ImportKey - Import the wrapped key with the import token
func (b *XKMSdBackend) ImportKey(ctx context.Context, keyID string, privateKeyPEM []byte) (*KeyInfo, error) {
	if keyID == "" {
		return nil, ErrBackendEmptyKeyID
	}

	// Parse the SSH private key to get the crypto.PrivateKey
	rawKey, err := ssh.ParseRawPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse SSH private key: %v", ErrBackendInvalidKeyData, err)
	}

	// Normalize the key type for x509.MarshalPKCS8PrivateKey
	// x509 expects value types, not pointer types for ed25519
	var privateKey interface{}
	var algorithm types.KeyAlgorithmString

	switch k := rawKey.(type) {
	case *rsa.PrivateKey:
		privateKey = k
		algorithm = types.AlgorithmRSA
	case *ecdsa.PrivateKey:
		privateKey = k
		algorithm = types.AlgorithmECDSA
	case ed25519.PrivateKey:
		privateKey = k // Already a value type
		algorithm = types.AlgorithmEd25519
	case *ed25519.PrivateKey:
		privateKey = *k // Dereference to value type (required by x509.MarshalPKCS8PrivateKey)
		algorithm = types.AlgorithmEd25519
	default:
		return nil, fmt.Errorf("%w: unsupported SSH key type: %T", ErrBackendInvalidKeyData, rawKey)
	}

	// Convert to PKCS8 DER format (xkmsd's backend expects PKCS8 DER)
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal key to PKCS8: %v", ErrBackendInvalidKeyData, err)
	}

	// Step 1: Get import parameters (wrapping key and import token)
	// Use RSA_AES_KEY_WRAP_SHA_256 for larger key material (SSH private keys are too large for direct RSA-OAEP)
	// This algorithm: 1) generates random AES key, 2) encrypts key material with AES, 3) wraps AES key with RSA-OAEP
	wrappingAlgorithm := backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256
	importParams, err := b.client.GetImportParameters(ctx, &xkms.GetImportParametersRequest{
		Backend:   b.backend,
		KeyID:     keyID,
		Algorithm: string(wrappingAlgorithm),
		KeyType:   string(algorithm),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get import parameters: %v", ErrBackendImportFailed, err)
	}

	// Step 2: Wrap the PKCS8 DER key material
	wrapResp, err := b.client.WrapKey(ctx, &xkms.WrapKeyRequest{
		Backend:           b.backend,
		KeyMaterial:       pkcs8DER,
		Algorithm:         importParams.Algorithm,
		WrappingPublicKey: importParams.WrappingPublicKey,
		ImportToken:       importParams.ImportToken,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to wrap key: %v", ErrBackendImportFailed, err)
	}

	// Step 3: Import the wrapped key
	req := &xkms.ImportKeyRequest{
		Backend:            b.backend,
		KeyID:              keyID,
		KeyType:            string(algorithm),
		WrappedKeyMaterial: wrapResp.WrappedKeyMaterial,
		ImportToken:        importParams.ImportToken,
		Algorithm:          importParams.Algorithm,
	}

	_, err = b.client.ImportKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendImportFailed, err)
	}

	// Get the public key
	pubKey, err := b.GetPublicKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("%w: key imported but failed to retrieve public key: %v", ErrBackendImportFailed, err)
	}

	fingerprint := ssh.FingerprintSHA256(pubKey)
	return &KeyInfo{
		KeyID:       keyID,
		KeyType:     algorithmToKeyType(algorithm),
		Fingerprint: fingerprint,
		PublicKey:   pubKey,
		CreatedAt:   time.Now().Unix(),
	}, nil
}

// DeleteKey deletes a key from the backend.
// Implements KeyBackend.DeleteKey.
func (b *XKMSdBackend) DeleteKey(ctx context.Context, keyID string) error {
	if keyID == "" {
		return ErrBackendEmptyKeyID
	}

	_, err := b.client.DeleteKey(ctx, b.backend, keyID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackendDeleteFailed, err)
	}

	return nil
}

// Close closes the underlying client connection.
// Implements KeyBackend.Close.
func (b *XKMSdBackend) Close() error {
	return b.client.Close()
}

// isSSHCompatibleKeyType checks if a key type string is compatible with SSH.
// SSH only supports asymmetric signing keys: Ed25519, RSA, and ECDSA.
func isSSHCompatibleKeyType(keyType string) bool {
	normalized := strings.ToLower(keyType)

	// Handle ECDSA curve variants
	if strings.HasPrefix(normalized, "ecdsa") {
		return true
	}

	// Check standard algorithms
	switch normalized {
	case "ed25519", "rsa":
		return true
	default:
		// Also check using the types package
		return types.AlgorithmEd25519.Equals(keyType) ||
			types.AlgorithmRSA.Equals(keyType) ||
			types.AlgorithmECDSA.Equals(keyType)
	}
}

// parsePublicKeyFromDER parses a public key from DER or raw bytes.
// parsePublicKeyFromDER parses a public key from DER or raw bytes.
// keyType should be a types.KeyAlgorithmString value (e.g., "Ed25519", "RSA", "ECDSA").
func parsePublicKeyFromDER(data []byte, keyType string) (crypto.PublicKey, error) {
	// Use types package for case-insensitive algorithm comparison
	if types.AlgorithmEd25519.Equals(keyType) {
		if len(data) == ed25519.PublicKeySize {
			return ed25519.PublicKey(data), nil
		}
		// Try parsing as PKIX
		return parseSubjectPublicKeyInfo(data)
	}

	if types.AlgorithmRSA.Equals(keyType) {
		return parseSubjectPublicKeyInfo(data)
	}

	if types.AlgorithmECDSA.Equals(keyType) || isECDSAVariant(keyType) {
		return parseSubjectPublicKeyInfo(data)
	}

	return nil, fmt.Errorf("unsupported key type: %s", keyType)
}

// isECDSAVariant checks if keyType is an ECDSA curve-specific variant.
func isECDSAVariant(keyType string) bool {
	variants := []string{
		"ecdsa-p256", "ecdsa-p384", "ecdsa-p521",
		"ecdsa-p-256", "ecdsa-p-384", "ecdsa-p-521",
		"ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
	}
	for _, v := range variants {
		if keyType == v {
			return true
		}
	}
	return false
}

// algorithmToKeyType converts a types.KeyAlgorithmString to the SSH agent KeyType.
func algorithmToKeyType(algorithm types.KeyAlgorithmString) KeyType {
	switch algorithm {
	case types.AlgorithmEd25519:
		return KeyTypeEd25519
	case types.AlgorithmRSA:
		return KeyTypeRSA
	case types.AlgorithmECDSA:
		return KeyTypeECDSA
	default:
		return KeyTypeUnknown
	}
}

// detectKeyTypeFromPEM detects the key type from a PEM block.
// Used by standalone backend which doesn't go through xkmsd.
func detectKeyTypeFromPEM(block *pem.Block) string {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return string(types.AlgorithmRSA)
	case "EC PRIVATE KEY":
		return string(types.AlgorithmECDSA)
	case "OPENSSH PRIVATE KEY", "PRIVATE KEY":
		// Need to parse the key to determine type
		// For simplicity, try ed25519 first
		return string(types.AlgorithmEd25519)
	default:
		return ""
	}
}

// Verify XKMSdBackend implements the KeyBackend interface at compile time.
var _ KeyBackend = (*XKMSdBackend)(nil)
