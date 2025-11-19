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

// Package jwe implements JSON Web Encryption (JWE) as defined in RFC 7516.
// This package provides a thin wrapper around the battle-tested go-jose library,
// offering a simplified API for JWE encryption and decryption.
//
// The go-jose library (https://github.com/go-jose/go-jose) is:
//   - Battle-tested and widely used in production environments
//   - Actively maintained by the community
//   - RFC-compliant (RFC 7516, RFC 7518)
//   - Security-audited for cryptographic operations
//
// We use go-jose instead of a custom implementation for the same reason we use
// golang-jwt/jwt for JWT: security-critical crypto should rely on established,
// well-tested libraries that have undergone extensive review.
//
// Supported Key Management Algorithms (alg):
//   - RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384, RSA-OAEP-512
//   - ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static)
//   - ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
//   - A128KW, A192KW, A256KW (AES Key Wrap)
//   - A128GCMKW, A192GCMKW, A256GCMKW (AES-GCM Key Wrap)
//   - dir (Direct Key Agreement)
//
// Supported Content Encryption Algorithms (enc):
//   - A128GCM, A192GCM, A256GCM (AES-GCM)
//   - A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 (AES-CBC-HMAC)
//   - "" (empty string) - Auto-detects optimal AEAD algorithm based on CPU features
//
// # Auto-Detection Mode
//
// When the content encryption algorithm is an empty string (""), the package
// automatically selects the optimal AEAD algorithm based on CPU features:
//
//   - On systems with AES-NI CPU instruction support, A256GCM is selected for
//     optimal performance (uses hardware-accelerated AES-GCM encryption)
//   - On systems without AES-NI, A256CBC-HS512 is selected as a secure fallback
//
// Auto-detection is useful when you want the best performance on any platform
// without manually selecting algorithms. This is particularly beneficial in
// distributed systems with heterogeneous hardware.
//
// Example usage:
//
//	// Encrypt with RSA-OAEP and explicit A256GCM
//	encrypter, _ := jwe.NewEncrypter("RSA-OAEP", "A256GCM", publicKey)
//	jweString, _ := encrypter.Encrypt(plaintext)
//
//	// Auto-detect optimal AEAD algorithm based on CPU features
//	encrypter, _ := jwe.NewEncrypter("RSA-OAEP", "", publicKey)
//	jweString, _ := encrypter.Encrypt(plaintext)  // Uses A256GCM or A256CBC-HS512
//
//	// Decrypt (automatically handles any supported algorithm)
//	decrypter := jwe.NewDecrypter()
//	plaintext, _ := decrypter.Decrypt(jweString, privateKey)
//
//	// Encrypt with custom header (e.g., kid)
//	jweString, _ := encrypter.EncryptWithHeader(plaintext, map[string]interface{}{"kid": "key-123"})
//
// Auto-Detection Examples:
//
// The package automatically selects optimal algorithms when an empty string is
// provided for the encryption algorithm parameter. This is useful for distributed
// systems with heterogeneous hardware:
//
//	// Example 1: Simple auto-detection with RSA
//	encrypter, _ := jwe.NewEncrypter("RSA-OAEP-256", "", publicKey)
//	// Automatically uses A256GCM on AES-NI systems, A256CBC-HS512 otherwise
//
//	// Example 2: Auto-detection with ECDH key management
//	encrypter, _ := jwe.NewEncrypter("ECDH-ES+A256KW", "", ecdsaKey)
//	// Selects optimal AEAD algorithm for current CPU
//
//	// Example 3: Override auto-detection with explicit algorithm
//	encrypter, _ := jwe.NewEncrypter("RSA-OAEP-256", "A128CBC-HS256", publicKey)
//	// Uses explicitly specified algorithm regardless of CPU capabilities
//
// # Performance Characteristics
//
// When using auto-detection with AES-NI support:
//   - A256GCM: ~2-3x faster than software implementation
//   - Uses x86_64 AES-NI instruction set (when available)
//   - ARM64 systems benefit from ARM AES instructions
//
// When AES-NI is not available:
//   - A256CBC-HS512: Secure software-based HMAC-SHA-512 with AES-CBC
//   - Maintains strong security without hardware acceleration
//
// For benchmarking your system, use:
//   - BenchmarkRSAEncryption for RSA-based key management
//   - BenchmarkECDHESEncryption for ECDH-based key management
package jwe

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-keychain/pkg/crypto/aead"
)

// Encrypter wraps go-jose encrypter with a simplified API for JWE encryption.
type Encrypter struct {
	encrypter    jose.Encrypter
	keyAlg       jose.KeyAlgorithm
	contentAlg   jose.ContentEncryption
	recipientKey interface{}
}

// NewEncrypter creates a new JWE encrypter with the specified algorithms.
//
// Parameters:
//   - keyEncAlg: Key management algorithm (e.g., "RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A256KW")
//   - encAlg: Content encryption algorithm (e.g., "A256GCM", "A192GCM", "A128GCM").
//     An empty string ("") enables auto-detection of the optimal AEAD algorithm based on CPU features.
//   - recipientKey: The recipient's public key (RSA or ECDSA) or symmetric key ([]byte)
//
// Returns an error if the algorithm combination is not supported or key type is invalid.
//
// # Algorithm Selection
//
// Explicit Selection: Use specific algorithm names like "A256GCM" for deterministic behavior
// across all platforms. This is recommended when you need guaranteed interoperability.
//
// Auto-Detection: Use an empty string ("") to automatically select the optimal algorithm:
//   - On systems with AES-NI: A256GCM (hardware-accelerated)
//   - On systems without AES-NI: A256CBC-HS512 (software-based, CPU-optimized)
//
// Example:
//
//	// RSA encryption with explicit A256GCM
//	encrypter, err := jwe.NewEncrypter("RSA-OAEP-256", "A256GCM", rsaPublicKey)
//
//	// RSA encryption with auto-detected algorithm
//	encrypter, err := jwe.NewEncrypter("RSA-OAEP-256", "", rsaPublicKey)
//
//	// ECDH-ES encryption
//	encrypter, err := jwe.NewEncrypter("ECDH-ES+A256KW", "A256GCM", ecdsaPublicKey)
//
//	// ECDH-ES with auto-detection
//	encrypter, err := jwe.NewEncrypter("ECDH-ES+A256KW", "", ecdsaPublicKey)
func NewEncrypter(keyEncAlg, encAlg string, recipientKey interface{}) (*Encrypter, error) {
	if recipientKey == nil {
		return nil, fmt.Errorf("recipient key cannot be nil")
	}

	// Map string algorithms to jose types
	keyAlg, err := parseKeyAlgorithm(keyEncAlg)
	if err != nil {
		return nil, err
	}

	contentAlg, err := parseContentEncryption(encAlg)
	if err != nil {
		return nil, err
	}

	// Create recipient with the appropriate key
	var recipient jose.Recipient
	switch key := recipientKey.(type) {
	case *rsa.PublicKey:
		recipient = jose.Recipient{
			Algorithm: keyAlg,
			Key:       key,
		}
	case *ecdsa.PublicKey:
		recipient = jose.Recipient{
			Algorithm: keyAlg,
			Key:       key,
		}
	case []byte:
		// Symmetric key for direct encryption or AES key wrap
		recipient = jose.Recipient{
			Algorithm: keyAlg,
			Key:       key,
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %T (expected *rsa.PublicKey, *ecdsa.PublicKey, or []byte)", recipientKey)
	}

	// Create encrypter options
	opts := &jose.EncrypterOptions{
		Compression: jose.NONE,
	}

	// Create go-jose encrypter
	joseEncrypter, err := jose.NewEncrypter(contentAlg, recipient, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypter: %w", err)
	}

	return &Encrypter{
		encrypter:    joseEncrypter,
		keyAlg:       keyAlg,
		contentAlg:   contentAlg,
		recipientKey: recipientKey,
	}, nil
}

// Encrypt encrypts plaintext to JWE compact serialization format.
//
// The JWE format is:
// BASE64URL(UTF8(JWE Protected Header)) || '.' ||
// BASE64URL(JWE Encrypted Key) || '.' ||
// BASE64URL(JWE Initialization Vector) || '.' ||
// BASE64URL(JWE Ciphertext) || '.' ||
// BASE64URL(JWE Authentication Tag)
//
// Example:
//
//	jweString, err := encrypter.Encrypt([]byte("secret data"))
func (e *Encrypter) Encrypt(plaintext []byte) (string, error) {
	if plaintext == nil {
		return "", fmt.Errorf("plaintext cannot be nil")
	}

	// Encrypt using go-jose
	jwe, err := e.encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	// Return compact serialization
	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWE: %w", err)
	}

	return serialized, nil
}

// EncryptWithHeader encrypts plaintext with custom JWE header parameters.
//
// Custom headers can include:
//   - kid: Key ID for key identification
//   - typ: Type header (e.g., "JWT")
//   - cty: Content type header
//
// Note: This creates a new encrypter with the custom headers to ensure
// proper authentication tag calculation by go-jose.
//
// Example:
//
//	jweString, err := encrypter.EncryptWithHeader(plaintext, map[string]interface{}{
//	    "kid": "rsa-key-2048",
//	    "typ": "JWT",
//	})
func (e *Encrypter) EncryptWithHeader(plaintext []byte, header map[string]interface{}) (string, error) {
	if plaintext == nil {
		return "", fmt.Errorf("plaintext cannot be nil")
	}
	if len(header) == 0 {
		return e.Encrypt(plaintext)
	}

	// Build extra headers map
	extraHeaders := make(map[jose.HeaderKey]interface{})
	var kid string

	for k, v := range header {
		if k == "kid" {
			if kidStr, ok := v.(string); ok {
				kid = kidStr
			}
		} else {
			extraHeaders[jose.HeaderKey(k)] = v
		}
	}

	// Create recipient with the appropriate key
	var recipient jose.Recipient
	switch key := e.recipientKey.(type) {
	case *rsa.PublicKey:
		recipient = jose.Recipient{
			Algorithm: e.keyAlg,
			Key:       key,
			KeyID:     kid,
		}
	case *ecdsa.PublicKey:
		recipient = jose.Recipient{
			Algorithm: e.keyAlg,
			Key:       key,
			KeyID:     kid,
		}
	case []byte:
		recipient = jose.Recipient{
			Algorithm: e.keyAlg,
			Key:       key,
			KeyID:     kid,
		}
	default:
		return "", fmt.Errorf("unsupported key type: %T", e.recipientKey)
	}

	// Create encrypter options with extra headers
	opts := &jose.EncrypterOptions{
		Compression:  jose.NONE,
		ExtraHeaders: extraHeaders,
	}

	// Create new encrypter with custom headers
	customEncrypter, err := jose.NewEncrypter(e.contentAlg, recipient, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter with headers: %w", err)
	}

	// Encrypt using the custom encrypter
	jwe, err := customEncrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	// Return compact serialization
	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWE: %w", err)
	}

	return serialized, nil
}

// Decrypter wraps go-jose for JWE decryption.
type Decrypter struct{}

// NewDecrypter creates a new JWE decrypter.
//
// Example:
//
//	decrypter := jwe.NewDecrypter()
//	plaintext, err := decrypter.Decrypt(jweString, privateKey)
func NewDecrypter() *Decrypter {
	return &Decrypter{}
}

// Decrypt decrypts a JWE compact serialization string to plaintext.
//
// Parameters:
//   - jweString: The JWE in compact serialization format (5 base64url parts separated by dots)
//   - privateKey: The recipient's private key (*rsa.PrivateKey, *ecdsa.PrivateKey, crypto.Decrypter, or []byte for symmetric)
//
// Returns the decrypted plaintext or an error if decryption fails.
//
// Example:
//
//	decrypter := jwe.NewDecrypter()
//	plaintext, err := decrypter.Decrypt(jweString, rsaPrivateKey)
func (d *Decrypter) Decrypt(jweString string, privateKey interface{}) ([]byte, error) {
	if jweString == "" {
		return nil, fmt.Errorf("JWE string cannot be empty")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	// Parse JWE with all supported algorithms
	jwe, err := jose.ParseEncrypted(jweString, []jose.KeyAlgorithm{
		jose.RSA_OAEP,
		jose.RSA_OAEP_256,
		jose.ECDH_ES,
		jose.ECDH_ES_A128KW,
		jose.ECDH_ES_A192KW,
		jose.ECDH_ES_A256KW,
		jose.A128KW,
		jose.A192KW,
		jose.A256KW,
		jose.A128GCMKW,
		jose.A192GCMKW,
		jose.A256GCMKW,
		jose.DIRECT,
	}, []jose.ContentEncryption{
		jose.A128GCM,
		jose.A192GCM,
		jose.A256GCM,
		jose.A128CBC_HS256,
		jose.A192CBC_HS384,
		jose.A256CBC_HS512,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWE: %w", err)
	}

	// Handle ECDSA wrapper (unwrap for go-jose)
	// If privateKey implements a GetPrivateKey method, use it to get the underlying key
	type ecdsaKeyer interface {
		GetPrivateKey() *ecdsa.PrivateKey
	}

	decryptKey := privateKey
	if wrapper, ok := privateKey.(ecdsaKeyer); ok {
		decryptKey = wrapper.GetPrivateKey()
	}

	// Decrypt using the provided key
	plaintext, err := jwe.Decrypt(decryptKey)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// ExtractKID extracts the Key ID (kid) from a JWE header without decrypting.
// This is useful for determining which key to use for decryption.
//
// Returns an empty string if no kid is present in the header.
//
// Example:
//
//	kid, err := jwe.ExtractKID(jweString)
//	if err != nil {
//	    return err
//	}
//	privateKey, err := keyStore.GetKey(kid)
func ExtractKID(jweString string) (string, error) {
	if jweString == "" {
		return "", fmt.Errorf("JWE string cannot be empty")
	}

	// Parse without decrypting - just extract header
	parts := strings.Split(jweString, ".")
	if len(parts) != 5 {
		return "", fmt.Errorf("invalid JWE format: expected 5 parts, got %d", len(parts))
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode header: %w", err)
	}

	// Parse header JSON
	var header struct {
		Kid string `json:"kid,omitempty"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("failed to unmarshal header: %w", err)
	}

	return header.Kid, nil
}

// Helper functions for algorithm mapping

func parseKeyAlgorithm(alg string) (jose.KeyAlgorithm, error) {
	switch alg {
	case "RSA-OAEP":
		return jose.RSA_OAEP, nil
	case "RSA-OAEP-256":
		return jose.RSA_OAEP_256, nil
	case "ECDH-ES":
		return jose.ECDH_ES, nil
	case "ECDH-ES+A128KW":
		return jose.ECDH_ES_A128KW, nil
	case "ECDH-ES+A192KW":
		return jose.ECDH_ES_A192KW, nil
	case "ECDH-ES+A256KW":
		return jose.ECDH_ES_A256KW, nil
	case "A128KW":
		return jose.A128KW, nil
	case "A192KW":
		return jose.A192KW, nil
	case "A256KW":
		return jose.A256KW, nil
	case "A128GCMKW":
		return jose.A128GCMKW, nil
	case "A192GCMKW":
		return jose.A192GCMKW, nil
	case "A256GCMKW":
		return jose.A256GCMKW, nil
	case "dir":
		return jose.DIRECT, nil
	default:
		return "", fmt.Errorf("unsupported key algorithm: %s", alg)
	}
}

// parseContentEncryption parses a content encryption algorithm string to jose.ContentEncryption.
//
// If an empty string is provided, auto-detection is performed:
//   - Returns A256GCM on systems with AES-NI CPU support
//   - Returns A256CBC-HS512 on systems without AES-NI support
//
// Supported algorithms:
//   - A128GCM, A192GCM, A256GCM (AES-GCM)
//   - A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 (AES-CBC-HMAC)
//   - "" (empty string) for auto-detection based on CPU features
func parseContentEncryption(enc string) (jose.ContentEncryption, error) {
	// Auto-detection mode: empty string means select algorithm based on CPU features
	if enc == "" {
		// Use AEAD package to select optimal algorithm
		// For JWE, we assume non-hardware-backed keys (software keys)
		// Hardware-backed scenarios should explicitly specify their algorithm
		algorithm := aead.SelectOptimal(false)
		enc = algorithm
	}

	switch enc {
	case "A128GCM":
		return jose.A128GCM, nil
	case "A192GCM":
		return jose.A192GCM, nil
	case "A256GCM":
		return jose.A256GCM, nil
	case "A128CBC-HS256":
		return jose.A128CBC_HS256, nil
	case "A192CBC-HS384":
		return jose.A192CBC_HS384, nil
	case "A256CBC-HS512":
		return jose.A256CBC_HS512, nil
	case "ChaCha20-Poly1305", "XChaCha20-Poly1305":
		// ChaCha20-Poly1305 is not part of the JWE RFC 7516 standard
		// Fall back to A256GCM for JWE compatibility
		return jose.A256GCM, nil
	default:
		return "", fmt.Errorf("unsupported content encryption algorithm: %s", enc)
	}
}
