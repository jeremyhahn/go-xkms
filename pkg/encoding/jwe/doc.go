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

// Package jwe implements JSON Web Encryption (JWE) as defined in RFC 7516,
// providing a simplified API for encrypting and decrypting data with
// automatic or explicit algorithm selection.
//
// This package wraps the production-tested go-jose library, offering a
// simplified interface with additional features like auto-detection of
// optimal AEAD algorithms based on CPU capabilities.
//
// # Supported Algorithms
//
// Key Management Algorithms:
//   - RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384, RSA-OAEP-512
//   - ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static)
//   - ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
//   - A128KW, A192KW, A256KW (AES Key Wrap)
//   - A128GCMKW, A192GCMKW, A256GCMKW (AES-GCM Key Wrap)
//   - dir (Direct Key Agreement)
//
// Content Encryption Algorithms:
//   - A128GCM, A192GCM, A256GCM (AES-GCM)
//   - A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 (AES-CBC-HMAC)
//   - "" (empty string) for auto-detection based on CPU features
//
// # Auto-Detection Feature
//
// The package supports automatic selection of the optimal AEAD algorithm
// based on CPU capabilities. This eliminates the need to choose algorithms
// explicitly while ensuring optimal performance across diverse hardware.
//
// When you provide an empty string ("") as the content encryption algorithm,
// the package automatically selects:
//   - A256GCM on systems with AES-NI support (2-3x faster)
//   - A256CBC-HS512 on systems without AES-NI (secure fallback)
//
// # Basic Usage
//
// Explicit Algorithm Selection:
//
//	encrypter, err := jwe.NewEncrypter("RSA-OAEP-256", "A256GCM", publicKey)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	jweString, err := encrypter.Encrypt(plaintext)
//
// Auto-Detection:
//
//	encrypter, err := jwe.NewEncrypter("RSA-OAEP-256", "", publicKey)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	jweString, err := encrypter.Encrypt(plaintext)  // Uses A256GCM or A256CBC-HS512
//
// Decryption (works with any supported algorithm):
//
//	decrypter := jwe.NewDecrypter()
//	plaintext, err := decrypter.Decrypt(jweString, privateKey)
//
// # Algorithm Selection Guide
//
// Use auto-detection ("") when:
//   - You want optimal performance across heterogeneous hardware
//   - You're deploying to environments with unknown CPU capabilities
//   - You need the best security/performance balance automatically
//   - You're building cloud-native or containerized applications
//
// Use explicit selection when:
//   - You need guaranteed cross-platform interoperability
//   - You must comply with specific algorithm requirements
//   - You're working with legacy systems with limited algorithm support
//   - You want predictable behavior across different hardware
//
// # Key Management
//
// The package supports both asymmetric and symmetric key management:
//
// RSA encryption:
//
//	publicKey, _ := rsa.GenerateKey(rand.Reader, 2048)
//	encrypter, _ := jwe.NewEncrypter("RSA-OAEP-256", "A256GCM", &publicKey.PublicKey)
//
// ECDH key agreement:
//
//	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//	encrypter, _ := jwe.NewEncrypter("ECDH-ES+A256KW", "", &privateKey.PublicKey)
//
// Symmetric encryption (direct key agreement):
//
//	symmetricKey := make([]byte, 32)  // 256-bit key
//	rand.Read(symmetricKey)
//	encrypter, _ := jwe.NewEncrypter("dir", "A256GCM", symmetricKey)
//
// # Custom Headers
//
// Add custom headers including Key ID (kid) for key identification:
//
//	header := map[string]interface{}{
//	    "kid": "prod-key-2024",
//	    "typ": "JWT",
//	}
//	jweString, err := encrypter.EncryptWithHeader(plaintext, header)
//
// Extract Key ID without decrypting:
//
//	kid, err := jwe.ExtractKID(jweString)
//
// # Performance Characteristics
//
// Auto-Detection Performance:
//
//   - x86_64 with AES-NI: ~2-3x faster than software AES
//   - ARM64 with AES instructions: ~1.5-2x faster
//   - Systems without hardware AES: Uses optimized software implementation
//
// Encryption Overhead:
//   - A256GCM: ~50-100µs per operation (with AES-NI)
//   - A256CBC-HS512: ~150-300µs per operation
//   - RSA-OAEP key wrapping: ~5-20ms per operation
//   - ECDH key agreement: ~10-30ms per operation
//
// # CPU Feature Detection
//
// The package automatically detects:
//   - x86_64 AES-NI instruction set
//   - ARM64 AES instructions
//   - Other hardware acceleration capabilities
//
// Detection is performed once and cached for optimal performance.
//
// # Thread Safety
//
// All types in this package are safe for concurrent use.
// Encrypter and Decrypter instances can be safely shared between goroutines.
//
// # Format
//
// JWE uses the compact serialization format (RFC 7516):
//
//	BASE64URL(Header) || '.' ||
//	BASE64URL(EncryptedKey) || '.' ||
//	BASE64URL(IV) || '.' ||
//	BASE64URL(Ciphertext) || '.' ||
//	BASE64URL(AuthTag)
//
// # Security Considerations
//
//   - Always use at least 2048-bit RSA keys
//   - Prefer ECDH with P-256 or P-384 curves over RSA
//   - Auto-detection uses secure algorithms (A256* variants)
//   - Never use weak symmetric keys (less than 128 bits)
//   - Validate all ciphertexts with authentication tags
//
// # Examples
//
// See the test file for comprehensive examples of:
//   - Auto-detection with different key algorithms
//   - Symmetric and asymmetric encryption
//   - Custom headers and Key ID extraction
//   - Performance comparisons between algorithms
package jwe
