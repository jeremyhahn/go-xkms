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

package jwk

import (
	"crypto"
	"fmt"
	"strings"
)

// KeychainKeyGetter is a function type that retrieves a key from the keychain by ID.
// This is used for dependency injection to avoid circular imports with the keychain package.
type KeychainKeyGetter func(keyID string) (crypto.PrivateKey, error)

// KeychainSignerGetter is a function type that retrieves a signer from the keychain by ID.
// This is used for dependency injection to avoid circular imports with the keychain package.
type KeychainSignerGetter func(keyID string) (crypto.Signer, error)

// FromKeychain creates a JWK from a keychain key using the unified Key ID.
// The JWK will contain:
//   - kid: The unified Key ID (e.g., "pkcs11:signing-key")
//   - Public key material (n, e for RSA; x, y for EC)
//   - Appropriate algorithm (alg) and use (use) fields
//   - NO private key material (for security)
//
// The getKey function should be provided by the caller to retrieve the key from their keychain.
// This design avoids circular import dependencies between jwk and keychain packages.
//
// Example:
//
//	jwk, err := jwk.FromKeychain("pkcs11:my-key", func(keyID string) (crypto.PrivateKey, error) {
//	    return keystore.GetKeyByID(keyID)
//	})
func FromKeychain(keyID string, getKey KeychainKeyGetter) (*JWK, error) {
	if keyID == "" {
		return nil, fmt.Errorf("key ID cannot be empty")
	}

	// Retrieve the key using the provided function
	key, err := getKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Extract public key
	var pubKey crypto.PublicKey
	if pk, ok := key.(interface{ Public() crypto.PublicKey }); ok {
		pubKey = pk.Public()
	} else {
		return nil, fmt.Errorf("key does not expose public key")
	}

	// Create JWK from public key (not private!)
	jwk, err := FromPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from public key: %w", err)
	}

	// Set kid to the Key ID
	jwk.Kid = keyID

	// Set use field to signing by default
	// This could be enhanced to detect key usage from key attributes
	jwk.Use = "sig"

	return jwk, nil
}

// LoadKeyFromKeychain loads the private key from the keychain using
// the JWK's kid field as the Key ID.
//
// The getKey function should be provided by the caller to retrieve the key from their keychain.
//
// Example:
//
//	jwk := &JWK{Kid: "pkcs11:my-key"}
//	key, err := jwk.LoadKeyFromKeychain(func(keyID string) (crypto.PrivateKey, error) {
//	    return keystore.GetKeyByID(keyID)
//	})
func (jwk *JWK) LoadKeyFromKeychain(getKey KeychainKeyGetter) (crypto.PrivateKey, error) {
	if jwk.Kid == "" {
		return nil, fmt.Errorf("JWK has no kid field")
	}

	if !jwk.IsKeychainBacked() {
		return nil, fmt.Errorf("JWK kid is not a valid keychain Key ID")
	}

	return getKey(jwk.Kid)
}

// IsKeychainBacked returns true if the JWK references a keychain key.
// A JWK is considered keychain-backed if its kid field matches the
// unified Key ID format: "backend:keyname"
//
// Example:
//
//	jwk := &JWK{Kid: "pkcs11:signing-key"}
//	jwk.IsKeychainBacked() // true
//
//	jwk := &JWK{Kid: "random-key-id"}
//	jwk.IsKeychainBacked() // false
func (jwk *JWK) IsKeychainBacked() bool {
	if jwk.Kid == "" {
		return false
	}

	// Check if kid matches "backend:keyname" format
	parts := strings.Split(jwk.Kid, ":")
	if len(parts) != 2 {
		return false
	}

	backend := strings.ToLower(parts[0])

	// Check if backend is one of the valid keychain backends
	validBackends := map[string]bool{
		"pkcs8":    true,
		"aes":      true,
		"software": true,
		"pkcs11":   true,
		"tpm2":     true,
		"awskms":   true,
		"gcpkms":   true,
		"azurekv":  true,
		"vault":    true,
	}

	return validBackends[backend]
}

// ToKeychainSigner returns a crypto.Signer backed by the keychain.
// The JWK must have a kid field in the unified Key ID format.
//
// The getSigner function should be provided by the caller to retrieve the signer from their keychain.
//
// Example:
//
//	jwk := &JWK{Kid: "pkcs11:signing-key"}
//	signer, err := jwk.ToKeychainSigner(func(keyID string) (crypto.Signer, error) {
//	    return keystore.GetSignerByID(keyID)
//	})
func (jwk *JWK) ToKeychainSigner(getSigner KeychainSignerGetter) (crypto.Signer, error) {
	if !jwk.IsKeychainBacked() {
		return nil, fmt.Errorf("JWK is not keychain-backed")
	}

	return getSigner(jwk.Kid)
}
