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

package jwk

import (
	"crypto"
	"fmt"
	"strings"
)

// XKMSKeyGetter is a function type that retrieves a key from the xkms by ID.
// This is used for dependency injection to avoid circular imports with the xkms package.
type XKMSKeyGetter func(keyID string) (crypto.PrivateKey, error)

// XKMSSignerGetter is a function type that retrieves a signer from the xkms by ID.
// This is used for dependency injection to avoid circular imports with the xkms package.
type XKMSSignerGetter func(keyID string) (crypto.Signer, error)

// FromXKMS creates a JWK from a xkmsctl key using the unified Key ID.
// The JWK will contain:
//   - kid: The unified Key ID (e.g., "pkcs11:signing-key")
//   - Public key material (n, e for RSA; x, y for EC)
//   - Appropriate algorithm (alg) and use (use) fields
//   - NO private key material (for security)
//
// The getKey function should be provided by the caller to retrieve the key from their xkms.
// This design avoids circular import dependencies between jwk and xkms packages.
//
// Example:
//
//	jwk, err := jwk.FromXKMS("pkcs11:my-key", func(keyID string) (crypto.PrivateKey, error) {
//	    return keystore.GetKeyByID(keyID)
//	})
func FromXKMS(keyID string, getKey XKMSKeyGetter) (*JWK, error) {
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

// LoadKeyFromXKMS loads the private key from the xkms using
// the JWK's kid field as the Key ID.
//
// The getKey function should be provided by the caller to retrieve the key from their xkms.
//
// Example:
//
//	jwk := &JWK{Kid: "pkcs11:my-key"}
//	key, err := jwk.LoadKeyFromXKMS(func(keyID string) (crypto.PrivateKey, error) {
//	    return keystore.GetKeyByID(keyID)
//	})
func (jwk *JWK) LoadKeyFromXKMS(getKey XKMSKeyGetter) (crypto.PrivateKey, error) {
	if jwk.Kid == "" {
		return nil, fmt.Errorf("JWK has no kid field")
	}

	if !jwk.IsXKMSBacked() {
		return nil, fmt.Errorf("JWK kid is not a valid xkms Key ID")
	}

	return getKey(jwk.Kid)
}

// IsXKMSBacked returns true if the JWK references a xkms key.
// A JWK is considered xkms-backed if its kid field matches the
// unified Key ID format: "backend:keyname"
//
// Example:
//
//	jwk := &JWK{Kid: "pkcs11:signing-key"}
//	jwk.IsXKMSBacked() // true
//
//	jwk := &JWK{Kid: "random-key-id"}
//	jwk.IsXKMSBacked() // false
func (jwk *JWK) IsXKMSBacked() bool {
	if jwk.Kid == "" {
		return false
	}

	// Check if kid matches "backend:keyname" format
	parts := strings.Split(jwk.Kid, ":")
	if len(parts) != 2 {
		return false
	}

	backend := strings.ToLower(parts[0])

	// Check if backend is one of the valid xkms backends
	validBackends := map[string]bool{
		"pkcs8":     true,
		"symmetric": true,
		"software":  true,
		"pkcs11":    true,
		"tpm2":      true,
		"awskms":    true,
		"gcpkms":    true,
		"azurekv":   true,
		"vault":     true,
	}

	return validBackends[backend]
}

// ToXKMSSigner returns a crypto.Signer backed by the xkms.
// The JWK must have a kid field in the unified Key ID format.
//
// The getSigner function should be provided by the caller to retrieve the signer from their xkms.
//
// Example:
//
//	jwk := &JWK{Kid: "pkcs11:signing-key"}
//	signer, err := jwk.ToXKMSSigner(func(keyID string) (crypto.Signer, error) {
//	    return keystore.GetSignerByID(keyID)
//	})
func (jwk *JWK) ToXKMSSigner(getSigner XKMSSignerGetter) (crypto.Signer, error) {
	if !jwk.IsXKMSBacked() {
		return nil, fmt.Errorf("JWK is not xkms-backed")
	}

	return getSigner(jwk.Kid)
}
