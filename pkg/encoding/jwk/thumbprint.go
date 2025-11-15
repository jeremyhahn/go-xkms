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
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"sort"
)

// ThumbprintSHA256 computes the SHA-256 JWK thumbprint as defined in RFC 7638.
// This is the most commonly used thumbprint hash function.
//
// The thumbprint is computed from the required members of a JWK representing
// the key, in lexicographic order, with no whitespace or line breaks.
//
// For RSA keys: {"e":"...","kty":"RSA","n":"..."}
// For EC keys: {"crv":"...","kty":"EC","x":"...","y":"..."}
// For OKP keys: {"crv":"...","kty":"OKP","x":"..."}
// For oct keys: {"k":"...","kty":"oct"}
func ThumbprintSHA256(key crypto.PublicKey) (string, error) {
	return Thumbprint(key, crypto.SHA256)
}

// ThumbprintSHA1 computes the SHA-1 JWK thumbprint.
// SHA-1 is deprecated for most uses but may be required for legacy compatibility.
func ThumbprintSHA1(key crypto.PublicKey) (string, error) {
	return Thumbprint(key, crypto.SHA1)
}

// ThumbprintSHA512 computes the SHA-512 JWK thumbprint.
func ThumbprintSHA512(key crypto.PublicKey) (string, error) {
	return Thumbprint(key, crypto.SHA512)
}

// Thumbprint computes a JWK thumbprint using the specified hash function.
// The hash parameter should be one of crypto.SHA1, crypto.SHA256, or crypto.SHA512.
//
// The thumbprint is computed according to RFC 7638:
// 1. Construct a JSON object containing only the required members for the key type
// 2. Serialize with lexicographically sorted keys and no whitespace
// 3. Hash the UTF-8 representation
// 4. Base64url encode the hash
func Thumbprint(key crypto.PublicKey, hashFunc crypto.Hash) (string, error) {
	jwk, err := FromPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to convert key to JWK: %w", err)
	}

	return jwk.Thumbprint(hashFunc)
}

// Thumbprint computes the JWK thumbprint for this key using the specified hash function.
// This method can be called on both public and private keys.
func (jwk *JWK) Thumbprint(hashFunc crypto.Hash) (string, error) {
	// Get the required fields for thumbprint based on key type
	requiredFields, err := jwk.getRequiredThumbprintFields()
	if err != nil {
		return "", err
	}

	// Create JSON with lexicographically sorted keys (RFC 7638 requirement)
	jsonBytes, err := serializeForThumbprint(requiredFields)
	if err != nil {
		return "", fmt.Errorf("failed to serialize for thumbprint: %w", err)
	}

	// Hash the JSON
	var h hash.Hash
	switch hashFunc {
	case crypto.SHA1:
		h = sha1.New()
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return "", fmt.Errorf("unsupported hash function: %v", hashFunc)
	}

	h.Write(jsonBytes)
	hashBytes := h.Sum(nil)

	// Base64url encode (no padding)
	return base64.RawURLEncoding.EncodeToString(hashBytes), nil
}

// ThumbprintSHA256 is a convenience method that computes the SHA-256 thumbprint.
func (jwk *JWK) ThumbprintSHA256() (string, error) {
	return jwk.Thumbprint(crypto.SHA256)
}

// getRequiredThumbprintFields returns the required fields for computing a thumbprint
// according to RFC 7638 Section 3.2.
func (jwk *JWK) getRequiredThumbprintFields() (map[string]string, error) {
	fields := make(map[string]string)

	switch jwk.Kty {
	case string(KeyTypeRSA):
		// Required: e, kty, n
		if jwk.E == "" || jwk.N == "" {
			return nil, fmt.Errorf("RSA JWK missing required fields for thumbprint")
		}
		fields["e"] = jwk.E
		fields["kty"] = jwk.Kty
		fields["n"] = jwk.N

	case string(KeyTypeEC):
		// Required: crv, kty, x, y
		if jwk.Crv == "" || jwk.X == "" || jwk.Y == "" {
			return nil, fmt.Errorf("EC JWK missing required fields for thumbprint")
		}
		fields["crv"] = jwk.Crv
		fields["kty"] = jwk.Kty
		fields["x"] = jwk.X
		fields["y"] = jwk.Y

	case string(KeyTypeOKP):
		// Required: crv, kty, x
		if jwk.Crv == "" || jwk.X == "" {
			return nil, fmt.Errorf("OKP JWK missing required fields for thumbprint")
		}
		fields["crv"] = jwk.Crv
		fields["kty"] = jwk.Kty
		fields["x"] = jwk.X

	case string(KeyTypeOct):
		// Required: k, kty
		if jwk.K == "" {
			return nil, fmt.Errorf("symmetric JWK missing required fields for thumbprint")
		}
		fields["k"] = jwk.K
		fields["kty"] = jwk.Kty

	default:
		return nil, fmt.Errorf("unsupported key type for thumbprint: %s", jwk.Kty)
	}

	return fields, nil
}

// serializeForThumbprint creates the JSON representation required for thumbprint computation.
// Per RFC 7638, this must be:
// - Lexicographically sorted by key name
// - No whitespace or line breaks
// - UTF-8 encoded
func serializeForThumbprint(fields map[string]string) ([]byte, error) {
	// Sort keys lexicographically
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build JSON manually to ensure exact format (no whitespace)
	// We can't use json.Marshal with compact mode because we need exact control
	result := "{"
	for i, key := range keys {
		if i > 0 {
			result += ","
		}
		// Use json.Marshal for proper escaping of key and value
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		valueJSON, err := json.Marshal(fields[key])
		if err != nil {
			return nil, err
		}
		result += string(keyJSON) + ":" + string(valueJSON)
	}
	result += "}"

	return []byte(result), nil
}

// KeyAuthorization computes the key authorization string for ACME challenges.
// This combines a token with the JWK thumbprint as defined in RFC 8555.
//
// The key authorization is: token || '.' || base64url(SHA-256(JWK))
func KeyAuthorization(token string, key crypto.PublicKey) (string, error) {
	thumbprint, err := ThumbprintSHA256(key)
	if err != nil {
		return "", fmt.Errorf("failed to compute JWK thumbprint: %w", err)
	}
	return fmt.Sprintf("%s.%s", token, thumbprint), nil
}
