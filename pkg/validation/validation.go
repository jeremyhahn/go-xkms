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

// Package validation provides centralized input validation for all go-xkms APIs.
// ALL public interfaces (REST, gRPC, QUIC, CLI, MCP) use the XKMSService which enforces
// these validations, preventing injection attacks across all entry points.
package validation

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// backendPattern matches safe backend names (lowercase alphanumeric + hyphens)
	backendPattern = regexp.MustCompile(`^[a-z0-9\-]+$`)

	// simpleKeyIDPattern for key IDs - supports both simple names and extended format (backend:type:algo:keyname)
	simpleKeyIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-\.:]+$`)

	// validKeyTypes provides O(1) lookup for valid key types.
	validKeyTypes = map[string]struct{}{
		"attestation": {},
		"ca":          {},
		"encryption":  {},
		"endorsement": {},
		"hmac":        {},
		"idevid":      {},
		"secret":      {},
		"signing":     {},
		"storage":     {},
		"tls":         {},
		"tpm":         {},
	}

	// validAlgorithms provides O(1) lookup for valid algorithm names.
	// This list must stay in sync with the authoritative algorithm list
	// in pkg/xkms/keyid.go validateAlgorithm.
	validAlgorithms = map[string]struct{}{
		// Asymmetric algorithms
		"rsa":        {},
		"ecdsa-p256": {}, "ecdsa-p-256": {}, "p256": {}, "p-256": {},
		"ecdsa-p384": {}, "ecdsa-p-384": {}, "p384": {}, "p-384": {},
		"ecdsa-p521": {}, "ecdsa-p-521": {}, "p521": {}, "p-521": {},
		"ed25519": {},
		"ed448":   {},
		// Key exchange algorithms
		"x25519": {}, "x448": {},
		// Symmetric algorithms
		"aes128-gcm": {}, "aes128": {},
		"aes192-gcm": {}, "aes192": {},
		"aes256-gcm": {}, "aes256": {},
		"chacha20-poly1305": {}, "chacha20": {},
		"xchacha20-poly1305": {}, "xchacha20": {},
		// Post-quantum signature algorithms (ML-DSA / Dilithium)
		"ml-dsa-44": {}, "mldsa44": {},
		"ml-dsa-65": {}, "mldsa65": {},
		"ml-dsa-87": {}, "mldsa87": {},
		// Post-quantum key encapsulation algorithms (ML-KEM / Kyber)
		"ml-kem-512": {}, "mlkem512": {},
		"ml-kem-768": {}, "mlkem768": {},
		"ml-kem-1024": {}, "mlkem1024": {},
		// HMAC algorithms
		"hmac-sha256": {}, "hmac-sha384": {}, "hmac-sha512": {},
		// FROST threshold signature algorithms (RFC 9591)
		"frost-ed25519": {}, "frost-ed25519-sha512": {},
		"frost-ristretto255": {}, "frost-ristretto255-sha512": {},
		"frost-ed448": {}, "frost-ed448-shake256": {},
		"frost-p256": {}, "frost-p256-sha256": {},
		"frost-secp256k1": {}, "frost-secp256k1-sha256": {},
	}
)

// ValidateKeyID validates a key identifier.
// Prevents path traversal, injection, and other attacks by:
// - Rejecting empty strings
// - Rejecting null bytes
// - Rejecting absolute paths
// - Rejecting parent directory references (..)
// - Allowing only safe characters
// - Enforcing length limits
func ValidateKeyID(keyID string) error {
	if keyID == "" {
		return newErrKeyID(ConstraintEmpty, "")
	}

	if strings.Contains(keyID, "\x00") {
		return newErrKeyID(ConstraintNullByte, "")
	}

	// Check length before other validations (prevent ReDoS)
	if len(keyID) > 255 {
		return newErrKeyID(ConstraintTooLong, "max 255 characters")
	}

	if filepath.IsAbs(keyID) {
		return newErrKeyID(ConstraintAbsolutePath, "")
	}

	// Check for path traversal attempts
	cleaned := filepath.Clean(keyID)
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, string(filepath.Separator)+"..") {
		return newErrKeyID(ConstraintPathTraversal, "")
	}

	// Check for control characters
	for _, r := range keyID {
		if r < 32 || r == 127 {
			return newErrKeyID(ConstraintControlChars, "")
		}
	}

	// Only allow safe characters (supports extended key ID format with colons)
	if !simpleKeyIDPattern.MatchString(keyID) {
		return newErrKeyID(ConstraintInvalidChars, "allowed: a-z, A-Z, 0-9, -, _, ., :")
	}

	return nil
}

// ValidateKeyReference validates a key reference using the 4-part Key ID format.
//
// Format: "backend:type:algo:keyname" with optional segments
// - All segments except keyname are optional (can be empty)
// - Shorthand: "keyname" (no colons) uses defaults
// - Examples:
//   - "my-key" - shorthand for just keyname
//   - ":::my-key" - explicit form of above
//   - "pkcs11:::my-key" - specify backend only
//   - "pkcs11:signing:ecdsa-p256:my-key" - full specification
func ValidateKeyReference(keyID string) error {
	if keyID == "" {
		return newErrKeyReference(ConstraintEmpty, "")
	}

	if strings.Contains(keyID, "\x00") {
		return newErrKeyReference(ConstraintNullByte, "")
	}

	if len(keyID) > 512 {
		return newErrKeyReference(ConstraintTooLong, "max 512 characters")
	}

	// Check for control characters
	for _, r := range keyID {
		if r < 32 || r == 127 {
			return newErrKeyReference(ConstraintControlChars, "")
		}
	}

	// Check for shorthand format (no colons = just keyname)
	if !strings.Contains(keyID, ":") {
		return ValidateKeyID(keyID)
	}

	// Count colons to determine format
	colonCount := strings.Count(keyID, ":")
	if colonCount != 3 {
		return newErrKeyReference(
			ConstraintInvalidFormat,
			fmt.Sprintf("must have format 'backend:type:algo:keyname' (got %d colons, expected 3)", colonCount),
		)
	}

	// Parse 4-part format: backend:type:algo:keyname
	parts := strings.Split(keyID, ":")
	backend := strings.TrimSpace(parts[0])
	keyType := strings.TrimSpace(parts[1])
	algo := strings.TrimSpace(parts[2])
	keyname := strings.TrimSpace(parts[3])

	// Keyname is required
	if keyname == "" {
		return newErrKeyReferenceComponentDetail("keyname", ConstraintEmpty, "")
	}

	// Validate non-empty components
	if backend != "" {
		if err := ValidateBackendName(backend); err != nil {
			return newErrKeyReferenceComponent("backend", err)
		}
	}

	if keyType != "" {
		if !isValidKeyType(keyType) {
			return newErrKeyReferenceComponentDetail("key type", ConstraintInvalidKeyType, keyType)
		}
	}

	if algo != "" {
		if !isValidAlgorithm(algo) {
			return newErrKeyReferenceComponentDetail("algorithm", ConstraintInvalidAlgorithm, algo)
		}
	}

	// Validate keyname
	if err := ValidateKeyID(keyname); err != nil {
		return newErrKeyReferenceComponent("keyname", err)
	}

	return nil
}

// isValidKeyType checks if the key type is valid using O(1) map lookup.
func isValidKeyType(keyType string) bool {
	_, ok := validKeyTypes[strings.ToLower(keyType)]
	return ok
}

// isValidAlgorithm checks if the algorithm is valid using O(1) map lookup.
func isValidAlgorithm(algo string) bool {
	_, ok := validAlgorithms[strings.ToLower(algo)]
	return ok
}

// ValidateBackendName validates a backend name.
// Backend names must be simple lowercase identifiers.
func ValidateBackendName(backend string) error {
	if backend == "" {
		return newErrBackendName(ConstraintEmpty, "")
	}

	if strings.Contains(backend, "\x00") {
		return newErrBackendName(ConstraintNullByte, "")
	}

	if len(backend) > 64 {
		return newErrBackendName(ConstraintTooLong, "max 64 characters")
	}

	// Check for control characters
	for _, r := range backend {
		if r < 32 || r == 127 {
			return newErrBackendName(ConstraintControlChars, "")
		}
	}

	// Only allow lowercase alphanumeric and hyphens
	if !backendPattern.MatchString(backend) {
		return newErrBackendName(ConstraintInvalidChars, "allowed: a-z, 0-9, -")
	}

	return nil
}

// SanitizeForLog sanitizes a string for safe logging (prevents log injection).
func SanitizeForLog(s string) string {
	// Remove control characters and null bytes
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)

	// Limit length to prevent log flooding
	if len(s) > 1000 {
		s = s[:1000] + "...[truncated]"
	}

	return s
}
