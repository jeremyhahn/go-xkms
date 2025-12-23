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

// Package validation provides centralized input validation for all go-keychain APIs.
// ALL public interfaces (REST, gRPC, QUIC, CLI, MCP) use the KeychainService which enforces
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

	// simpleKeyIDPattern for key IDs without backend prefix
	simpleKeyIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)
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
		return fmt.Errorf("key ID cannot be empty")
	}

	// Check for null bytes (can bypass some path checks)
	if strings.Contains(keyID, "\x00") {
		return fmt.Errorf("key ID contains null byte")
	}

	// Check length before other validations (prevent ReDoS)
	if len(keyID) > 255 {
		return fmt.Errorf("key ID too long (max 255 characters)")
	}

	// Check for absolute paths
	if filepath.IsAbs(keyID) {
		return fmt.Errorf("key ID cannot be an absolute path")
	}

	// Check for path traversal attempts
	cleaned := filepath.Clean(keyID)
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, string(filepath.Separator)+"..") {
		return fmt.Errorf("key ID contains path traversal attempt")
	}

	// Check for control characters
	for _, r := range keyID {
		if r < 32 || r == 127 {
			return fmt.Errorf("key ID contains control characters")
		}
	}

	// Only allow safe characters
	if !simpleKeyIDPattern.MatchString(keyID) {
		return fmt.Errorf("key ID contains invalid characters (allowed: a-z, A-Z, 0-9, -, _, .)")
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
		return fmt.Errorf("key ID cannot be empty")
	}

	// Check for null bytes
	if strings.Contains(keyID, "\x00") {
		return fmt.Errorf("key ID contains null byte")
	}

	// Check length
	if len(keyID) > 512 { // Maximum key ID length
		return fmt.Errorf("key ID too long (max 512 characters)")
	}

	// Check for control characters
	for _, r := range keyID {
		if r < 32 || r == 127 {
			return fmt.Errorf("key ID contains control characters")
		}
	}

	// Check for shorthand format (no colons = just keyname)
	if !strings.Contains(keyID, ":") {
		// Validate as a simple keyname
		return ValidateKeyID(keyID)
	}

	// Count colons to determine format
	colonCount := strings.Count(keyID, ":")
	if colonCount != 3 {
		return fmt.Errorf("key ID must have format 'backend:type:algo:keyname' (got %d colons, expected 3)", colonCount)
	}

	// Parse 4-part format: backend:type:algo:keyname
	parts := strings.Split(keyID, ":")
	backend := strings.TrimSpace(parts[0])
	keyType := strings.TrimSpace(parts[1])
	algo := strings.TrimSpace(parts[2])
	keyname := strings.TrimSpace(parts[3])

	// Keyname is required
	if keyname == "" {
		return fmt.Errorf("keyname cannot be empty")
	}

	// Validate non-empty components
	if backend != "" {
		if err := ValidateBackendName(backend); err != nil {
			return fmt.Errorf("invalid backend in key reference: %w", err)
		}
	}

	if keyType != "" {
		if !isValidKeyType(keyType) {
			return fmt.Errorf("invalid key type in key reference: %s", keyType)
		}
	}

	if algo != "" {
		if !isValidAlgorithm(algo) {
			return fmt.Errorf("invalid algorithm in key reference: %s", algo)
		}
	}

	// Validate keyname
	if err := ValidateKeyID(keyname); err != nil {
		return fmt.Errorf("invalid keyname in key reference: %w", err)
	}

	return nil
}

// isValidKeyType checks if the key type is valid.
func isValidKeyType(keyType string) bool {
	validTypes := []string{
		"attestation", "ca", "encryption", "endorsement",
		"hmac", "idevid", "secret",
		"signing", "storage", "tls", "tpm",
	}
	keyType = strings.ToLower(keyType)
	for _, valid := range validTypes {
		if keyType == valid {
			return true
		}
	}
	return false
}

// isValidAlgorithm checks if the algorithm is valid.
func isValidAlgorithm(algo string) bool {
	validAlgos := []string{
		// Asymmetric algorithms
		"rsa",
		"ecdsa-p256", "ecdsa-p-256", "p256", "p-256",
		"ecdsa-p384", "ecdsa-p-384", "p384", "p-384",
		"ecdsa-p521", "ecdsa-p-521", "p521", "p-521",
		"ed25519",
		// Symmetric algorithms
		"aes128-gcm", "aes128",
		"aes192-gcm", "aes192",
		"aes256-gcm", "aes256",
	}
	algo = strings.ToLower(algo)
	for _, valid := range validAlgos {
		if algo == valid {
			return true
		}
	}
	return false
}

// ValidateBackendName validates a backend name.
// Backend names must be simple lowercase identifiers.
func ValidateBackendName(backend string) error {
	if backend == "" {
		return fmt.Errorf("backend name cannot be empty")
	}

	// Check for null bytes
	if strings.Contains(backend, "\x00") {
		return fmt.Errorf("backend name contains null byte")
	}

	// Check length
	if len(backend) > 64 {
		return fmt.Errorf("backend name too long (max 64 characters)")
	}

	// Check for control characters
	for _, r := range backend {
		if r < 32 || r == 127 {
			return fmt.Errorf("backend name contains control characters")
		}
	}

	// Only allow lowercase alphanumeric and hyphens
	if !backendPattern.MatchString(backend) {
		return fmt.Errorf("backend name contains invalid characters (allowed: a-z, 0-9, -)")
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
