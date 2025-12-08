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

// ValidateKeyReference validates a key reference which may include backend prefix.
// Format: "backend:key-id" or "key-id"
func ValidateKeyReference(keyRef string) error {
	if keyRef == "" {
		return fmt.Errorf("key reference cannot be empty")
	}

	// Check for null bytes
	if strings.Contains(keyRef, "\x00") {
		return fmt.Errorf("key reference contains null byte")
	}

	// Check length
	if len(keyRef) > 320 { // 64 for backend + 1 for colon + 255 for keyID
		return fmt.Errorf("key reference too long (max 320 characters)")
	}

	// Check for control characters
	for _, r := range keyRef {
		if r < 32 || r == 127 {
			return fmt.Errorf("key reference contains control characters")
		}
	}

	// Parse and validate components
	parts := strings.SplitN(keyRef, ":", 2)
	if len(parts) == 2 {
		// Format: "backend:key-id"
		if err := ValidateBackendName(parts[0]); err != nil {
			return fmt.Errorf("invalid backend in key reference: %w", err)
		}
		if err := ValidateKeyID(parts[1]); err != nil {
			return fmt.Errorf("invalid key ID in key reference: %w", err)
		}
	} else {
		// Format: "key-id" only
		if err := ValidateKeyID(keyRef); err != nil {
			return err
		}
	}

	return nil
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
