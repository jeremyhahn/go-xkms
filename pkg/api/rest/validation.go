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

package rest

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

var (
	// keyIDPattern matches safe key identifiers (alphanumeric, dash, underscore, dot, colon)
	// This prevents path traversal and other injection attacks while supporting extended key ID format
	keyIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-\.:]+$`)
)

// ValidateKeyID checks if a key ID is safe to use.
// Prevents path traversal, injection, and other attacks by:
// - Rejecting empty strings
// - Rejecting null bytes
// - Rejecting absolute paths
// - Rejecting parent directory references (..)
// - Allowing only safe characters (alphanumeric, dash, underscore, dot)
func ValidateKeyID(keyID string) error {
	if keyID == "" {
		return &errs.Message{Msg: "key ID cannot be empty"}
	}

	// Check for null bytes
	if strings.Contains(keyID, "\x00") {
		return &errs.Message{Msg: "key ID contains invalid characters"}
	}

	// Check for absolute paths
	if filepath.IsAbs(keyID) {
		return &errs.Message{Msg: "key ID cannot be an absolute path"}
	}

	// Check for path traversal attempts
	cleaned := filepath.Clean(keyID)
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, string(filepath.Separator)+"..") {
		return &errs.Message{Msg: "key ID contains invalid path components"}
	}

	// Only allow safe characters (alphanumeric, dash, underscore, dot, colon for extended format)
	if !keyIDPattern.MatchString(keyID) {
		return &errs.Message{Msg: "key ID contains invalid characters (allowed: a-z, A-Z, 0-9, -, _, ., :)"}
	}

	// Additional length check (prevent DoS via extremely long names)
	if len(keyID) > 255 {
		return &errs.Message{Msg: "key ID too long (max 255 characters)"}
	}

	return nil
}

// ValidateBackendName checks if a backend name is valid.
// Backend names should be simple identifiers without special characters.
func ValidateBackendName(backend string) error {
	if backend == "" {
		return &errs.Message{Msg: "backend name cannot be empty"}
	}

	// Backend names should only contain alphanumeric and hyphens
	if !regexp.MustCompile(`^[a-z0-9\-]+$`).MatchString(backend) {
		return &errs.Message{Msg: "backend name contains invalid characters (allowed: a-z, 0-9, -)"}
	}

	if len(backend) > 64 {
		return &errs.Message{Msg: "backend name too long (max 64 characters)"}
	}

	return nil
}

// SanitizeString removes potentially dangerous characters from a string.
// Used for log messages and error outputs to prevent log injection.
func SanitizeString(s string) string {
	// Remove control characters and null bytes
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)

	// Limit length
	if len(s) > 1000 {
		s = s[:1000] + "..."
	}

	return s
}

// ValidateAndGetBackend validates backend name and retrieves it.
// This is a helper to combine validation with backend lookup.
func ValidateAndGetBackend(backendName string) (interface{}, error) {
	if backendName == "" {
		return nil, &errs.Message{Msg: "backend name cannot be empty"}
	}

	if err := ValidateBackendName(backendName); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid backend", Err: err}
	}

	// Note: This returns interface{} to avoid import cycle
	// Callers should type assert to xkms.Backend
	return nil, &errs.Message{Msg: "use xkms.KeyProvider() directly after validation"}
}

// ValidateURLParam validates a URL parameter (like keyID from path).
// More strict than ValidateKeyID since URL params have additional constraints.
func ValidateURLParam(param string, paramName string) error {
	if param == "" {
		return &errs.Message{Msg: fmt.Sprintf("%s cannot be empty", paramName)}
	}

	// Check for null bytes and control characters
	for _, r := range param {
		if r < 32 || r == 127 {
			return &errs.Message{Msg: fmt.Sprintf("%s contains invalid characters", paramName)}
		}
	}

	// Check for URL encoding attacks
	if strings.Contains(param, "%") {
		return &errs.Message{Msg: fmt.Sprintf("%s contains percent encoding", paramName)}
	}

	// Additional validation based on parameter type
	switch paramName {
	case "id", "keyID":
		return ValidateKeyID(param)
	case "backend", "backendID":
		return ValidateBackendName(param)
	}

	// Generic validation for other params
	if len(param) > 255 {
		return &errs.Message{Msg: fmt.Sprintf("%s too long (max 255 characters)", paramName)}
	}

	return nil
}
