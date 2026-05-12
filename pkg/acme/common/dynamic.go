// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package common

import (
	"fmt"
	"regexp"
	"strconv"
)

const (
	DefaultHTTPPort   = "80"
	DefaultHTTPSPort  = "443"
	DefaultEnrollPort = "8443"
)

// DynamicChallengePatterns maps base challenge types to their standard forms
var DynamicChallengePatterns = map[string]string{
	"http":    "http-01",
	"dns":     "dns-01",
	"enroll":  "enroll-01",
	"endorse": "endorse-01",
}

var (
	// dynamicChallengeRegex matches challenges like "http-8080" or "enroll-8443"
	// Format: {name}-{port} where port is 1-5 digits
	dynamicChallengeRegex = regexp.MustCompile(`^([a-z]+)-(\d{1,5})$`)

	// standardChallengeRegex matches standard ACME challenges like "http-01"
	// Format: {name}-{sequence} where sequence is exactly 2 digits
	standardChallengeRegex = regexp.MustCompile(`^([a-z]+)-(\d{2})$`)
)

// ParseDynamicChallenge parses dynamic port assignment from challenge type.
//
// For dynamic challenges (e.g., "http-8080"):
//   - Returns the base name ("http"), port ("8080"), and nil error
//
// For standard challenges (e.g., "http-01"):
//   - Returns the full challenge type ("http-01"), empty port (""), and nil error
//
// Returns an error if the format is invalid.
//
// Examples:
//
//	ParseDynamicChallenge("http-8080")  -> ("http", "8080", nil)
//	ParseDynamicChallenge("enroll-8443") -> ("enroll", "8443", nil)
//	ParseDynamicChallenge("http-01")     -> ("http-01", "", nil)
//	ParseDynamicChallenge("dns-01")      -> ("dns-01", "", nil)
//	ParseDynamicChallenge("invalid")     -> ("", "", ErrInvalidChallengeFormat)
func ParseDynamicChallenge(challengeType string) (name, port string, err error) {
	if challengeType == "" {
		return "", "", ErrInvalidChallengeFormat
	}

	// Check for standard challenge format first (e.g., "http-01")
	if matches := standardChallengeRegex.FindStringSubmatch(challengeType); matches != nil {
		// Standard challenge - return full type with no port
		return challengeType, "", nil
	}

	// Check for dynamic challenge format (e.g., "http-8080")
	if matches := dynamicChallengeRegex.FindStringSubmatch(challengeType); matches != nil {
		name := matches[1]
		port := matches[2]

		// Validate port number is in valid range
		portNum, err := strconv.Atoi(port)
		if err != nil {
			return "", "", ErrInvalidChallengeFormat
		}
		if portNum < 1 || portNum > 65535 {
			return "", "", ErrInvalidChallengeFormat
		}

		// Validate that the base name is a known challenge type
		if _, exists := DynamicChallengePatterns[name]; !exists {
			return "", "", ErrUnsupportedChallenge
		}

		return name, port, nil
	}

	// No match - invalid format
	return "", "", ErrInvalidChallengeFormat
}

// IsDynamicChallenge checks if a challenge uses dynamic port assignment.
//
// Returns true for dynamic challenges (e.g., "http-8080", "enroll-8443").
// Returns false for standard challenges (e.g., "http-01", "dns-01").
//
// Examples:
//
//	IsDynamicChallenge("http-8080")  -> true
//	IsDynamicChallenge("enroll-8443") -> true
//	IsDynamicChallenge("http-01")     -> false
//	IsDynamicChallenge("dns-01")      -> false
//	IsDynamicChallenge("invalid")     -> false
func IsDynamicChallenge(challengeType string) bool {
	_, port, err := ParseDynamicChallenge(challengeType)
	return err == nil && port != ""
}

// GetChallengePort returns the port for a challenge type.
//
// For dynamic challenges (e.g., "http-8080"), returns the specified port ("8080").
// For standard challenges, returns the default port for that challenge type:
//   - "http-01"   -> "80"
//   - "https-01"  -> "443"
//   - "enroll-01" -> "8443"
//   - "endorse-01" -> "8443"
//   - "dns-01"    -> "" (DNS doesn't use ports)
//
// Returns empty string if the challenge type is invalid or has no default port.
//
// Examples:
//
//	GetChallengePort("http-8080")  -> "8080"
//	GetChallengePort("http-01")    -> "80"
//	GetChallengePort("enroll-8443") -> "8443"
//	GetChallengePort("dns-01")     -> ""
func GetChallengePort(challengeType string) string {
	name, port, err := ParseDynamicChallenge(challengeType)
	if err != nil {
		return ""
	}

	// If dynamic challenge, return the specified port
	if port != "" {
		return port
	}

	// For standard challenges, return default port based on type
	switch name {
	case "http-01":
		return DefaultHTTPPort
	case "https-01":
		return DefaultHTTPSPort
	case "enroll-01", "endorse-01":
		return DefaultEnrollPort
	case "dns-01":
		// DNS challenges don't use ports
		return ""
	default:
		return ""
	}
}

// NormalizeChallengeType converts a dynamic challenge to its base standard type.
//
// For dynamic challenges (e.g., "http-8080"), returns the standard form ("http-01").
// For standard challenges (e.g., "http-01"), returns the input unchanged.
//
// This is useful for validating challenge types against supported standards
// while still allowing dynamic port assignment.
//
// Examples:
//
//	NormalizeChallengeType("http-8080")  -> "http-01"
//	NormalizeChallengeType("enroll-8443") -> "enroll-01"
//	NormalizeChallengeType("http-01")    -> "http-01"
//	NormalizeChallengeType("dns-01")     -> "dns-01"
//	NormalizeChallengeType("invalid")    -> ""
func NormalizeChallengeType(challengeType string) string {
	name, port, err := ParseDynamicChallenge(challengeType)
	if err != nil {
		return ""
	}

	// If it's already a standard challenge, return as-is
	if port == "" {
		return name
	}

	// Convert dynamic challenge to standard form
	if standard, exists := DynamicChallengePatterns[name]; exists {
		return standard
	}

	return ""
}

// FormatDynamicChallenge creates a dynamic challenge type from a base type and port.
//
// Examples:
//
//	FormatDynamicChallenge("http", "8080")  -> "http-8080"
//	FormatDynamicChallenge("enroll", "8443") -> "enroll-8443"
func FormatDynamicChallenge(baseType, port string) string {
	if baseType == "" || port == "" {
		return ""
	}
	return fmt.Sprintf("%s-%s", baseType, port)
}
