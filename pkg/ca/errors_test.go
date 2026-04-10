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

package ca

import (
	"errors"
	"fmt"
	"testing"
)

// =============================================================================
// Error Distinctness Tests
// =============================================================================

func TestErrors_AreDistinct(t *testing.T) {
	t.Parallel()

	// Collect all sentinel errors
	sentinelErrors := []error{
		// Initialization errors
		ErrNotInitialized,
		ErrAlreadyInitialized,

		// CSR errors
		ErrInvalidCSR,
		ErrCSRGenerationFailed,

		// Certificate errors
		ErrInvalidCertificate,
		ErrCertificateNotFound,
		ErrCertificateExpired,
		ErrCertificateNotYetValid,
		ErrCertificateAlreadyExists,

		// Signing errors
		ErrSigningFailed,
		ErrInvalidSignature,

		// Revocation errors
		ErrCertificateRevoked,
		ErrCRLNotFound,
		ErrCRLGenerationFailed,
		ErrAlreadyRevoked,

		// Chain errors
		ErrInvalidCertificateChain,
		ErrRootNotFound,
		ErrIntermediateNotFound,

		// Config errors
		ErrInvalidConfig,
		ErrInvalidKeyAlgorithm,
		ErrInvalidStoreType,
		ErrNoKeysConfigured,

		// Storage errors
		ErrKeyStoreRequired,
		ErrCertStoreRequired,
		ErrStorageError,

		// Serial number errors
		ErrSerialGenerationFailed,
		ErrSerialCollision,

		// Profile errors
		ErrProfileNotFound,
		ErrInvalidProfile,

		// TLS errors
		ErrTLSConfigFailed,
		ErrInvalidTLSOptions,
		ErrKeyNotFound,
		ErrKeyCertMismatch,
		ErrInvalidPEM,
		ErrPeerVerificationFailed,

		// Validation errors
		ErrSubjectCommonNameRequired,
		ErrInvalidValidityPeriod,
		ErrInvalidPathLength,
	}

	// Create a map to track seen error messages
	seen := make(map[string]error)

	for _, err := range sentinelErrors {
		msg := err.Error()
		if existing, found := seen[msg]; found {
			t.Errorf("Duplicate error message: %q (used by multiple errors including %v)", msg, existing)
		}
		seen[msg] = err
	}

	// Verify each error is distinct from all others
	for i, err1 := range sentinelErrors {
		for j, err2 := range sentinelErrors {
			if i != j {
				if errors.Is(err1, err2) {
					t.Errorf("errors.Is(%v, %v) = true, expected false", err1, err2)
				}
			}
		}
	}
}

// =============================================================================
// errors.Is() Tests
// =============================================================================

func TestErrors_WorkWithErrorsIs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		target error
	}{
		// Initialization errors
		{name: "ErrNotInitialized", err: ErrNotInitialized, target: ErrNotInitialized},
		{name: "ErrAlreadyInitialized", err: ErrAlreadyInitialized, target: ErrAlreadyInitialized},

		// CSR errors
		{name: "ErrInvalidCSR", err: ErrInvalidCSR, target: ErrInvalidCSR},
		{name: "ErrCSRGenerationFailed", err: ErrCSRGenerationFailed, target: ErrCSRGenerationFailed},

		// Certificate errors
		{name: "ErrInvalidCertificate", err: ErrInvalidCertificate, target: ErrInvalidCertificate},
		{name: "ErrCertificateNotFound", err: ErrCertificateNotFound, target: ErrCertificateNotFound},
		{name: "ErrCertificateExpired", err: ErrCertificateExpired, target: ErrCertificateExpired},
		{name: "ErrCertificateNotYetValid", err: ErrCertificateNotYetValid, target: ErrCertificateNotYetValid},
		{name: "ErrCertificateAlreadyExists", err: ErrCertificateAlreadyExists, target: ErrCertificateAlreadyExists},

		// Signing errors
		{name: "ErrSigningFailed", err: ErrSigningFailed, target: ErrSigningFailed},
		{name: "ErrInvalidSignature", err: ErrInvalidSignature, target: ErrInvalidSignature},

		// Revocation errors
		{name: "ErrCertificateRevoked", err: ErrCertificateRevoked, target: ErrCertificateRevoked},
		{name: "ErrCRLNotFound", err: ErrCRLNotFound, target: ErrCRLNotFound},
		{name: "ErrCRLGenerationFailed", err: ErrCRLGenerationFailed, target: ErrCRLGenerationFailed},
		{name: "ErrAlreadyRevoked", err: ErrAlreadyRevoked, target: ErrAlreadyRevoked},

		// Chain errors
		{name: "ErrInvalidCertificateChain", err: ErrInvalidCertificateChain, target: ErrInvalidCertificateChain},
		{name: "ErrRootNotFound", err: ErrRootNotFound, target: ErrRootNotFound},
		{name: "ErrIntermediateNotFound", err: ErrIntermediateNotFound, target: ErrIntermediateNotFound},

		// Config errors
		{name: "ErrInvalidConfig", err: ErrInvalidConfig, target: ErrInvalidConfig},
		{name: "ErrInvalidKeyAlgorithm", err: ErrInvalidKeyAlgorithm, target: ErrInvalidKeyAlgorithm},
		{name: "ErrInvalidStoreType", err: ErrInvalidStoreType, target: ErrInvalidStoreType},
		{name: "ErrNoKeysConfigured", err: ErrNoKeysConfigured, target: ErrNoKeysConfigured},

		// Storage errors
		{name: "ErrKeyStoreRequired", err: ErrKeyStoreRequired, target: ErrKeyStoreRequired},
		{name: "ErrCertStoreRequired", err: ErrCertStoreRequired, target: ErrCertStoreRequired},
		{name: "ErrStorageError", err: ErrStorageError, target: ErrStorageError},

		// Serial number errors
		{name: "ErrSerialGenerationFailed", err: ErrSerialGenerationFailed, target: ErrSerialGenerationFailed},
		{name: "ErrSerialCollision", err: ErrSerialCollision, target: ErrSerialCollision},

		// Profile errors
		{name: "ErrProfileNotFound", err: ErrProfileNotFound, target: ErrProfileNotFound},
		{name: "ErrInvalidProfile", err: ErrInvalidProfile, target: ErrInvalidProfile},

		// TLS errors
		{name: "ErrTLSConfigFailed", err: ErrTLSConfigFailed, target: ErrTLSConfigFailed},
		{name: "ErrInvalidTLSOptions", err: ErrInvalidTLSOptions, target: ErrInvalidTLSOptions},
		{name: "ErrKeyNotFound", err: ErrKeyNotFound, target: ErrKeyNotFound},
		{name: "ErrKeyCertMismatch", err: ErrKeyCertMismatch, target: ErrKeyCertMismatch},
		{name: "ErrInvalidPEM", err: ErrInvalidPEM, target: ErrInvalidPEM},
		{name: "ErrPeerVerificationFailed", err: ErrPeerVerificationFailed, target: ErrPeerVerificationFailed},

		// Validation errors
		{name: "ErrSubjectCommonNameRequired", err: ErrSubjectCommonNameRequired, target: ErrSubjectCommonNameRequired},
		{name: "ErrInvalidValidityPeriod", err: ErrInvalidValidityPeriod, target: ErrInvalidValidityPeriod},
		{name: "ErrInvalidPathLength", err: ErrInvalidPathLength, target: ErrInvalidPathLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !errors.Is(tt.err, tt.target) {
				t.Errorf("errors.Is(%v, %v) = false, expected true", tt.err, tt.target)
			}
		})
	}
}

func TestErrors_WorkWithWrappedErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		target error
	}{
		{
			name:   "wrapped ErrNotInitialized",
			err:    fmt.Errorf("operation failed: %w", ErrNotInitialized),
			target: ErrNotInitialized,
		},
		{
			name:   "wrapped ErrCertificateNotFound",
			err:    fmt.Errorf("could not retrieve certificate: %w", ErrCertificateNotFound),
			target: ErrCertificateNotFound,
		},
		{
			name:   "wrapped ErrInvalidCSR",
			err:    fmt.Errorf("CSR validation failed: %w", ErrInvalidCSR),
			target: ErrInvalidCSR,
		},
		{
			name:   "double wrapped ErrSerialCollision",
			err:    fmt.Errorf("generation failed: %w", fmt.Errorf("serial issue: %w", ErrSerialCollision)),
			target: ErrSerialCollision,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !errors.Is(tt.err, tt.target) {
				t.Errorf("errors.Is(%v, %v) = false, expected true for wrapped error", tt.err, tt.target)
			}
		})
	}
}

// =============================================================================
// Error Messages Tests
// =============================================================================

func TestErrors_HaveProperFormat(t *testing.T) {
	t.Parallel()

	// All sentinel errors should start with "ca:"
	sentinelErrors := []error{
		ErrNotInitialized,
		ErrAlreadyInitialized,
		ErrInvalidCSR,
		ErrCSRGenerationFailed,
		ErrInvalidCertificate,
		ErrCertificateNotFound,
		ErrCertificateExpired,
		ErrCertificateNotYetValid,
		ErrCertificateAlreadyExists,
		ErrSigningFailed,
		ErrInvalidSignature,
		ErrCertificateRevoked,
		ErrCRLNotFound,
		ErrCRLGenerationFailed,
		ErrAlreadyRevoked,
		ErrInvalidCertificateChain,
		ErrRootNotFound,
		ErrIntermediateNotFound,
		ErrInvalidConfig,
		ErrInvalidKeyAlgorithm,
		ErrInvalidStoreType,
		ErrNoKeysConfigured,
		ErrKeyStoreRequired,
		ErrCertStoreRequired,
		ErrStorageError,
		ErrSerialGenerationFailed,
		ErrSerialCollision,
		ErrProfileNotFound,
		ErrInvalidProfile,
		ErrTLSConfigFailed,
		ErrInvalidTLSOptions,
		ErrKeyNotFound,
		ErrKeyCertMismatch,
		ErrInvalidPEM,
		ErrPeerVerificationFailed,
		ErrSubjectCommonNameRequired,
		ErrInvalidValidityPeriod,
		ErrInvalidPathLength,
	}

	for _, err := range sentinelErrors {
		msg := err.Error()
		if len(msg) < 4 || msg[:3] != "ca:" {
			t.Errorf("Error message %q does not start with 'ca:'", msg)
		}
		// Messages should be lowercase after "ca: " prefix (Go convention)
		// Note: Some may start with uppercase for proper nouns like "CSR" or "CRL"
		if len(msg) > 4 && msg[4] >= 'A' && msg[4] <= 'Z' {
			// Allow uppercase for known abbreviations
			allowedPrefixes := []string{
				"ca: CSR",
				"ca: CRL",
				"ca: TLS",
			}
			allowed := false
			for _, prefix := range allowedPrefixes {
				if len(msg) >= len(prefix) && msg[:len(prefix)] == prefix {
					allowed = true
					break
				}
			}
			if !allowed {
				t.Logf("Note: Error message %q starts with uppercase letter (may be intentional)", msg)
			}
		}
	}
}

func TestErrors_Messages_NotEmpty(t *testing.T) {
	t.Parallel()

	sentinelErrors := []error{
		ErrNotInitialized,
		ErrAlreadyInitialized,
		ErrInvalidCSR,
		ErrCSRGenerationFailed,
		ErrInvalidCertificate,
		ErrCertificateNotFound,
		ErrCertificateExpired,
		ErrCertificateNotYetValid,
		ErrCertificateAlreadyExists,
		ErrSigningFailed,
		ErrInvalidSignature,
		ErrCertificateRevoked,
		ErrCRLNotFound,
		ErrCRLGenerationFailed,
		ErrAlreadyRevoked,
		ErrInvalidCertificateChain,
		ErrRootNotFound,
		ErrIntermediateNotFound,
		ErrInvalidConfig,
		ErrInvalidKeyAlgorithm,
		ErrInvalidStoreType,
		ErrNoKeysConfigured,
		ErrKeyStoreRequired,
		ErrCertStoreRequired,
		ErrStorageError,
		ErrSerialGenerationFailed,
		ErrSerialCollision,
		ErrProfileNotFound,
		ErrInvalidProfile,
		ErrTLSConfigFailed,
		ErrInvalidTLSOptions,
		ErrKeyNotFound,
		ErrKeyCertMismatch,
		ErrInvalidPEM,
		ErrPeerVerificationFailed,
		ErrSubjectCommonNameRequired,
		ErrInvalidValidityPeriod,
		ErrInvalidPathLength,
	}

	for _, err := range sentinelErrors {
		if err.Error() == "" {
			t.Errorf("Error %v has empty message", err)
		}
	}
}

// =============================================================================
// Error Category Tests
// =============================================================================

func TestErrors_InitializationCategory(t *testing.T) {
	t.Parallel()

	initErrors := []error{
		ErrNotInitialized,
		ErrAlreadyInitialized,
	}

	for _, err := range initErrors {
		msg := err.Error()
		if !containsAny(msg, []string{"initialized", "initialization"}) {
			t.Errorf("Initialization error %q doesn't contain 'initialized' or 'initialization'", msg)
		}
	}
}

func TestErrors_CertificateCategory(t *testing.T) {
	t.Parallel()

	certErrors := []error{
		ErrInvalidCertificate,
		ErrCertificateNotFound,
		ErrCertificateExpired,
		ErrCertificateNotYetValid,
		ErrCertificateAlreadyExists,
		ErrCertificateRevoked,
	}

	for _, err := range certErrors {
		msg := err.Error()
		if !containsAny(msg, []string{"certificate"}) {
			t.Errorf("Certificate error %q doesn't contain 'certificate'", msg)
		}
	}
}

func TestErrors_SerialCategory(t *testing.T) {
	t.Parallel()

	serialErrors := []error{
		ErrSerialGenerationFailed,
		ErrSerialCollision,
	}

	for _, err := range serialErrors {
		msg := err.Error()
		if !containsAny(msg, []string{"serial"}) {
			t.Errorf("Serial error %q doesn't contain 'serial'", msg)
		}
	}
}

// =============================================================================
// Error Non-Nil Tests
// =============================================================================

func TestErrors_AreNotNil(t *testing.T) {
	t.Parallel()

	sentinelErrors := []struct {
		name string
		err  error
	}{
		{"ErrNotInitialized", ErrNotInitialized},
		{"ErrAlreadyInitialized", ErrAlreadyInitialized},
		{"ErrInvalidCSR", ErrInvalidCSR},
		{"ErrCSRGenerationFailed", ErrCSRGenerationFailed},
		{"ErrInvalidCertificate", ErrInvalidCertificate},
		{"ErrCertificateNotFound", ErrCertificateNotFound},
		{"ErrCertificateExpired", ErrCertificateExpired},
		{"ErrCertificateNotYetValid", ErrCertificateNotYetValid},
		{"ErrCertificateAlreadyExists", ErrCertificateAlreadyExists},
		{"ErrSigningFailed", ErrSigningFailed},
		{"ErrInvalidSignature", ErrInvalidSignature},
		{"ErrCertificateRevoked", ErrCertificateRevoked},
		{"ErrCRLNotFound", ErrCRLNotFound},
		{"ErrCRLGenerationFailed", ErrCRLGenerationFailed},
		{"ErrAlreadyRevoked", ErrAlreadyRevoked},
		{"ErrInvalidCertificateChain", ErrInvalidCertificateChain},
		{"ErrRootNotFound", ErrRootNotFound},
		{"ErrIntermediateNotFound", ErrIntermediateNotFound},
		{"ErrInvalidConfig", ErrInvalidConfig},
		{"ErrInvalidKeyAlgorithm", ErrInvalidKeyAlgorithm},
		{"ErrInvalidStoreType", ErrInvalidStoreType},
		{"ErrNoKeysConfigured", ErrNoKeysConfigured},
		{"ErrKeyStoreRequired", ErrKeyStoreRequired},
		{"ErrCertStoreRequired", ErrCertStoreRequired},
		{"ErrStorageError", ErrStorageError},
		{"ErrSerialGenerationFailed", ErrSerialGenerationFailed},
		{"ErrSerialCollision", ErrSerialCollision},
		{"ErrProfileNotFound", ErrProfileNotFound},
		{"ErrInvalidProfile", ErrInvalidProfile},
		{"ErrTLSConfigFailed", ErrTLSConfigFailed},
		{"ErrInvalidTLSOptions", ErrInvalidTLSOptions},
		{"ErrKeyNotFound", ErrKeyNotFound},
		{"ErrKeyCertMismatch", ErrKeyCertMismatch},
		{"ErrInvalidPEM", ErrInvalidPEM},
		{"ErrPeerVerificationFailed", ErrPeerVerificationFailed},
		{"ErrSubjectCommonNameRequired", ErrSubjectCommonNameRequired},
		{"ErrInvalidValidityPeriod", ErrInvalidValidityPeriod},
		{"ErrInvalidPathLength", ErrInvalidPathLength},
	}

	for _, tt := range sentinelErrors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.err == nil {
				t.Errorf("%s is nil", tt.name)
			}
		})
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if containsIgnoreCase(s, substr) {
			return true
		}
	}
	return false
}

func containsIgnoreCase(s, substr string) bool {
	sLower := toLower(s)
	substrLower := toLower(substr)
	return containsSubstring(sLower, substrLower)
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

func containsSubstring(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
