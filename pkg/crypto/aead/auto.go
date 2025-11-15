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

// Package aead provides automatic AEAD algorithm selection based on hardware capabilities.
//
// This package implements intelligent AEAD cipher selection that optimizes performance
// by detecting CPU capabilities and choosing the best algorithm:
//
//   - AES-256-GCM: Used when hardware AES-NI instructions are available or when
//     using hardware-backed keys (HSM, TPM, cloud KMS). Provides excellent
//     performance on modern CPUs with AES acceleration.
//
//   - ChaCha20-Poly1305: Used on CPUs without AES-NI or for software-only encryption.
//     Provides better performance than AES-GCM on platforms without hardware
//     acceleration and is resistant to timing attacks.
//
// The selection logic ensures optimal performance across different architectures
// (amd64, arm64, etc.) and deployment scenarios (hardware-backed vs software keys).
//
// Example usage:
//
//	// Auto-select based on CPU and key type
//	algorithm := aead.SelectOptimal(false) // Software key
//	// Returns "ChaCha20-Poly1305" on CPUs without AES-NI
//	// Returns "AES-256-GCM" on CPUs with AES-NI
//
//	algorithm := aead.SelectOptimal(true) // Hardware-backed key
//	// Always returns "AES-256-GCM" for HSM/TPM/KMS keys
//
//	// Check if CPU has AES-NI
//	if aead.HasAESNI() {
//	    fmt.Println("CPU supports hardware AES acceleration")
//	}
package aead

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

// Algorithm names for AEAD ciphers
const (
	// AES256GCM is AES-256 in Galois/Counter Mode
	// Best performance on CPUs with AES-NI or when using hardware-backed keys
	AES256GCM = "A256GCM"

	// AES192GCM is AES-192 in Galois/Counter Mode
	AES192GCM = "A192GCM"

	// AES128GCM is AES-128 in Galois/Counter Mode
	AES128GCM = "A128GCM"

	// ChaCha20Poly1305 is ChaCha20-Poly1305 AEAD
	// Best performance on CPUs without AES-NI
	ChaCha20Poly1305 = "ChaCha20-Poly1305"

	// XChaCha20Poly1305 is XChaCha20-Poly1305 AEAD with extended nonce
	XChaCha20Poly1305 = "XChaCha20-Poly1305"
)

// Backend algorithm names (lowercase with hyphens)
const (
	// BackendAES256GCM is the backend algorithm name for AES-256-GCM
	BackendAES256GCM = "aes256-gcm"

	// BackendAES192GCM is the backend algorithm name for AES-192-GCM
	BackendAES192GCM = "aes192-gcm"

	// BackendAES128GCM is the backend algorithm name for AES-128-GCM
	BackendAES128GCM = "aes128-gcm"

	// BackendChaCha20Poly1305 is the backend algorithm name for ChaCha20-Poly1305
	BackendChaCha20Poly1305 = "chacha20-poly1305"

	// BackendXChaCha20Poly1305 is the backend algorithm name for XChaCha20-Poly1305
	BackendXChaCha20Poly1305 = "xchacha20-poly1305"
)

// HasAESNI returns true if the CPU has AES-NI (AES New Instructions) support.
// AES-NI provides hardware acceleration for AES encryption/decryption operations.
//
// Supported architectures:
//   - amd64: Checks X86.HasAES
//   - arm64: Checks ARM64.HasAES
//   - Other architectures return false
//
// Example:
//
//	if aead.HasAESNI() {
//	    fmt.Println("Using hardware-accelerated AES")
//	}
func HasAESNI() bool {
	switch runtime.GOARCH {
	case "amd64":
		return cpu.X86.HasAES
	case "arm64":
		return cpu.ARM64.HasAES
	default:
		return false
	}
}

// SelectOptimal selects the optimal AEAD algorithm based on hardware capabilities.
//
// Selection logic:
//  1. If isHardwareBacked is true (HSM, TPM, KMS), always use AES-256-GCM
//     Hardware security modules are optimized for AES operations
//  2. If CPU has AES-NI, use AES-256-GCM for best performance
//  3. Otherwise, use ChaCha20-Poly1305 for better software-only performance
//
// Parameters:
//   - isHardwareBacked: True if the key is stored in hardware (HSM, TPM, cloud KMS)
//
// Returns:
//   - JWE-compatible algorithm name (e.g., "A256GCM", "ChaCha20-Poly1305")
//
// Example:
//
//	// For a software key
//	algo := aead.SelectOptimal(false)
//
//	// For a TPM/HSM key
//	algo := aead.SelectOptimal(true)
func SelectOptimal(isHardwareBacked bool) string {
	// Hardware-backed keys (HSM, TPM, cloud KMS) - always use AES-256-GCM
	// These systems are optimized for AES operations
	if isHardwareBacked {
		return AES256GCM
	}

	// Software keys - check CPU capabilities
	if HasAESNI() {
		// CPU has hardware AES acceleration - use AES-256-GCM
		return AES256GCM
	}

	// No hardware acceleration - use ChaCha20-Poly1305
	// ChaCha20 performs better than AES without hardware support
	// and provides constant-time operations
	return ChaCha20Poly1305
}

// SelectOptimalBackend selects the optimal AEAD algorithm for backend use.
// Returns backend-compatible algorithm names (lowercase with hyphens).
//
// This is identical to SelectOptimal but returns backend.KeyAlgorithm compatible
// strings instead of JWE algorithm names.
//
// Parameters:
//   - isHardwareBacked: True if the key is stored in hardware (HSM, TPM, cloud KMS)
//
// Returns:
//   - Backend-compatible algorithm name (e.g., "aes256-gcm", "chacha20-poly1305")
//
// Example:
//
//	attrs := &types.KeyAttributes{
//	    KeyAlgorithm: backend.KeyAlgorithm(aead.SelectOptimalBackend(false)),
//	}
func SelectOptimalBackend(isHardwareBacked bool) string {
	// Hardware-backed keys - always use AES-256-GCM
	if isHardwareBacked {
		return BackendAES256GCM
	}

	// Software keys - check CPU capabilities
	if HasAESNI() {
		return BackendAES256GCM
	}

	// No hardware acceleration - use ChaCha20-Poly1305
	return BackendChaCha20Poly1305
}

// IsAESGCM returns true if the algorithm is an AES-GCM variant.
func IsAESGCM(algorithm string) bool {
	switch algorithm {
	case AES128GCM, AES192GCM, AES256GCM:
		return true
	case BackendAES128GCM, BackendAES192GCM, BackendAES256GCM:
		return true
	default:
		return false
	}
}

// IsChaCha returns true if the algorithm is a ChaCha variant.
func IsChaCha(algorithm string) bool {
	switch algorithm {
	case ChaCha20Poly1305, XChaCha20Poly1305:
		return true
	case BackendChaCha20Poly1305, BackendXChaCha20Poly1305:
		return true
	default:
		return false
	}
}

// ToJWE converts a backend algorithm name to a JWE algorithm name.
// Returns the input unchanged if it's already a JWE algorithm or unknown.
//
// Example:
//
//	jweAlg := aead.ToJWE("aes256-gcm") // Returns "A256GCM"
func ToJWE(backendAlgorithm string) string {
	switch backendAlgorithm {
	case BackendAES128GCM:
		return AES128GCM
	case BackendAES192GCM:
		return AES192GCM
	case BackendAES256GCM:
		return AES256GCM
	case BackendChaCha20Poly1305:
		return ChaCha20Poly1305
	case BackendXChaCha20Poly1305:
		return XChaCha20Poly1305
	default:
		// Already JWE format or unknown - return as-is
		return backendAlgorithm
	}
}

// ToBackend converts a JWE algorithm name to a backend algorithm name.
// Returns the input unchanged if it's already a backend algorithm or unknown.
//
// Example:
//
//	backendAlg := aead.ToBackend("A256GCM") // Returns "aes256-gcm"
func ToBackend(jweAlgorithm string) string {
	switch jweAlgorithm {
	case AES128GCM:
		return BackendAES128GCM
	case AES192GCM:
		return BackendAES192GCM
	case AES256GCM:
		return BackendAES256GCM
	case ChaCha20Poly1305:
		return BackendChaCha20Poly1305
	case XChaCha20Poly1305:
		return BackendXChaCha20Poly1305
	default:
		// Already backend format or unknown - return as-is
		return jweAlgorithm
	}
}
