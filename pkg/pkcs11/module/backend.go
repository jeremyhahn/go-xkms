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

// Package module provides backend discovery for PKCS#11 module implementations.
//
// This file implements a build-tag-aware backend registry that allows conditional
// compilation of different key storage backends. Backends register themselves via
// init() functions in their respective build-tagged files.
//
// The registry uses lock-free atomic operations for thread-safe access without
// mutex contention.
package module

import (
	"sync/atomic"
)

// BackendType represents the type of key storage backend.
type BackendType string

// Backend type constants for all supported backends.
const (
	// BackendSoftware represents the pure software PKCS#8 backend.
	// This is the default backend and is always available.
	BackendSoftware BackendType = "software"

	// BackendTPM2 represents the TPM 2.0 hardware backend.
	// Requires build tag: tpm2
	BackendTPM2 BackendType = "tpm2"

	// BackendPKCS11 represents external PKCS#11/HSM backend.
	// Requires build tag: pkcs11
	BackendPKCS11 BackendType = "pkcs11"

	// BackendQuantum represents post-quantum cryptography backend.
	// Requires build tag: quantum
	BackendQuantum BackendType = "quantum"

	// BackendAWSKMS represents AWS Key Management Service backend.
	// Requires build tag: awskms
	BackendAWSKMS BackendType = "awskms"

	// BackendGCPKMS represents Google Cloud KMS backend.
	// Requires build tag: gcpkms
	BackendGCPKMS BackendType = "gcpkms"

	// BackendAzureKV represents Azure Key Vault backend.
	// Requires build tag: azurekv
	BackendAzureKV BackendType = "azurekv"
)

// String returns the string representation of the backend type.
func (b BackendType) String() string {
	return string(b)
}

// IsValid returns true if the backend type is a recognized value.
func (b BackendType) IsValid() bool {
	switch b {
	case BackendSoftware, BackendTPM2, BackendPKCS11,
		BackendQuantum, BackendAWSKMS, BackendGCPKMS, BackendAzureKV:
		return true
	default:
		return false
	}
}

// backendRegistry holds the registered backends using atomic.Value for lock-free access.
// The stored value is a map[BackendType]bool where true indicates the backend is available.
var backendRegistry atomic.Value

func init() {
	// Initialize with empty map
	backendRegistry.Store(make(map[BackendType]bool))
}

// RegisterBackend registers a backend as available. This function is called by
// init() functions in backend-specific files that are conditionally compiled
// based on build tags.
//
// This function is safe to call concurrently from multiple init() functions.
// It uses copy-on-write semantics with atomic.Value for lock-free operation.
func RegisterBackend(name BackendType) {
	// Load current registry
	current := backendRegistry.Load().(map[BackendType]bool)

	// Create new map with the additional backend (copy-on-write)
	updated := make(map[BackendType]bool, len(current)+1)
	for k, v := range current {
		updated[k] = v
	}
	updated[name] = true

	// Store atomically. Since init() functions run sequentially in a
	// single goroutine per package, this is safe without CAS.
	backendRegistry.Store(updated)
}

// AvailableBackends returns a slice of all backends that were compiled into
// the binary. The returned slice is sorted alphabetically for consistent output.
func AvailableBackends() []BackendType {
	registry := backendRegistry.Load().(map[BackendType]bool)

	// Pre-allocate slice with exact capacity
	backends := make([]BackendType, 0, len(registry))
	for backend := range registry {
		backends = append(backends, backend)
	}

	// Sort for consistent output
	sortBackends(backends)

	return backends
}

// SupportedBackends is an alias for AvailableBackends for API consistency.
// Some callers may prefer the "supported" terminology.
func SupportedBackends() []BackendType {
	return AvailableBackends()
}

// IsBackendAvailable returns true if the specified backend was compiled into
// the binary and is available for use.
func IsBackendAvailable(name BackendType) bool {
	registry := backendRegistry.Load().(map[BackendType]bool)
	return registry[name]
}

// BackendCount returns the number of available backends.
func BackendCount() int {
	registry := backendRegistry.Load().(map[BackendType]bool)
	return len(registry)
}

// sortBackends sorts a slice of BackendType alphabetically using insertion sort.
// Insertion sort is efficient for small slices (< 20 elements) which is our case.
func sortBackends(backends []BackendType) {
	for i := 1; i < len(backends); i++ {
		key := backends[i]
		j := i - 1
		for j >= 0 && backends[j] > key {
			backends[j+1] = backends[j]
			j--
		}
		backends[j+1] = key
	}
}
