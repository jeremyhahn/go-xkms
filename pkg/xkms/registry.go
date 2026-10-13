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

// Package xkms provides backend discovery for XKMS key management implementations.
//
// This file implements a build-tag-aware backend registry that allows conditional
// compilation of different key storage backends. Backends register themselves via
// init() functions in their respective build-tagged files.
//
// The registry uses lock-free atomic operations for thread-safe access without
// mutex contention.
package xkms

import (
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// BackendType represents the type of key storage backend.
type BackendType string

// Backend type constants for all supported backends.
const (
	// BackendSoftware represents the pure software backend.
	// This is the default backend and is always available.
	BackendSoftware BackendType = "software"

	// BackendTPM2 represents the TPM 2.0 hardware backend.
	// Always compiled in.
	BackendTPM2 BackendType = "tpm2"

	// BackendPKCS11 represents external PKCS#11/HSM backend.
	// Requires build tag: pkcs11
	BackendPKCS11 BackendType = "pkcs11"

	// BackendPKCS8 represents the PKCS#8 file-based backend.
	// Always compiled in.
	BackendPKCS8 BackendType = "pkcs8"

	// BackendAWSKMS represents AWS Key Management Service backend.
	// Requires build tag: awskms
	BackendAWSKMS BackendType = "awskms"

	// BackendGCPKMS represents Google Cloud KMS backend.
	// Requires build tag: gcpkms
	BackendGCPKMS BackendType = "gcpkms"

	// BackendAzureKV represents Azure Key Vault backend.
	// Requires build tag: azurekv
	BackendAzureKV BackendType = "azurekv"

	// BackendVault represents HashiCorp Vault backend.
	// Requires build tag: vault
	BackendVault BackendType = "vault"

	// BackendQuantum represents post-quantum cryptography backend.
	// Requires build tag: quantum
	BackendQuantum BackendType = "quantum"

	// BackendFROST represents the FROST threshold signing backend.
	// Requires build tag: frost
	BackendFROST BackendType = "frost"

	// BackendSymmetric represents the symmetric encryption backend.
	// Always compiled in.
	BackendSymmetric BackendType = "symmetric"

	// BackendAVR represents an AVR device with a DICE-rooted identity,
	// reached over the arduino-generic wire protocol.
	// Always compiled in.
	BackendAVR BackendType = "avr"
)

// String returns the string representation of the backend type.
func (b BackendType) String() string {
	return string(b)
}

// IsValid returns true if the backend type is a recognized value.
func (b BackendType) IsValid() bool {
	return b.isBuiltin() || types.IsRegisteredBackendType(types.BackendType(b))
}

// isBuiltin reports whether b is one of the backend types go-xkms defines.
func (b BackendType) isBuiltin() bool {
	switch b {
	case BackendSoftware, BackendTPM2, BackendPKCS11, BackendPKCS8,
		BackendAWSKMS, BackendGCPKMS,
		BackendAzureKV, BackendVault, BackendQuantum, BackendFROST,
		BackendSymmetric, BackendAVR:
		return true
	default:
		return false
	}
}

// keyProviderTypes lists the BackendType values that are partial key providers
// (key generation + limited ops) rather than full-service backends.
var keyProviderTypes = map[BackendType]bool{
	BackendPKCS8:     true,
	BackendSymmetric: true,
	BackendQuantum:   true,
	BackendFROST:     true,
}

// IsKeyProviderType returns true if the backend type is a partial key provider.
func IsKeyProviderType(bt BackendType) bool {
	return keyProviderTypes[bt]
}

// backendRegistry holds the registered backends, copy-on-write behind an
// atomic pointer for lock-free access. A true value marks the backend
// available; the zero value is an empty registry.
var backendRegistry atomic.Pointer[map[BackendType]bool]

// RegisterBackend registers a backend as available. This function is called by
// init() functions in backend-specific files that are conditionally compiled
// based on build tags.
//
// This function is safe to call concurrently: it uses copy-on-write with a
// compare-and-swap, so no registration is lost.
func RegisterBackend(name BackendType) {
	storeCopyOnWrite(&backendRegistry, name, true)
}

// SupportedBackends returns a slice of all backends that were compiled into
// the binary. The returned slice is sorted alphabetically for consistent output.
func SupportedBackends() []BackendType {
	builtin := loadCopyOnWrite(&backendRegistry)
	external := types.RegisteredBackends()

	backends := make([]BackendType, 0, len(builtin)+len(external))
	for backend := range builtin {
		backends = append(backends, backend)
	}
	for backend := range external {
		backends = append(backends, BackendType(backend))
	}

	// Sort for consistent output
	sortBackends(backends)

	return backends
}

// IsBackendSupported returns true if the specified backend was compiled into
// the binary and is available for use.
func IsBackendSupported(name BackendType) bool {
	return loadCopyOnWrite(&backendRegistry)[name] ||
		types.IsRegisteredBackendType(types.BackendType(name))
}

// BackendCount returns the number of available backends.
func BackendCount() int {
	return len(loadCopyOnWrite(&backendRegistry)) + len(types.RegisteredBackends())
}

// BackendFactory creates a KeyProvider from configuration.
// Each backend registers a factory function that knows how to instantiate
// its KeyProvider from a generic configuration map.
type BackendFactory = types.BackendFactory

// backendFactories holds the factories of the backends compiled into
// go-xkms, copy-on-write behind an atomic pointer for lock-free access.
// Backends added by RegisterExternalBackend are not kept here: their single
// source of truth is the pkg/types registry, which publishes a name with its
// factory in one step and which the pkg/types validators must read.
var backendFactories atomic.Pointer[map[BackendType]BackendFactory]

// RegisterBackendFactory registers a factory function for creating a backend's
// KeyProvider. This is called alongside RegisterBackend in init() functions.
//
// The factory function receives a generic configuration map and returns a
// KeyProvider instance. Each backend defines its own expected configuration
// keys (e.g., "key_storage" for a pre-built storage.Backend -- see
// AutoConfig.Datastore).
func RegisterBackendFactory(name BackendType, factory BackendFactory) {
	storeCopyOnWrite(&backendFactories, name, factory)
}

// GetBackendFactory returns the factory function for the specified backend type.
// Returns the factory and true if found, or nil and false if no factory is
// registered for the given backend type.
func GetBackendFactory(name BackendType) (BackendFactory, bool) {
	if f, ok := types.RegisteredBackendFactory(types.BackendType(name)); ok {
		return f, true
	}
	f, ok := loadCopyOnWrite(&backendFactories)[name]
	return f, ok
}

// featureBuild names the Makefile toggle and build tag that compile a
// backend in.
type featureBuild struct {
	toggle string
	tag    string
}

// backendFeatures maps each backend that has a Makefile feature toggle to
// that toggle and its build tag.
var backendFeatures = map[BackendType]featureBuild{
	BackendTPM2:    {toggle: "WITH_TPM2", tag: "tpm2"},
	BackendPKCS11:  {toggle: "WITH_PKCS11", tag: "pkcs11"},
	BackendPKCS8:   {toggle: "WITH_PKCS8", tag: "pkcs8"},
	BackendAWSKMS:  {toggle: "WITH_AWS_KMS", tag: "awskms"},
	BackendGCPKMS:  {toggle: "WITH_GCP_KMS", tag: "gcpkms"},
	BackendAzureKV: {toggle: "WITH_AZURE_KV", tag: "azurekv"},
	BackendVault:   {toggle: "WITH_VAULT", tag: "vault"},
	BackendFROST:   {toggle: "WITH_FROST", tag: "frost"},
}

// RequireBackend returns the backend's registered factory, or a
// *FeatureNotCompiledError when the backend was not compiled into this
// binary. Callers that act on configuration naming a backend use it instead
// of GetBackendFactory so an absent feature fails closed rather than being
// skipped.
func RequireBackend(name BackendType) (BackendFactory, error) {
	factory, ok := GetBackendFactory(name)
	if !ok || !IsBackendSupported(name) {
		feature := backendFeatures[name]
		return nil, &FeatureNotCompiledError{
			Feature: string(name),
			Toggle:  feature.toggle,
			Tag:     feature.tag,
		}
	}
	return factory, nil
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

// loadCopyOnWrite returns the current snapshot of a copy-on-write registry
// map. The snapshot is never mutated; a nil map reads as empty.
func loadCopyOnWrite[V any](registry *atomic.Pointer[map[BackendType]V]) map[BackendType]V {
	if current := registry.Load(); current != nil {
		return *current
	}
	return nil
}

// storeCopyOnWrite sets name to value in a copy-on-write registry map,
// retrying when a concurrent writer swapped the map first.
func storeCopyOnWrite[V any](registry *atomic.Pointer[map[BackendType]V], name BackendType, value V) {
	for {
		current := registry.Load()
		updated := make(map[BackendType]V, 1)
		if current != nil {
			for k, v := range *current {
				updated[k] = v
			}
		}
		updated[name] = value
		if registry.CompareAndSwap(current, &updated) {
			return
		}
	}
}
