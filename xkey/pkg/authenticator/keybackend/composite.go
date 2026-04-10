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

package keybackend

import (
	"errors"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// BackendTypeComposite identifies the composite key backend type.
const BackendTypeComposite types.BackendType = "composite"

// CompositeBackend aggregates multiple FIDO2KeyBackend implementations and
// routes operations to the correct backend based on KeyHandle.BackendID().
// It is used by the GUI service layer to present a unified view across
// software, TPM2, PKCS#11, and other backends.
type CompositeBackend struct {
	mu             sync.RWMutex
	backends       map[types.BackendType]FIDO2KeyBackend
	defaultBackend types.BackendType
}

// NewCompositeBackend creates a CompositeBackend with the given default backend type.
// The default backend is used for GenerateCredentialKey and ImportPrivateKey when
// no backend-specific routing information is available.
func NewCompositeBackend(defaultBackend types.BackendType) *CompositeBackend {
	return &CompositeBackend{
		backends:       make(map[types.BackendType]FIDO2KeyBackend),
		defaultBackend: defaultBackend,
	}
}

// Register adds a backend to the composite under the given type.
func (c *CompositeBackend) Register(bt types.BackendType, backend FIDO2KeyBackend) {
	c.mu.Lock()
	c.backends[bt] = backend
	c.mu.Unlock()
}

// Unregister removes a backend from the composite.
func (c *CompositeBackend) Unregister(bt types.BackendType) {
	c.mu.Lock()
	delete(c.backends, bt)
	c.mu.Unlock()
}

// SetDefault changes the default backend for new key generation and import.
func (c *CompositeBackend) SetDefault(bt types.BackendType) {
	c.mu.Lock()
	c.defaultBackend = bt
	c.mu.Unlock()
}

// DefaultID returns the current default backend type.
func (c *CompositeBackend) DefaultID() types.BackendType {
	c.mu.RLock()
	bt := c.defaultBackend
	c.mu.RUnlock()
	return bt
}

// Type returns BackendTypeComposite.
func (c *CompositeBackend) Type() types.BackendType {
	return BackendTypeComposite
}

// Capabilities returns the merged capabilities of all registered backends.
// SupportedAlgorithms is the deduplicated union of all backends' algorithms.
// HardwareBacked is true if any backend is hardware-backed.
// SupportsExport is true if any backend supports export.
// SupportsImport is true if any backend supports import.
// SupportsAttestation is true if any backend supports attestation.
func (c *CompositeBackend) Capabilities() FIDO2KeyCapabilities {
	c.mu.RLock()
	defer c.mu.RUnlock()

	seen := make(map[int]struct{})
	var merged FIDO2KeyCapabilities

	for _, b := range c.backends {
		caps := b.Capabilities()
		for _, alg := range caps.SupportedAlgorithms {
			if _, exists := seen[alg]; !exists {
				seen[alg] = struct{}{}
				merged.SupportedAlgorithms = append(merged.SupportedAlgorithms, alg)
			}
		}
		if caps.HardwareBacked {
			merged.HardwareBacked = true
		}
		if caps.SupportsExport {
			merged.SupportsExport = true
		}
		if caps.SupportsImport {
			merged.SupportsImport = true
		}
		if caps.SupportsAttestation {
			merged.SupportsAttestation = true
		}
		if caps.HandlesUserPresence {
			merged.HandlesUserPresence = true
		}
		if caps.HandlesUserVerification {
			merged.HandlesUserVerification = true
		}
	}

	return merged
}

// GenerateCredentialKey routes to the default backend.
func (c *CompositeBackend) GenerateCredentialKey(algorithm int, credentialID []byte) (KeyHandle, []byte, error) {
	b, err := c.resolveDefault()
	if err != nil {
		return nil, nil, err
	}
	return b.GenerateCredentialKey(algorithm, credentialID)
}

// Sign routes to the backend identified by handle.BackendID().
// If BackendID is empty, each backend is tried in order until one succeeds.
func (c *CompositeBackend) Sign(handle KeyHandle, algorithm int, data []byte) ([]byte, error) {
	if handle == nil {
		return nil, ErrInvalidKeyHandle
	}

	bt := handle.BackendID()
	if bt != "" {
		b, err := c.resolveBackend(bt)
		if err != nil {
			return nil, err
		}
		return b.Sign(handle, algorithm, data)
	}

	// BackendID is empty; try each backend.
	c.mu.RLock()
	defer c.mu.RUnlock()

	var lastErr error
	for _, b := range c.backends {
		sig, err := b.Sign(handle, algorithm, data)
		if err == nil {
			return sig, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrBackendNotFound
}

// LoadKey tries each registered backend in order and returns the first
// successful result. This supports credentials created before BackendID
// tracking was introduced.
func (c *CompositeBackend) LoadKey(credentialID []byte, algorithm int) (KeyHandle, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var lastErr error
	for _, b := range c.backends {
		handle, err := b.LoadKey(credentialID, algorithm)
		if err == nil {
			return handle, nil
		}
		if !errors.Is(err, ErrKeyNotFound) {
			lastErr = err
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrKeyNotFound
}

// DeleteKey routes to the backend identified by handle.BackendID().
func (c *CompositeBackend) DeleteKey(handle KeyHandle) error {
	if handle == nil {
		return ErrInvalidKeyHandle
	}
	b, err := c.resolveBackend(handle.BackendID())
	if err != nil {
		return err
	}
	return b.DeleteKey(handle)
}

// ExportPrivateKey routes to the backend identified by handle.BackendID().
func (c *CompositeBackend) ExportPrivateKey(handle KeyHandle) ([]byte, error) {
	if handle == nil {
		return nil, ErrInvalidKeyHandle
	}
	b, err := c.resolveBackend(handle.BackendID())
	if err != nil {
		return nil, err
	}
	return b.ExportPrivateKey(handle)
}

// ImportPrivateKey routes to the default backend.
func (c *CompositeBackend) ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (KeyHandle, error) {
	b, err := c.resolveDefault()
	if err != nil {
		return nil, err
	}
	return b.ImportPrivateKey(credentialID, algorithm, pkcs8Key)
}

// Close closes all registered backends. All errors are collected; the first
// non-nil error is returned.
func (c *CompositeBackend) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var firstErr error
	for _, b := range c.backends {
		if err := b.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Backend returns the backend registered under the given type, or nil if not found.
func (c *CompositeBackend) Backend(bt types.BackendType) FIDO2KeyBackend {
	c.mu.RLock()
	b := c.backends[bt]
	c.mu.RUnlock()
	return b
}

// Backends returns a snapshot of all registered backend types.
func (c *CompositeBackend) Backends() []types.BackendType {
	c.mu.RLock()
	defer c.mu.RUnlock()

	bts := make([]types.BackendType, 0, len(c.backends))
	for bt := range c.backends {
		bts = append(bts, bt)
	}
	return bts
}

// resolveDefault returns the default backend.
func (c *CompositeBackend) resolveDefault() (FIDO2KeyBackend, error) {
	c.mu.RLock()
	b, ok := c.backends[c.defaultBackend]
	c.mu.RUnlock()
	if !ok {
		return nil, ErrBackendNotFound
	}
	return b, nil
}

// resolveBackend returns the backend for the given type.
func (c *CompositeBackend) resolveBackend(bt types.BackendType) (FIDO2KeyBackend, error) {
	c.mu.RLock()
	b, ok := c.backends[bt]
	c.mu.RUnlock()
	if !ok {
		return nil, ErrBackendNotFound
	}
	return b, nil
}

// Ensure CompositeBackend implements FIDO2KeyBackend.
var _ FIDO2KeyBackend = (*CompositeBackend)(nil)
