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
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// BarrierStateProvider reports whether the barrier is unsealed and auto-UV should be active.
type BarrierStateProvider interface {
	// IsAutoUVActive returns true when the auto-unseal barrier is unsealed
	// and user verification should be reported as handled by the backend.
	IsAutoUVActive() bool
}

// AutoUVBackend wraps a FIDO2KeyBackend and reports HandlesUserVerification=true
// when a BarrierStateProvider confirms auto-unseal is active and the barrier is unsealed.
// All other operations delegate directly to the inner backend.
type AutoUVBackend struct {
	inner    FIDO2KeyBackend
	provider BarrierStateProvider
}

// NewAutoUVBackend creates an AutoUVBackend that decorates the given inner backend.
// When the provider reports the barrier as unsealed, Capabilities will override
// HandlesUserVerification to true. All other methods are pure delegation.
func NewAutoUVBackend(inner FIDO2KeyBackend, provider BarrierStateProvider) *AutoUVBackend {
	return &AutoUVBackend{
		inner:    inner,
		provider: provider,
	}
}

// Type returns the inner backend's type identifier.
func (a *AutoUVBackend) Type() types.BackendType {
	return a.inner.Type()
}

// Capabilities returns the inner backend's capabilities, overriding
// HandlesUserVerification to true when the provider reports auto-UV is active.
func (a *AutoUVBackend) Capabilities() FIDO2KeyCapabilities {
	caps := a.inner.Capabilities()
	if a.provider.IsAutoUVActive() {
		caps.HandlesUserVerification = true
	}
	return caps
}

// GenerateCredentialKey delegates to the inner backend.
func (a *AutoUVBackend) GenerateCredentialKey(algorithm int, credentialID []byte) (KeyHandle, []byte, error) {
	return a.inner.GenerateCredentialKey(algorithm, credentialID)
}

// Sign delegates to the inner backend.
func (a *AutoUVBackend) Sign(handle KeyHandle, algorithm int, data []byte) ([]byte, error) {
	return a.inner.Sign(handle, algorithm, data)
}

// LoadKey delegates to the inner backend.
func (a *AutoUVBackend) LoadKey(credentialID []byte, algorithm int) (KeyHandle, error) {
	return a.inner.LoadKey(credentialID, algorithm)
}

// DeleteKey delegates to the inner backend.
func (a *AutoUVBackend) DeleteKey(handle KeyHandle) error {
	return a.inner.DeleteKey(handle)
}

// ExportPrivateKey delegates to the inner backend.
func (a *AutoUVBackend) ExportPrivateKey(handle KeyHandle) ([]byte, error) {
	return a.inner.ExportPrivateKey(handle)
}

// ImportPrivateKey delegates to the inner backend.
func (a *AutoUVBackend) ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (KeyHandle, error) {
	return a.inner.ImportPrivateKey(credentialID, algorithm, pkcs8Key)
}

// Close delegates to the inner backend.
func (a *AutoUVBackend) Close() error {
	return a.inner.Close()
}

// Compile-time interface check.
var _ FIDO2KeyBackend = (*AutoUVBackend)(nil)
