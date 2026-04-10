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

package services

import (
	"errors"
	"sync"
	"sync/atomic"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// ErrTPMShuttingDown indicates the TPM accessor has been shut down and is
// no longer accepting new operations.
var ErrTPMShuttingDown = errors.New("tpm_service: TPM accessor is shutting down")

// TPMAccessor provides serialized access to a shared TPM device.
// All services that need the TPM should use a single TPMAccessor instance
// to ensure cross-service serialization of TPM commands.
type TPMAccessor struct {
	mu      sync.Mutex
	tpmFunc func() tpm2pkg.TrustedPlatformModule
	closed  atomic.Bool
}

// NewTPMAccessor creates a new TPMAccessor with the given function to
// obtain the TrustedPlatformModule instance.
func NewTPMAccessor(fn func() tpm2pkg.TrustedPlatformModule) *TPMAccessor {
	return &TPMAccessor{tpmFunc: fn}
}

// Acquire locks the shared TPM mutex and returns the TPM instance.
// On success the caller MUST call Release when done with the TPM.
// On error (TPM unavailable or shutting down) the mutex is NOT held.
func (a *TPMAccessor) Acquire() (tpm2pkg.TrustedPlatformModule, error) {
	if a.closed.Load() {
		return nil, ErrTPMShuttingDown
	}
	a.mu.Lock()
	if a.closed.Load() {
		a.mu.Unlock()
		return nil, ErrTPMShuttingDown
	}
	if a.tpmFunc == nil {
		a.mu.Unlock()
		return nil, ErrTPMNotAvailable
	}
	tpm := a.tpmFunc()
	if tpm == nil {
		a.mu.Unlock()
		return nil, ErrTPMNotAvailable
	}
	return tpm, nil
}

// Release unlocks the shared TPM mutex. Callers must call Release
// after a successful Acquire once they are done with the TPM instance.
func (a *TPMAccessor) Release() {
	a.mu.Unlock()
}

// Shutdown marks the accessor as closed and waits for any in-flight
// TPM operation to complete. After Shutdown returns, all subsequent
// Acquire calls will return ErrTPMShuttingDown.
func (a *TPMAccessor) Shutdown() {
	a.closed.Store(true)
	// Acquire and release the mutex to wait for any in-flight operation.
	a.mu.Lock()
	a.mu.Unlock()
}
