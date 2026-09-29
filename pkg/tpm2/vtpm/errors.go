// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package vtpm

import (
	"errors"
	"fmt"
)

var (
	// ErrStateDirRequired is returned by NewManager when Config.StateDir is
	// empty: a vTPM's state must persist somewhere the node controls.
	ErrStateDirRequired = errors.New("vtpm: Config.StateDir is required")

	// ErrRunDirRequired is returned by NewManager when Config.RunDir is
	// empty: the vTPM sockets need a private directory.
	ErrRunDirRequired = errors.New("vtpm: Config.RunDir is required")

	// ErrKeyProviderRequired is returned by NewManager when no StateKeyProvider
	// is supplied: a vTPM's state is never written unencrypted.
	ErrKeyProviderRequired = errors.New("vtpm: a StateKeyProvider is required")

	// ErrInvalidTenant is returned for a tenant ID that cannot name a vTPM
	// (empty, or containing a path separator).
	ErrInvalidTenant = errors.New("vtpm: invalid tenant ID")

	// ErrNotRunning is returned when a tenant's vTPM is not running.
	ErrNotRunning = errors.New("vtpm: the tenant's vTPM is not running")

	// ErrManagerClosed is returned by every call after Close.
	ErrManagerClosed = errors.New("vtpm: manager is closed")

	// ErrConnectionLost is returned by a Transport when the vTPM connection
	// dropped after a command was sent, so whether the command ran is
	// unknown. The next Send reconnects.
	ErrConnectionLost = errors.New("vtpm: connection to the vTPM was lost mid-command")

	// ErrResponseTooLarge is returned when a vTPM response header declares a
	// size beyond the TPM 2.0 maximum.
	ErrResponseTooLarge = errors.New("vtpm: response exceeds the maximum TPM response size")
)

// StateKeyError wraps a failure obtaining a tenant's state-encryption key.
type StateKeyError struct {
	Tenant string
	Err    error
}

// Error implements the error interface.
func (e *StateKeyError) Error() string {
	return fmt.Sprintf("vtpm: state key for tenant %q: %v", e.Tenant, e.Err)
}

// Unwrap returns the underlying cause.
func (e *StateKeyError) Unwrap() error { return e.Err }

// StateKeySizeError reports a state key that is not an AES-256 key.
type StateKeySizeError struct {
	Tenant string
	Size   int
}

// Error implements the error interface.
func (e *StateKeySizeError) Error() string {
	return fmt.Sprintf("vtpm: state key for tenant %q is %d bytes, want %d", e.Tenant, e.Size, StateKeySize)
}

// StartError wraps a failure starting a tenant's swtpm process.
type StartError struct {
	Tenant string
	Err    error
}

// Error implements the error interface.
func (e *StartError) Error() string {
	return fmt.Sprintf("vtpm: starting the vTPM for tenant %q: %v", e.Tenant, e.Err)
}

// Unwrap returns the underlying cause.
func (e *StartError) Unwrap() error { return e.Err }

// StopError wraps a failure stopping a tenant's swtpm process.
type StopError struct {
	Tenant string
	Err    error
}

// Error implements the error interface.
func (e *StopError) Error() string {
	return fmt.Sprintf("vtpm: stopping the vTPM for tenant %q: %v", e.Tenant, e.Err)
}

// Unwrap returns the underlying cause.
func (e *StopError) Unwrap() error { return e.Err }
