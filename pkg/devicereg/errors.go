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

package devicereg

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidConfig reports a registry built without a DAO factory.
	ErrInvalidConfig = errors.New("devicereg: invalid config")

	// ErrInvalidTenant reports an empty or malformed tenant.
	ErrInvalidTenant = errors.New("devicereg: invalid tenant")

	// ErrInvalidID reports a device ID that is not one path-safe name.
	ErrInvalidID = errors.New("devicereg: invalid device ID")

	// ErrInvalidDevice reports a device record that cannot be paired, or a
	// revoke with no time.
	ErrInvalidDevice = errors.New("devicereg: invalid device")

	// ErrDeviceExists reports a pair of an ID the tenant already holds,
	// active or revoked.
	ErrDeviceExists = errors.New("devicereg: device already paired")

	// ErrDeviceNotFound reports an ID the tenant does not hold.
	ErrDeviceNotFound = errors.New("devicereg: device not found")

	// ErrRevokeConflict reports a revoke whose every compare-and-swap lost
	// to a concurrent write of the same record.
	ErrRevokeConflict = errors.New("devicereg: revoke lost every compare-and-swap")
)

// StoreError reports a failure of the qrdb store under the registry.
type StoreError struct {
	// Op is the registry operation: pair, get, list or revoke.
	Op string
	// ID is the device ID, empty for a list.
	ID string
	// Err is the store's error.
	Err error
}

// Error implements error.
func (e *StoreError) Error() string {
	return fmt.Sprintf("devicereg: %s %q: %v", e.Op, e.ID, e.Err)
}

// Unwrap returns the store's error.
func (e *StoreError) Unwrap() error { return e.Err }
