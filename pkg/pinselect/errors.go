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

package pinselect

import "errors"

// ErrNoSoftwareProvider is returned by Select when Config.Software is nil. The
// software backend is the mandatory fallback; without it Select cannot
// guarantee a usable PINBackend.
var ErrNoSoftwareProvider = errors.New("pinselect: Config.Software provider is required")

// ErrNoBackendAvailable is returned when a custom preference order omits the
// software strategy and no hardware backend is available. The default order
// always includes software, so this only occurs with a misconfigured
// Config.Preference.
var ErrNoBackendAvailable = errors.New("pinselect: no PIN backend available for the configured preference order")

// SoftwareStorageError wraps a failure opening the software PIN store or
// constructing the software backend.
type SoftwareStorageError struct {
	Cause error
}

// Error implements the error interface.
func (e *SoftwareStorageError) Error() string {
	if e.Cause == nil {
		return "pinselect: software PIN backend construction failed"
	}
	return "pinselect: software PIN backend construction failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause for errors.Is / errors.As traversal.
func (e *SoftwareStorageError) Unwrap() error { return e.Cause }
