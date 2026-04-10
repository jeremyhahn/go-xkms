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

package cmd

import "fmt"

// BarrierError represents a barrier operation error.
type BarrierError struct {
	Operation string
	Message   string
	Err       error
}

// Error returns the error message.
func (e *BarrierError) Error() string {
	if e.Err != nil {
		if e.Message != "" {
			return fmt.Sprintf("barrier: %s: %s: %v", e.Operation, e.Message, e.Err)
		}
		return fmt.Sprintf("barrier: %s: %v", e.Operation, e.Err)
	}
	if e.Message != "" {
		return fmt.Sprintf("barrier: %s: %s", e.Operation, e.Message)
	}
	return fmt.Sprintf("barrier: %s", e.Operation)
}

// Unwrap returns the underlying error.
func (e *BarrierError) Unwrap() error {
	return e.Err
}

// Barrier command sentinel errors.
var (
	ErrBarrierPasswordRead    = &BarrierError{Operation: "read_password", Message: "failed to read password"}
	ErrBarrierPasswordEmpty   = &BarrierError{Operation: "read_password", Message: "password cannot be empty"}
	ErrBarrierPasswordConfirm = &BarrierError{Operation: "read_password", Message: "passwords do not match"}
	ErrBarrierInitFailed      = &BarrierError{Operation: "initialize", Message: "failed to initialize barrier"}
	ErrBarrierUnsealFailed    = &BarrierError{Operation: "unseal", Message: "failed to unseal barrier"}
	ErrBarrierSealFailed      = &BarrierError{Operation: "seal", Message: "failed to seal barrier"}
	ErrBarrierStatusFailed    = &BarrierError{Operation: "status", Message: "failed to get barrier status"}
	ErrBarrierCreateFailed    = &BarrierError{Operation: "create", Message: "failed to create barrier"}
	ErrBarrierStorageFailed   = &BarrierError{Operation: "storage", Message: "failed to create storage backend"}
	ErrBarrierDataDirResolve  = &BarrierError{Operation: "resolve_data_dir", Message: "failed to resolve data directory"}
	ErrBarrierInvalidStrategy = &BarrierError{Operation: "strategy", Message: "invalid strategy"}
)
