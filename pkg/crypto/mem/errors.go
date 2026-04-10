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

package mem

import "fmt"

// ErrInvalidSize is returned when a guarded buffer is requested with a
// non-positive size.
type ErrInvalidSize struct {
	Size int
}

func (e *ErrInvalidSize) Error() string {
	return fmt.Sprintf("mem: guarded buffer size must be positive, got %d", e.Size)
}

// ErrMmapFailed is returned when the mmap system call fails during
// guarded buffer allocation.
type ErrMmapFailed struct {
	Cause error
}

func (e *ErrMmapFailed) Error() string {
	return fmt.Sprintf("mem: mmap failed: %s", e.Cause)
}

func (e *ErrMmapFailed) Unwrap() error {
	return e.Cause
}

// ErrMprotectFailed is returned when mprotect fails while setting up
// guard pages for a guarded buffer.
type ErrMprotectFailed struct {
	Page  string
	Cause error
}

func (e *ErrMprotectFailed) Error() string {
	return fmt.Sprintf("mem: mprotect %s guard failed: %s", e.Page, e.Cause)
}

func (e *ErrMprotectFailed) Unwrap() error {
	return e.Cause
}
