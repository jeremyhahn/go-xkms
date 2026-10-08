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

package aeadnonce

import (
	"errors"
	"fmt"
)

// ErrNilDAOFactory is returned by NewStore without a DAO factory.
var ErrNilDAOFactory = errors.New("aeadnonce: a DAO factory is required")

// StoreError wraps a failure of the claim store. Op is "open" for NewStore
// and "claim" for ClaimNonce. A failed claim's outcome is unknown, so it is
// never reported as a refusal.
type StoreError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *StoreError) Error() string {
	return fmt.Sprintf("aeadnonce: %s: %v", e.Op, e.Err)
}

// Unwrap returns the underlying cause.
func (e *StoreError) Unwrap() error { return e.Err }
