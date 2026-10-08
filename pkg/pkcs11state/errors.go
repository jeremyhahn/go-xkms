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

package pkcs11state

import (
	"errors"
	"fmt"
)

// ErrNilDAOFactory is returned by NewStore without a DAO factory.
var ErrNilDAOFactory = errors.New("pkcs11state: a DAO factory is required")

// StoreError wraps a failure of the record store. Op names the operation
// ("open", "put", "put-if-absent", "compare-and-swap", "compare-and-delete",
// "get", "delete" or "list") and Key the record name, or the scope for a
// list. A failed conditional write's outcome is unknown, so it is never
// reported as a refusal.
type StoreError struct {
	Op  string
	Key string
	Err error
}

// Error implements the error interface.
func (e *StoreError) Error() string {
	return fmt.Sprintf("pkcs11state: %s %q: %v", e.Op, e.Key, e.Err)
}

// Unwrap returns the underlying cause.
func (e *StoreError) Unwrap() error { return e.Err }
