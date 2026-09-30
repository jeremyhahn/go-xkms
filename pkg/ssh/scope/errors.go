// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package scope

import "github.com/jeremyhahn/go-xkms/pkg/scope"

// ScopeInvalidError is returned by Parse / BuildKeyID / ParseKeyID when
// the scope component is not one of the canonical values (tenant, user,
// service). It is the xkms-wide scope.InvalidScopeError; Value holds the
// offending input exactly as supplied.
type ScopeInvalidError = scope.InvalidScopeError

// KeyIDMalformedError is returned when a key-ID component is missing,
// empty, or contains the reserved separator. Field identifies which
// component failed validation (id, owner, or name) so callers can
// surface a precise error to users without re-parsing the string.
type KeyIDMalformedError struct {
	Field  string
	Reason string
}

// Error implements the error interface.
func (e *KeyIDMalformedError) Error() string {
	return "ssh/scope: malformed key id: " + e.Field + ": " + e.Reason
}
