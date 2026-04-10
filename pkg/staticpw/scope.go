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

package staticpw

// PasswordScope identifies the visibility of a password entry within a tenant.
type PasswordScope string

const (
	// ScopePersonal restricts listing to the current user's personal passwords.
	ScopePersonal PasswordScope = "personal"

	// ScopeShared restricts listing to tenant-wide shared passwords.
	ScopeShared PasswordScope = "shared"

	// ScopeAll returns both personal and shared passwords.
	ScopeAll PasswordScope = "all"
)

// IsValid reports whether the scope value is a recognized PasswordScope.
func (s PasswordScope) IsValid() bool {
	switch s {
	case ScopePersonal, ScopeShared, ScopeAll:
		return true
	default:
		return false
	}
}
