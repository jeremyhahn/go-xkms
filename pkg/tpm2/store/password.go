// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package store

import (
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

const (
	// DEFAULT_PASSWORD is the default password for TPM hierarchies
	DEFAULT_PASSWORD = "changeme"
)

// ClearPassword implements types.Password for clear text passwords.
// Used for TPM key authentication (UserAuth).
type ClearPassword struct {
	password []byte
}

// NewPassword creates a new clear text password for TPM key authentication.
// Use this for UserAuth values passed to TPM operations.
func NewPassword(password []byte) types.Password {
	return &ClearPassword{password: password}
}

// NewClearPassword is an alias for NewPassword for backward compatibility.
// Deprecated: Use NewPassword instead.
func NewClearPassword(password []byte) types.Password {
	return NewPassword(password)
}

// Bytes returns the password as bytes
func (p *ClearPassword) Bytes() []byte {
	return p.password
}

// String returns the password as a string
func (p *ClearPassword) String() (string, error) {
	return string(p.password), nil
}

// Clear zeros out the password from memory
func (p *ClearPassword) Clear() {
	for i := range p.password {
		p.password[i] = 0
	}
}

// RequiredPassword implements types.Password but returns an error
// Used when a password is required but not stored
type RequiredPassword struct{}

// NewRequiredPassword creates a password placeholder that returns ErrPasswordRequired
func NewRequiredPassword() types.Password {
	return &RequiredPassword{}
}

// Bytes returns nil for RequiredPassword
func (p *RequiredPassword) Bytes() []byte {
	return nil
}

// String returns ErrPasswordRequired
func (p *RequiredPassword) String() (string, error) {
	return "", ErrPasswordRequired
}

// Clear is a no-op
func (p *RequiredPassword) Clear() {}
