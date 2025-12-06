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

package keychain

// Password represents a secret used to authenticate or decrypt protected data.
// Implementations may store passwords in memory, retrieve them from secure storage,
// or use other mechanisms to protect sensitive credential information.
//
// The interface separates the concept of a password from its storage mechanism,
// allowing for different security models ranging from clear-text in-memory
// storage to hardware-backed secure enclaves.
type Password interface {
	// String returns the password as a string.
	// Returns an error if the password cannot be retrieved.
	String() (string, error)

	// Bytes returns the password as a byte slice.
	// Returns an error if the password cannot be retrieved.
	Bytes() ([]byte, error)
}

// ClearPassword is a simple in-memory implementation of the Password interface
// that stores the password in clear text. This implementation should only be
// used in development or testing environments, or where the security model
// explicitly accepts storing passwords in memory.
type ClearPassword struct {
	password []byte
}

// NewPassword creates a new clear text password stored in memory.
// The password is copied to prevent external modification.
func NewPassword(password []byte) Password {
	p := make([]byte, len(password))
	copy(p, password)
	return &ClearPassword{password: p}
}

// NewPasswordFromString creates a new clear text password from a string.
// The string is converted to bytes and stored in memory.
func NewPasswordFromString(password string) Password {
	return &ClearPassword{password: []byte(password)}
}

// NewClearPassword is an alias for NewPassword for backward compatibility.
// Deprecated: Use NewPassword instead.
func NewClearPassword(password []byte) Password {
	return NewPassword(password)
}

// NewClearPasswordFromString is an alias for NewPasswordFromString for backward compatibility.
// Deprecated: Use NewPasswordFromString instead.
func NewClearPasswordFromString(password string) Password {
	return NewPasswordFromString(password)
}

// String returns the password as a string.
func (p *ClearPassword) String() (string, error) {
	return string(p.password), nil
}

// Bytes returns the password as a byte slice.
// A copy is returned to prevent external modification of the internal password.
func (p *ClearPassword) Bytes() ([]byte, error) {
	// Return a copy to prevent external modification
	b := make([]byte, len(p.password))
	copy(b, p.password)
	return b, nil
}

// Zeroize overwrites the password memory with zeros.
// This should be called when the password is no longer needed to minimize
// the time sensitive data remains in memory.
func (p *ClearPassword) Zeroize() {
	for i := range p.password {
		p.password[i] = 0
	}
}
