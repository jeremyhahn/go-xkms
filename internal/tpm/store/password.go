// Package store provides password implementations
package store

import (
	"errors"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

const (
	// DEFAULT_PASSWORD is the default password for TPM hierarchies
	DEFAULT_PASSWORD = "changeme"
)

var (
	// ErrPasswordRequired indicates a password is required but not provided
	ErrPasswordRequired = errors.New("password required")
)

// ClearPassword implements types.Password for clear text passwords
type ClearPassword struct {
	password []byte
}

// NewClearPassword creates a new clear text password
func NewClearPassword(password []byte) types.Password {
	return &ClearPassword{password: password}
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

// Bytes returns ErrPasswordRequired
func (p *RequiredPassword) Bytes() []byte {
	return nil
}

// String returns ErrPasswordRequired
func (p *RequiredPassword) String() (string, error) {
	return "", ErrPasswordRequired
}

// Clear is a no-op
func (p *RequiredPassword) Clear() {}
