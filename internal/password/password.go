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

// Package password provides secure password handling utilities for the keychain.
//
// This package implements the Password interface for managing sensitive password
// data in memory, with support for secure string handling and memory zeroing when
// appropriate.
package password

import (
	"crypto/subtle"
	"errors"
)

var (
	// ErrEmptyPassword is returned when an empty password is provided.
	ErrEmptyPassword = errors.New("password cannot be empty")
)

// Password represents a secret used to protect or access data.
//
// Passwords can be used for various purposes including system-to-system
// interactions, such as when a web application communicates with a database,
// or for encrypting/decrypting private keys.
type Password interface {
	// String returns the password as a string.
	String() (string, error)

	// Bytes returns the password as a byte slice.
	Bytes() ([]byte, error)

	// Zero securely clears the password from memory.
	Zero()
}

// ClearPassword stores a password in memory as cleartext.
//
// While stored in cleartext, the password data is protected in memory
// and can be securely zeroed when no longer needed.
type ClearPassword struct {
	password []byte
}

// NewClearPassword creates a new cleartext password stored in memory.
//
// The provided byte slice is copied to prevent external modification.
// Returns an error if the password is empty.
func NewClearPassword(password []byte) (Password, error) {
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	// Copy the password to prevent external modification
	p := make([]byte, len(password))
	copy(p, password)
	return &ClearPassword{password: p}, nil
}

// NewClearPasswordFromString creates a new cleartext password from a string.
//
// The string is converted to bytes and stored securely in memory.
// Returns an error if the password is empty.
func NewClearPasswordFromString(password string) (Password, error) {
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	return &ClearPassword{password: []byte(password)}, nil
}

// String returns the password as a string.
//
// Note: This method exposes the password as a string, which may be
// less secure than working with byte slices. Use with caution.
func (p *ClearPassword) String() (string, error) {
	if p.password == nil {
		return "", errors.New("password has been zeroed")
	}
	return string(p.password), nil
}

// Bytes returns the password as a byte slice.
//
// The returned slice is a copy to prevent external modification
// of the internal password data.
func (p *ClearPassword) Bytes() ([]byte, error) {
	if p.password == nil {
		return nil, errors.New("password has been zeroed")
	}
	// Return a copy to prevent external modification
	result := make([]byte, len(p.password))
	copy(result, p.password)
	return result, nil
}

// Zero securely clears the password from memory.
//
// After calling Zero, the password cannot be retrieved and any
// subsequent calls to String() or Bytes() will return an error.
// This operation is irreversible.
func (p *ClearPassword) Zero() {
	if p.password != nil {
		// Overwrite memory with zeros using constant-time operation
		for i := range p.password {
			p.password[i] = 0
		}
		// Use subtle.ConstantTimeCopy to ensure compiler doesn't optimize away
		subtle.ConstantTimeCopy(1, p.password, make([]byte, len(p.password)))
		p.password = nil
	}
}

// Equal compares two passwords in constant time to prevent timing attacks.
//
// Returns true if the passwords are equal, false otherwise.
func Equal(a, b Password) (bool, error) {
	aBytes, err := a.Bytes()
	if err != nil {
		return false, err
	}
	defer func() {
		// Zero the copy after comparison
		for i := range aBytes {
			aBytes[i] = 0
		}
	}()

	bBytes, err := b.Bytes()
	if err != nil {
		return false, err
	}
	defer func() {
		// Zero the copy after comparison
		for i := range bBytes {
			bBytes[i] = 0
		}
	}()

	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1, nil
}
