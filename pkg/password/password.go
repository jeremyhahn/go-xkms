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

// Package password provides secure password handling utilities for xkms.
//
// ClearPassword stores the password in a go-enclave-backed *secure.Buffer
// so the plaintext never sits on the ordinary Go heap. Callers receive
// defensive copies from Bytes/String and MUST invoke Clear when the
// password is no longer needed; Clear destroys the enclave and
// subsequent access returns ErrPasswordZeroed.
package password

import (
	"crypto/subtle"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

var (
	// ErrEmptyPassword is returned when an empty password is provided.
	ErrEmptyPassword = errors.New("password cannot be empty")

	// ErrPasswordZeroed is returned when the password has been zeroed.
	ErrPasswordZeroed = errors.New("password has been zeroed")

	// ErrEnclaveUnavailable is returned when a password cannot get its
	// locked buffer: the process locked-memory budget refuses it, or the
	// kernel will not lock the pages (RLIMIT_MEMLOCK). Callers cannot
	// recover.
	ErrEnclaveUnavailable = errors.New("secure enclave unavailable")
)

// ClearPassword holds a password in a locked go-enclave memory enclave.
//
// The enclave guarantees the plaintext never sits on the ordinary Go
// heap; the bytes are mlocked, canary-guarded, and wiped on Destroy.
// ClearPassword is not safe for concurrent mutation (NewPassword then
// Clear from the same goroutine is fine; concurrent Clear + Bytes is
// not). This matches the prior cleartext semantics.
type ClearPassword struct {
	buf *secure.Buffer
}

// NewPassword creates a new password in a locked go-enclave memory enclave.
//
// The provided slice is copied into the enclave; the caller's slice
// is NOT wiped — callers that control the source should wipe after
// construction. Returns ErrEmptyPassword on an empty or nil input.
func NewPassword(password []byte) (types.Password, error) {
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	return newClearPassword(len(password), func(dst []byte) { copy(dst, password) })
}

// newClearPassword allocates an enclave of size bytes and has fill write the
// password into it while the borrow is held. A failed allocation or borrow
// returns ErrEnclaveUnavailable rather than a usable password.
func newClearPassword(size int, fill func(dst []byte)) (types.Password, error) {
	buf, err := secure.NewBuffer(size)
	if err != nil {
		return nil, ErrEnclaveUnavailable
	}
	if err := buf.WithBytes(func(dst []byte) error {
		fill(dst)
		return nil
	}); err != nil {
		buf.Destroy()
		return nil, ErrEnclaveUnavailable
	}
	return &ClearPassword{buf: buf}, nil
}

// NewPasswordFromString creates a new password from a string.
//
// The string bytes are copied into an enclave. Note: the input
// string itself continues to live on the Go heap until GC reclaims
// it; when possible prefer NewPassword with a caller-managed byte
// slice so the source can be wiped immediately.
func NewPasswordFromString(password string) (types.Password, error) {
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	return newClearPassword(len(password), func(dst []byte) { copy(dst, password) })
}

// String returns types.PasswordRedacted. It never returns the password: a
// Go string can never be wiped, so the secret is only reachable through
// Bytes.
func (p *ClearPassword) String() string {
	return types.PasswordRedacted
}

// WithBytes lends the enclaved password bytes to fn for the duration of the
// call. Returns ErrPasswordZeroed after Clear, without calling fn.
func (p *ClearPassword) WithBytes(fn func([]byte) error) error {
	if p.buf == nil {
		return ErrPasswordZeroed
	}
	return p.buf.WithBytes(fn)
}

// Bytes returns a defensive copy of the password bytes.
//
// The copy is an ordinary Go slice (not enclaved) — callers use it
// for one crypto call and discard. Returns nil after Clear.
func (p *ClearPassword) Bytes() []byte {
	if p.buf == nil {
		return nil
	}
	result, err := secure.CopyOut(p.buf)
	if err != nil {
		return nil
	}
	return result
}

// Clear destroys the enclave holding the password.
//
// After Clear, the password cannot be retrieved and subsequent calls
// to WithBytes return ErrPasswordZeroed and Bytes returns nil. Clear
// is idempotent.
func (p *ClearPassword) Clear() {
	if p.buf != nil {
		p.buf.Destroy()
		p.buf = nil
	}
}

// Equal compares two passwords in constant time to prevent timing
// attacks. Both passwords must be live (not zeroed); a zeroed
// operand returns ErrPasswordZeroed.
func Equal(a, b types.Password) (bool, error) {
	aBytes := a.Bytes()
	if aBytes == nil {
		return false, ErrPasswordZeroed
	}
	defer secure.Wipe(aBytes)

	bBytes := b.Bytes()
	if bBytes == nil {
		return false, ErrPasswordZeroed
	}
	defer secure.Wipe(bBytes)

	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1, nil
}

// Verify interface compliance at compile time.
var _ types.Password = (*ClearPassword)(nil)
