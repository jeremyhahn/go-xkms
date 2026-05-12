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
// ClearPassword stores the password in a memguard-backed *secure.Buffer
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

	// ErrEnclaveUnavailable is returned when memguard fails to allocate
	// an mlocked region. This is a hard system condition (RLIMIT_MEMLOCK
	// exhausted, no swap, etc.) and callers cannot recover.
	ErrEnclaveUnavailable = errors.New("secure enclave unavailable")
)

// ClearPassword holds a password inside a memguard-backed enclave.
//
// The enclave guarantees the plaintext never sits on the ordinary Go
// heap; the bytes are mlocked, canary-guarded, and wiped on Destroy.
// ClearPassword is not safe for concurrent mutation (NewPassword then
// Clear from the same goroutine is fine; concurrent Clear + Bytes is
// not). This matches the prior cleartext semantics.
type ClearPassword struct {
	buf *secure.Buffer
}

// NewPassword creates a new password stored in a memguard enclave.
//
// The provided slice is copied into the enclave; the caller's slice
// is NOT wiped — callers that control the source should wipe after
// construction. Returns ErrEmptyPassword on an empty or nil input.
func NewPassword(password []byte) (types.Password, error) {
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	buf, err := secure.NewBuffer(len(password))
	if err != nil {
		return nil, ErrEnclaveUnavailable
	}
	copy(buf.Bytes(), password)
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
	buf, err := secure.NewBuffer(len(password))
	if err != nil {
		return nil, ErrEnclaveUnavailable
	}
	copy(buf.Bytes(), []byte(password))
	return &ClearPassword{buf: buf}, nil
}

// String returns the password as a string.
//
// Note: the returned string is a heap allocation that survives until
// GC reclaims it. Prefer Bytes followed by immediate wipe for hot
// paths. Returns ErrPasswordZeroed after Clear.
func (p *ClearPassword) String() (string, error) {
	if p.buf == nil {
		return "", ErrPasswordZeroed
	}
	return string(p.buf.Bytes()), nil
}

// Bytes returns a defensive copy of the password bytes.
//
// The copy is an ordinary Go slice (not enclaved) — callers use it
// for one crypto call and discard. Returns nil after Clear.
func (p *ClearPassword) Bytes() []byte {
	if p.buf == nil {
		return nil
	}
	src := p.buf.Bytes()
	result := make([]byte, len(src))
	copy(result, src)
	return result
}

// Clear destroys the enclave holding the password.
//
// After Clear, the password cannot be retrieved and subsequent calls
// to String return ErrPasswordZeroed and Bytes returns nil. Clear
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
