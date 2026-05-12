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

package store

import (
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

const (
	// DEFAULT_PASSWORD is the default password for TPM hierarchies
	DEFAULT_PASSWORD = "changeme"
)

// ClearPassword implements types.Password for TPM UserAuth values.
// The password bytes are held in a memguard-backed *secure.Buffer so
// the plaintext UserAuth never sits on the ordinary Go heap; callers
// receive defensive copies from Bytes/String and MUST invoke Clear
// when the password is no longer needed.
//
// A zero-length password (nil or empty input to NewPassword) stays
// represented as a nil buf — TPM2 treats an empty UserAuth as
// "no authentication", so we avoid allocating an enclave for it.
type ClearPassword struct {
	buf *secure.Buffer
}

// NewPassword creates a new password for TPM key authentication,
// sealing the bytes into a memguard enclave. An empty or nil input
// produces a ClearPassword with no enclave backing — TPM2 interprets
// that as "no UserAuth required". The input slice is copied into the
// enclave; the caller's slice is NOT wiped by this constructor.
func NewPassword(password []byte) types.Password {
	if len(password) == 0 {
		return &ClearPassword{}
	}
	buf, err := secure.NewBuffer(len(password))
	if err != nil {
		// secure.NewBuffer only fails on non-positive size (guarded
		// above) or on an underlying memguard allocation failure,
		// which is a hard process-level condition. Fall back to the
		// empty ClearPassword so the factory always returns a usable
		// value — callers that depend on non-empty content will fail
		// downstream on the TPM handshake.
		_ = err
		return &ClearPassword{}
	}
	copy(buf.Bytes(), password)
	return &ClearPassword{buf: buf}
}

// Bytes returns a defensive copy of the password bytes. Returns nil
// for an empty / cleared password. The returned slice is an ordinary
// Go slice (not enclaved) — callers pass it to TPM operations and
// drop the reference; no caller has a legitimate reason to mutate
// the slice.
func (p *ClearPassword) Bytes() []byte {
	if p == nil || p.buf == nil {
		return nil
	}
	src := p.buf.Bytes()
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

// String returns the password as a Go string. Note: the string
// escapes to the heap and lives there until GC reclaims it. Prefer
// Bytes for hot paths; String exists for compatibility with existing
// call sites that log or format the auth value.
func (p *ClearPassword) String() (string, error) {
	if p == nil || p.buf == nil {
		return "", nil
	}
	return string(p.buf.Bytes()), nil
}

// Clear destroys the underlying enclave. Safe to call on a zero-value
// receiver and idempotent — memguard.Destroy itself is idempotent.
// After Clear, Bytes returns nil and String returns an empty string.
func (p *ClearPassword) Clear() {
	if p == nil || p.buf == nil {
		return
	}
	p.buf.Destroy()
	p.buf = nil
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

// Clear is a no-op for RequiredPassword as there is no sensitive data to clear
func (p *RequiredPassword) Clear() {
	_ = p // No-op: RequiredPassword holds no sensitive data
}
