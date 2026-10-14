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
	pwenclave "github.com/jeremyhahn/go-xkms/pkg/password"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

const (
	// DEFAULT_PASSWORD is the default password for TPM hierarchies
	DEFAULT_PASSWORD = "changeme"
)

// ClearPassword implements types.Password for TPM UserAuth values.
// The password bytes are held in a go-enclave-backed *secure.Buffer so
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
// copying the bytes into a locked go-enclave memory enclave. An empty or nil input
// produces a ClearPassword with no enclave backing and a nil error —
// TPM2 interprets that as "no UserAuth required", which is intentional
// and distinct from an allocation failure. The input slice is copied
// into the enclave; the caller's slice is NOT wiped by this
// constructor.
//
// The enclave allocation for a non-empty password is delegated to
// pkg/password, the canonical enclave-backed Password implementation,
// so this store never carries its own copy of that logic. A non-empty
// password whose enclave cannot be allocated returns an error instead
// of silently downgrading to an empty (passwordless) UserAuth.
func NewPassword(password []byte) (types.Password, error) {
	if len(password) == 0 {
		return &ClearPassword{}, nil
	}
	pw, err := pwenclave.NewPassword(password)
	if err != nil {
		return nil, err
	}
	return pw, nil
}

// WithBytes lends the enclaved password bytes to fn. An empty or cleared
// password calls fn with a nil slice: TPM2 reads an empty UserAuth as no
// authentication.
func (p *ClearPassword) WithBytes(fn func([]byte) error) error {
	if p == nil || p.buf == nil {
		return fn(nil)
	}
	return p.buf.WithBytes(fn)
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
	out, err := secure.CopyOut(p.buf)
	if err != nil {
		return nil
	}
	return out
}

// String returns types.PasswordRedacted. It never returns the password: a
// Go string can never be wiped, so the secret is only reachable through
// Bytes.
func (p *ClearPassword) String() string {
	return types.PasswordRedacted
}

// Clear destroys the underlying enclave. Safe to call on a zero-value
// receiver and idempotent — Buffer.Destroy itself is idempotent.
// After Clear, Bytes returns nil.
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

// WithBytes returns ErrPasswordRequired without calling fn: the password
// was required but never stored, and the caller must not proceed as if it
// were empty.
func (p *RequiredPassword) WithBytes(func([]byte) error) error {
	return ErrPasswordRequired
}

// String returns types.PasswordRedacted; there is no secret to reveal.
func (p *RequiredPassword) String() string {
	return types.PasswordRedacted
}

// Clear is a no-op for RequiredPassword as there is no sensitive data to clear
func (p *RequiredPassword) Clear() {
	_ = p // No-op: RequiredPassword holds no sensitive data
}
