// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package pkcs11strategy builds a PKCS#11 barrier seal strategy from a bare
// library, token label and PIN: it logs in to the token, provisions the
// wrapping key the strategy seals the root key under, and returns the
// strategy. xkmsd's node seal and, through sdk/go, xkey's barrier both build
// their PKCS#11 strategy here.
//
// It is a package of its own because pkg/backend/pkcs11 imports pkg/seal;
// pkg/seal importing it back would be a cycle. Without the pkcs11 build tag
// Build fails closed with ErrNotCompiledIn.
package pkcs11strategy

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var (
	// ErrNotCompiledIn is returned by Build in a binary built without the
	// pkcs11 tag.
	ErrNotCompiledIn = errors.New("pkcs11strategy: PKCS#11 support is not compiled in (build with -tags pkcs11)")

	// ErrLibraryRequired is returned when Params names no PKCS#11 library.
	ErrLibraryRequired = errors.New("pkcs11strategy: a PKCS#11 library is required")

	// ErrTokenRequired is returned when Params names no token label.
	ErrTokenRequired = errors.New("pkcs11strategy: a token label is required")

	// ErrPINRequired is returned when Params carries no token PIN.
	ErrPINRequired = errors.New("pkcs11strategy: a token PIN is required")
)

// BuildError is returned when the token cannot be opened, logged in to, or
// given its wrapping key.
type BuildError struct {
	// Step names the step that failed.
	Step string
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *BuildError) Error() string {
	return "pkcs11strategy: " + e.Step + ": " + e.Err.Error()
}

// Unwrap exposes Err.
func (e *BuildError) Unwrap() error { return e.Err }

// Params names the token a PKCS#11 seal strategy logs in to.
type Params struct {
	// CN labels the PKCS#11 backend in logs.
	CN string
	// Library is the path of the PKCS#11 module.
	Library string
	// TokenLabel selects the token.
	TokenLabel string
	// PIN is the token's user PIN. The returned strategy's backend holds it
	// for its session's life.
	PIN *types.SecretValue
}

// validate reports the first required parameter that is missing.
func (p Params) validate() error {
	switch {
	case p.Library == "":
		return ErrLibraryRequired
	case p.TokenLabel == "":
		return ErrTokenRequired
	case p.PIN == nil:
		return ErrPINRequired
	default:
		return nil
	}
}
