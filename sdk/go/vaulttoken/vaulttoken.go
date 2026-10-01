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

// Package vaulttoken re-exports go-xkms pkg/vaulttoken and the token side of
// pkg/vaultkey: the client side of a password-vault key factor (a PIV slot
// 9d key, a certificate's key or a TPM key, held in an xkms key backend).
// See pkg/vaulttoken for the flow and pkg/vaultkey for the wire format.
package vaulttoken

import (
	"github.com/jeremyhahn/go-xkms/pkg/vaultkey"
	pkg "github.com/jeremyhahn/go-xkms/pkg/vaulttoken"
)

// Key factor types and the PIV factor's slot.
const (
	FactorPIV         = pkg.FactorPIV
	FactorCertificate = pkg.FactorCertificate
	FactorTPM         = pkg.FactorTPM
	PIVSlot           = pkg.PIVSlot
)

type (
	// Lookup returns a configured xkms key backend by name.
	Lookup = pkg.Lookup
	// Key is a resolved token and its certificate.
	Key = pkg.Key
	// Token is the private half of a key factor.
	Token = vaultkey.Token
	// BackendError reports a backend not configured here.
	BackendError = pkg.BackendError
	// KeyError reports a key the backend cannot provide.
	KeyError = pkg.KeyError
)

var (
	// Resolve finds a key factor's token in the client's backends.
	Resolve = pkg.Resolve
	// EnrollCredential is the credential that enrolls a token.
	EnrollCredential = pkg.EnrollCredential
	// Verify proves a fresh enrollment opens with the token.
	Verify = pkg.Verify
	// UnlockCredential recovers the secret of the factor a token holds.
	UnlockCredential = pkg.UnlockCredential
	// Find resolves the token of the first vault key factor held here.
	Find = pkg.Find
	// IsKeyFactor reports whether a factor type is a key factor.
	IsKeyFactor = pkg.IsKeyFactor
	// NewKeyToken is the token of an in-memory (software, PEM file) key.
	NewKeyToken = vaultkey.NewKeyToken
	// NewBackendToken is the token of a key in an xkms key provider.
	NewBackendToken = vaultkey.NewBackendToken
	// Fingerprint is a public key's SPKI SHA-256, the factor selector.
	Fingerprint = vaultkey.Fingerprint
)

var (
	ErrUnknownFactor       = pkg.ErrUnknownFactor
	ErrKeyRequired         = pkg.ErrKeyRequired
	ErrCertificateRequired = pkg.ErrCertificateRequired
	ErrCertificateMismatch = pkg.ErrCertificateMismatch
	ErrNoKeyFactor         = pkg.ErrNoKeyFactor
	ErrTokenNotFound       = pkg.ErrTokenNotFound
	ErrWrongKey            = vaultkey.ErrWrongKey
	ErrUnsupportedKey      = vaultkey.ErrUnsupportedKey
)

// SelfTest proves a token can open a secret sealed to its own key.
var SelfTest = pkg.SelfTest

// SelfTestError reports a token that failed SelfTest.
type SelfTestError = pkg.SelfTestError
