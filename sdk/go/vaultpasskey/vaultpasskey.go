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

// Package vaultpasskey re-exports go-xkms pkg/vaultpasskey: the client side
// of a password-vault passkey (enroll and unlock through a FIDO2
// authenticator's hmac-secret, with the WebAuthn prf salt transform). See
// pkg/vaultpasskey for the salt and user-verification rules.
package vaultpasskey

import pkg "github.com/jeremyhahn/go-xkms/pkg/vaultpasskey"

// RelyingPartyName names a vault passkey's relying party; its ID is the
// server's (the vault status's PasskeyRPID).
const (
	RelyingPartyName = pkg.RelyingPartyName
	Factor           = pkg.Factor
)

type (
	// Authenticator is the FIDO2 platform; *fido2.FIDO2Handler satisfies it.
	Authenticator = pkg.Authenticator
	// Options configures an enrollment or an unlock.
	Options = pkg.Options
	// RandomError wraps a random-source failure.
	RandomError = pkg.RandomError
)

var (
	// Enroll creates a vault passkey and returns its enrollment credential.
	Enroll = pkg.Enroll
	// Unlock returns the unlock credential of the first vault passkey on
	// the authenticator.
	Unlock = pkg.Unlock
)

var (
	ErrPINRequired       = pkg.ErrPINRequired
	ErrNoRelyingParty    = pkg.ErrNoRelyingParty
	ErrNoPasskeyEnrolled = pkg.ErrNoPasskeyEnrolled
	ErrNoMatchingPasskey = pkg.ErrNoMatchingPasskey
	ErrUnexpectedOutput  = pkg.ErrUnexpectedOutput
)
