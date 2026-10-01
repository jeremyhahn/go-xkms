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

// Package vaultpasskey is the client side of a password-vault passkey: it
// drives a FIDO2 authenticator's hmac-secret extension to enroll a passkey
// factor and to produce the credential that unlocks the vault. Every
// non-browser client -- xkmsctl, the xkey CLI and the xkey GUI -- calls this
// one package, so a passkey enrolled on any surface unlocks on every other.
//
// # Salt handling
//
// The vault stores, per passkey factor, a random 32-byte PRF salt: the
// application-level salt of the WebAuthn prf extension. The authenticator is
// never asked to evaluate that salt directly. Exactly as a browser does for
// prf, the client sends the hmac-secret salt
//
//	SHA-256(UTF8("WebAuthn PRF") || 0x00 || prfSalt)        (fido2.WebAuthnPRFSalt)
//
// and the 32-byte hmac-secret output is the factor's secret. A browser
// evaluating prf with eval.first = prfSalt for the same credential therefore
// yields the same secret.
//
// # User verification
//
// CTAP 2.1 keys the hmac-secret output with one per-credential secret when
// the user was verified and another when not, so enrollment and every unlock
// must verify the same way. A vault passkey is always user-verified: the
// authenticator's client PIN is required for enrollment and for unlock
// (ErrPINRequired), and a browser must evaluate with userVerification
// "required". A key without a PIN must have one set before it can hold a
// vault passkey.
package vaultpasskey

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Relying party of every vault passkey. The RP ID scopes the credential on
// the authenticator: a credential is evaluated only for the RP ID it was
// created for, so every client must use this one.
const (
	RelyingPartyID   = "xkms-password-vault"
	RelyingPartyName = "xkms password vault"
)

// prfSaltLength is the length of the application-level PRF salt.
const prfSaltLength = 32

// Factor is the vault's name for a passkey factor.
const Factor = "passkey"

// Errors.
var (
	// ErrPINRequired is returned when no authenticator PIN is supplied: a
	// vault passkey is always user-verified (see the package doc).
	ErrPINRequired = errors.New("vaultpasskey: the authenticator PIN is required for a vault passkey")

	// ErrNoPasskeyEnrolled is returned by Unlock when the vault has no
	// passkey factor.
	ErrNoPasskeyEnrolled = errors.New("vaultpasskey: the vault has no passkey factor")

	// ErrNoMatchingPasskey is returned by Unlock when none of the vault's
	// passkeys is on this authenticator.
	ErrNoMatchingPasskey = errors.New("vaultpasskey: none of the vault's passkeys is on this authenticator")

	// ErrUnexpectedOutput is returned when the authenticator answers with an
	// hmac-secret output that is not 32 bytes.
	ErrUnexpectedOutput = errors.New("vaultpasskey: the authenticator returned no 32-byte hmac-secret output")
)

// Authenticator is the FIDO2 platform a vault passkey runs on.
// *fido2.FIDO2Handler satisfies it.
type Authenticator interface {
	EnrollKey(config *fido2.EnrollmentConfig) (*fido2.EnrollmentResult, error)
	DeriveHMACSecret(config *fido2.AuthenticationConfig) (*fido2.AuthenticationResult, error)
}

// Options configures an enrollment or an unlock.
type Options struct {
	// PIN is the authenticator's client PIN. Required.
	PIN *secure.Secret

	// UserName names the credential's user on the authenticator (enrollment
	// only); "" uses "xkms".
	UserName string

	// Label names the vault factor (enrollment only).
	Label string
}

// Enroll creates a vault passkey on a: a new hmac-secret credential for
// RelyingPartyID, a fresh PRF salt, and the credential's hmac-secret output
// over the transformed salt. The result is the credential to send to
// PasswordVaultEnroll (or PasswordVaultRecover). The caller zeroes its
// Secret once sent.
func Enroll(a Authenticator, opts Options) (transport.PasswordVaultCredential, error) {
	if opts.PIN == nil {
		return transport.PasswordVaultCredential{}, ErrPINRequired
	}
	userName := opts.UserName
	if userName == "" {
		userName = "xkms"
	}
	cfg := fido2.DefaultEnrollmentConfig(userName)
	cfg.RelyingParty = fido2.RelyingParty{ID: RelyingPartyID, Name: RelyingPartyName}
	cfg.PIN = opts.PIN
	enrolled, err := a.EnrollKey(cfg)
	if err != nil {
		return transport.PasswordVaultCredential{}, err
	}

	prfSalt := make([]byte, prfSaltLength)
	if _, err := rand.Read(prfSalt); err != nil {
		return transport.PasswordVaultCredential{}, &RandomError{Err: err}
	}
	secret, err := evaluate(a, enrolled.CredentialID, prfSalt, opts.PIN)
	if err != nil {
		return transport.PasswordVaultCredential{}, err
	}
	return transport.PasswordVaultCredential{
		Factor:       Factor,
		CredentialID: enrolled.CredentialID,
		PRFSalt:      prfSalt,
		Secret:       secret,
		Label:        opts.Label,
	}, nil
}

// Unlock evaluates the vault's passkey factors on a, in order, and returns
// the unlock credential of the first one this authenticator holds. factors
// is the vault status's factor list. The caller zeroes the Secret once sent.
func Unlock(a Authenticator, factors []transport.PasswordVaultFactor, opts Options) (transport.PasswordVaultCredential, error) {
	if opts.PIN == nil {
		return transport.PasswordVaultCredential{}, ErrPINRequired
	}
	tried := false
	for _, f := range factors {
		if f.Factor != Factor || len(f.CredentialID) == 0 || len(f.PRFSalt) == 0 {
			continue
		}
		tried = true
		secret, err := evaluate(a, f.CredentialID, f.PRFSalt, opts.PIN)
		if errors.Is(err, fido2.ErrCredentialNotFound) {
			continue // another authenticator's passkey
		}
		if err != nil {
			return transport.PasswordVaultCredential{}, err
		}
		return transport.PasswordVaultCredential{
			Factor:       Factor,
			CredentialID: bytes.Clone(f.CredentialID),
			Secret:       secret,
		}, nil
	}
	if !tried {
		return transport.PasswordVaultCredential{}, ErrNoPasskeyEnrolled
	}
	return transport.PasswordVaultCredential{}, ErrNoMatchingPasskey
}

// evaluate returns credentialID's hmac-secret output over the WebAuthn prf
// transform of prfSalt, user-verified with pin.
func evaluate(a Authenticator, credentialID, prfSalt []byte, pin *secure.Secret) ([]byte, error) {
	result, err := a.DeriveHMACSecret(&fido2.AuthenticationConfig{
		RelyingPartyID: RelyingPartyID,
		CredentialID:   credentialID,
		Salt:           fido2.WebAuthnPRFSalt(prfSalt),
		PIN:            pin,
		Timeout:        fido2.DefaultUserPresenceTimeout,
	})
	if err != nil {
		return nil, err
	}
	if len(result.HMACSecret) != prfSaltLength {
		clear(result.HMACSecret)
		return nil, ErrUnexpectedOutput
	}
	return result.HMACSecret, nil
}

// RandomError wraps a failure of the system random source.
type RandomError struct {
	Err error
}

// Error implements the error interface.
func (e *RandomError) Error() string { return "vaultpasskey: random source: " + e.Err.Error() }

// Unwrap returns the underlying failure.
func (e *RandomError) Unwrap() error { return e.Err }
