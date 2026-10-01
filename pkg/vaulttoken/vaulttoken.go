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

// Package vaulttoken is the client side of a password-vault key factor:
// finding the token that holds the factor's private key -- a PIV card's
// key-management slot (9d), a certificate's key on a PKCS#11 token, in a TPM
// or in software, a TPM key under a named policy -- through the xkms key
// backends the client already runs, and building the credentials that enroll
// it and unlock with it. xkmsctl, the xkey CLI, the xkey GUI and xkey's
// browser-extension bridge all call this one package.
//
// The token never gives up its private key and the client never sees the
// vault's DEK: it recovers the factor's secret from the server's challenge
// (pkg/vaultkey) and sends only that.
package vaulttoken

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/vaultkey"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Factor types of the key factors.
const (
	FactorPIV         = "piv"
	FactorCertificate = "certificate"
	FactorTPM         = "tpm"
)

// PIVSlot is the PIV slot a PIV factor's key is in: key management, the
// slot PIV defines for key establishment.
const PIVSlot = pivcert.PIVSlotKeyManagement

// Errors.
var (
	// ErrUnknownFactor is returned for a factor type that is not a key
	// factor.
	ErrUnknownFactor = errors.New("vaulttoken: not a key factor: use piv, certificate or tpm")

	// ErrKeyRequired is returned when a certificate or TPM factor names no
	// key.
	ErrKeyRequired = errors.New("vaulttoken: name the key (its ID in the backend)")

	// ErrCertificateRequired is returned when a certificate factor's key has
	// no certificate in its backend.
	ErrCertificateRequired = errors.New("vaulttoken: the key has no certificate")

	// ErrCertificateMismatch is returned when a certificate is not the
	// token key's.
	ErrCertificateMismatch = errors.New("vaulttoken: the certificate is not for this key")

	// ErrNoKeyFactor is returned when the vault has no key factor.
	ErrNoKeyFactor = errors.New("vaulttoken: the vault has no PIV, certificate or TPM factor")

	// ErrTokenNotFound is returned when none of the vault's key factors has
	// its token here: the card is not inserted, the key is not in this
	// machine's backends, or the backend is not configured.
	ErrTokenNotFound = errors.New("vaulttoken: none of the vault's key factors has its token here")
)

// Lookup returns a configured xkms key backend by name (xkms.GetBackend).
type Lookup func(name string) (xkms.Backend, error)

// Key is a resolved token: the token itself and, for a certificate (or a
// PIV slot with one), its certificate.
type Key struct {
	Token       vaultkey.Token
	Certificate *x509.Certificate
	Ref         transport.PasswordVaultKeyRef
}

// Resolve finds factor's key in backend ref.Backend: a PIV factor's key is
// the slot 9d key, a certificate or TPM factor's the key ref.KeyID names.
// A certificate factor also needs the key's certificate in the backend.
func Resolve(ctx context.Context, lookup Lookup, factor string, ref transport.PasswordVaultKeyRef) (*Key, error) {
	if factor != FactorPIV && factor != FactorCertificate && factor != FactorTPM {
		return nil, ErrUnknownFactor
	}
	if factor == FactorPIV && ref.KeyID == "" {
		ref.KeyID = xkms.PivSlotCN(PIVSlot)
	}
	if ref.KeyID == "" {
		return nil, ErrKeyRequired
	}
	b, err := lookup(ref.Backend)
	if err != nil {
		return nil, &BackendError{Backend: ref.Backend, Err: err}
	}
	attrs := keyAttributes(ctx, b, factor, ref)
	tok, err := vaultkey.NewBackendToken(ctx, b.KeyProvider(), attrs)
	if err != nil {
		return nil, &KeyError{Ref: ref, Err: err}
	}
	key := &Key{Token: tok, Ref: ref}
	cert, certErr := b.GetCert(ctx, ref.KeyID)
	switch {
	case certErr == nil && cert != nil:
		if !samePublicKey(tok.Public(), cert.PublicKey) {
			return nil, ErrCertificateMismatch
		}
		key.Certificate = cert
	case factor == FactorCertificate:
		return nil, ErrCertificateRequired
	}
	return key, nil
}

// keyAttributes returns the stored attributes of the key ref names, which
// carry the algorithm, store type and -- for a TPM key -- policy the
// backend validates against; a backend that does not enumerate the key (a
// PIV token resolving by slot) gets the key's ID and slot.
func keyAttributes(ctx context.Context, b xkms.Backend, factor string, ref transport.PasswordVaultKeyRef) *types.KeyAttributes {
	if stored, err := b.ListKeys(ctx); err == nil {
		for _, attrs := range stored {
			if attrs != nil && attrs.CN == ref.KeyID {
				return attrs
			}
		}
	}
	attrs := &types.KeyAttributes{CN: ref.KeyID, StoreType: b.Type(), KeyType: types.KeyTypeEncryption, TPMPolicy: ref.TPMPolicy}
	if factor == FactorPIV {
		attrs.PIVSlot = string(PIVSlot)
	}
	return attrs
}

// EnrollCredential is the credential that enrolls key as a factor: its
// certificate when it has one, else its public key, with where it lives.
func EnrollCredential(factor string, key *Key, label string) (transport.PasswordVaultCredential, error) {
	cred := transport.PasswordVaultCredential{Factor: factor, Label: label, KeyRef: key.Ref}
	if key.Certificate != nil {
		cred.Certificate = key.Certificate.Raw
		return cred, nil
	}
	der, err := x509.MarshalPKIXPublicKey(key.Token.Public())
	if err != nil {
		return transport.PasswordVaultCredential{}, &KeyError{Ref: key.Ref, Err: err}
	}
	cred.PublicKey = der
	return cred, nil
}

// SelfTest proves, before anything is enrolled, that tok can recover a
// secret sealed to its own key: it seals a throwaway secret exactly as the
// server will and opens it. A token that cannot perform the key's algorithm
// -- a PKCS#11 module without RSA-OAEP-256, a TPM key without the decrypt
// attribute -- fails here instead of after the user relies on the factor.
func SelfTest(ctx context.Context, tok vaultkey.Token) error {
	sealed, err := vaultkey.Seal(tok.Public())
	if err != nil {
		return err
	}
	defer clear(sealed.Secret)
	fingerprint, err := vaultkey.Fingerprint(tok.Public())
	if err != nil {
		return err
	}
	secret, err := vaultkey.Open(ctx, tok, vaultkey.Factor{Fingerprint: fingerprint, Algorithm: sealed.Algorithm, Challenge: sealed.Challenge, Check: sealed.Check})
	clear(secret)
	if err != nil {
		return &SelfTestError{Err: err}
	}
	return nil
}

// Verify proves a freshly enrolled factor opens with tok: the client runs
// it on the enrollment response, so a token that cannot recover the secret
// is found before the user relies on it.
func Verify(ctx context.Context, tok vaultkey.Token, f transport.PasswordVaultFactor) error {
	secret, err := vaultkey.Open(ctx, tok, factorOf(f))
	clear(secret)
	return err
}

// UnlockCredential recovers the secret of the vault factor that tok holds
// the key of, and returns the credential that unlocks with it. The caller
// zeroes the Secret once sent.
func UnlockCredential(ctx context.Context, tok vaultkey.Token, factors []transport.PasswordVaultFactor) (transport.PasswordVaultCredential, error) {
	fingerprint, err := vaultkey.Fingerprint(tok.Public())
	if err != nil {
		return transport.PasswordVaultCredential{}, err
	}
	keyFactors := 0
	for _, f := range factors {
		if !IsKeyFactor(f.Factor) {
			continue
		}
		keyFactors++
		if f.KeyFingerprint != fingerprint {
			continue
		}
		secret, err := vaultkey.Open(ctx, tok, factorOf(f))
		if err != nil {
			return transport.PasswordVaultCredential{}, err
		}
		return transport.PasswordVaultCredential{Factor: f.Factor, KeyFingerprint: f.KeyFingerprint, Secret: secret}, nil
	}
	if keyFactors == 0 {
		return transport.PasswordVaultCredential{}, ErrNoKeyFactor
	}
	return transport.PasswordVaultCredential{}, vaultkey.ErrWrongKey
}

// Find resolves, in order, the token of each key factor of the vault whose
// key this client holds, and returns the unlock credential of the first.
// It answers ErrNoKeyFactor for a vault without key factors and
// ErrTokenNotFound when no factor's token is here.
func Find(ctx context.Context, lookup Lookup, factors []transport.PasswordVaultFactor) (transport.PasswordVaultCredential, error) {
	tried := false
	for _, f := range factors {
		if !IsKeyFactor(f.Factor) {
			continue
		}
		tried = true
		key, err := Resolve(ctx, lookup, f.Factor, f.KeyRef)
		if err != nil {
			continue // this factor's token is not here
		}
		if fp, err := vaultkey.Fingerprint(key.Token.Public()); err != nil || fp != f.KeyFingerprint {
			continue
		}
		return UnlockCredential(ctx, key.Token, []transport.PasswordVaultFactor{f})
	}
	if !tried {
		return transport.PasswordVaultCredential{}, ErrNoKeyFactor
	}
	return transport.PasswordVaultCredential{}, ErrTokenNotFound
}

// IsKeyFactor reports whether factor is a key factor type.
func IsKeyFactor(factor string) bool {
	return factor == FactorPIV || factor == FactorCertificate || factor == FactorTPM
}

// samePublicKey reports whether a and b are one key, by fingerprint.
func samePublicKey(a, b crypto.PublicKey) bool {
	fa, errA := vaultkey.Fingerprint(a)
	fb, errB := vaultkey.Fingerprint(b)
	return errA == nil && errB == nil && fa == fb
}

func factorOf(f transport.PasswordVaultFactor) vaultkey.Factor {
	return vaultkey.Factor{Fingerprint: f.KeyFingerprint, Algorithm: f.KeyAlgorithm, Challenge: f.KeyChallenge, Check: f.KeyCheck}
}

// SelfTestError reports a token that cannot recover a secret sealed to its
// own key.
type SelfTestError struct {
	Err error
}

// Error implements the error interface.
func (e *SelfTestError) Error() string {
	return "vaulttoken: the token cannot open a secret sealed to its key: " + e.Err.Error()
}

// Unwrap returns the token's failure.
func (e *SelfTestError) Unwrap() error { return e.Err }

// BackendError reports a key factor whose backend is not configured here.
type BackendError struct {
	Backend string
	Err     error
}

// Error implements the error interface.
func (e *BackendError) Error() string {
	return "vaulttoken: backend " + e.Backend + ": " + e.Err.Error()
}

// Unwrap returns the lookup failure.
func (e *BackendError) Unwrap() error { return e.Err }

// KeyError reports a key the backend cannot provide as a token: missing, or
// not a key a factor can use.
type KeyError struct {
	Ref transport.PasswordVaultKeyRef
	Err error
}

// Error implements the error interface.
func (e *KeyError) Error() string {
	return "vaulttoken: key " + e.Ref.KeyID + " in " + e.Ref.Backend + ": " + e.Err.Error()
}

// Unwrap returns the backend's failure.
func (e *KeyError) Unwrap() error { return e.Err }
