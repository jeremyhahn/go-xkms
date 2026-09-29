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

package importtoken

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// SealedRSAKey holds an ephemeral RSA wrapping keypair the way an
// ImportBackend generates one in GetImportParameters and needs to keep
// until UnwrapKey consumes it, possibly hours later: the private half
// sealed inside a *secure.Secret so it does not sit in the process heap in
// the clear for its entire validity window, the public half kept as a
// plain pointer because it is not sensitive and callers need cheap
// repeated access to populate ImportParameters.WrappingPublicKey.
//
// This is the same seal/open/parse/destroy handling go-xkms's software
// backend has always applied to its own wrapping keys, factored out so
// every ImportBackend that generates one uses one implementation.
type SealedRSAKey struct {
	privateKey *secure.Secret
	publicKey  *rsa.PublicKey
}

// NewSealedRSAKey marshals priv to PKCS#8 DER and seals it. The DER is
// wiped once sealed; NewSecret already wipes its input, so the explicit
// wipe here is defense in depth, not the only protection.
func NewSealedRSAKey(priv *rsa.PrivateKey) (*SealedRSAKey, error) {
	if priv == nil {
		return nil, &errs.Message{Msg: "wrapping private key cannot be nil"}
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal wrapping key", Err: err}
	}
	sealed, err := secure.NewSecret(der)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to seal wrapping key", Err: err}
	}
	secure.Wipe(der)

	return &SealedRSAKey{
		privateKey: sealed,
		publicKey:  &priv.PublicKey,
	}, nil
}

// NewSealedRSAKeyFromSecret wraps an already-sealed secret as a
// SealedRSAKey, without marshaling a live *rsa.PrivateKey first. Most
// callers want NewSealedRSAKey; this constructor exists for tests that
// need to inject a specific sealed payload -- including one that is
// corrupt or decodes to a non-RSA key -- to exercise Use's error paths.
func NewSealedRSAKeyFromSecret(sealed *secure.Secret, pub *rsa.PublicKey) *SealedRSAKey {
	return &SealedRSAKey{privateKey: sealed, publicKey: pub}
}

// PublicKey returns the wrapping public key. It is safe to call after
// Destroy: the public half is never sealed.
func (k *SealedRSAKey) PublicKey() *rsa.PublicKey {
	if k == nil {
		return nil
	}
	return k.publicKey
}

// Use opens the enclave, parses the PKCS#8 DER into an ephemeral
// *rsa.PrivateKey, and calls fn with it. The parsed key and the Buffer
// that held its DER are destroyed before Use returns, win or lose, so the
// plaintext private key never outlives this call's stack frame -- the
// same guarantee the software backend's UnwrapKey has always given its
// callers, now available to every backend through one code path.
func (k *SealedRSAKey) Use(fn func(*rsa.PrivateKey) error) error {
	if k == nil || k.privateKey == nil {
		return &UnavailableError{}
	}

	buf, err := k.privateKey.Open()
	if err != nil {
		return &UnavailableError{Err: err}
	}
	defer buf.Destroy()

	parsed, err := x509.ParsePKCS8PrivateKey(buf.Bytes())
	if err != nil {
		return &errs.Wrapped{Msg: "failed to parse wrapping key", Err: err}
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return &NotRSAKeyError{}
	}

	return fn(rsaKey)
}

// Destroy wipes the enclave holding the wrapping private key. Safe to call
// on a nil receiver or more than once.
func (k *SealedRSAKey) Destroy() {
	if k == nil || k.privateKey == nil {
		return
	}
	k.privateKey.Destroy()
	k.privateKey = nil
	k.publicKey = nil
}
