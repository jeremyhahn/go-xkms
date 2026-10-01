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

package vaultkey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ErrNoPublicKey is returned when a backend key exposes no public key.
var ErrNoPublicKey = errors.New("vaultkey: the token's key exposes no public key")

// backendToken is a key held by an xkms key backend: a PIV slot's key, a
// PKCS#11 token's, a TPM's or the software backend's. Decryption goes
// through the backend's crypto.Decrypter and key agreement through its
// types.KeyAgreementProvider, so the private key never leaves the backend.
type backendToken struct {
	kp    types.KeyProvider
	attrs *types.KeyAttributes
	pub   crypto.PublicKey
}

// NewBackendToken returns the token for the key attrs names on kp.
func NewBackendToken(ctx context.Context, kp types.KeyProvider, attrs *types.KeyAttributes) (Token, error) {
	pub, err := backendPublicKey(ctx, kp, attrs)
	if err != nil {
		return nil, err
	}
	if _, err := algorithmFor(pub); err != nil {
		return nil, err
	}
	return &backendToken{kp: kp, attrs: attrs, pub: pub}, nil
}

// backendPublicKey reads the public half of the key attrs names.
func backendPublicKey(ctx context.Context, kp types.KeyProvider, attrs *types.KeyAttributes) (crypto.PublicKey, error) {
	type publicKeyer interface{ Public() crypto.PublicKey }
	priv, err := kp.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}
	if p, ok := priv.(publicKeyer); ok && p.Public() != nil {
		return p.Public(), nil
	}
	if signer, err := kp.Signer(ctx, attrs); err == nil && signer.Public() != nil {
		return signer.Public(), nil
	}
	if dec, err := kp.Decrypter(ctx, attrs); err == nil && dec.Public() != nil {
		return dec.Public(), nil
	}
	return nil, ErrNoPublicKey
}

func (t *backendToken) Public() crypto.PublicKey { return t.pub }

func (t *backendToken) DecryptOAEP(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if _, ok := t.pub.(*rsa.PublicKey); !ok {
		return nil, ErrTokenCannotDecrypt
	}
	dec, err := t.kp.Decrypter(ctx, t.attrs)
	if err != nil {
		return nil, err
	}
	return dec.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256})
}

func (t *backendToken) DeriveKeyECDH(ctx context.Context, peerPublicKey []byte, kdf *types.KDFParams) ([]byte, error) {
	if _, ok := t.pub.(*ecdsa.PublicKey); !ok {
		return nil, ErrTokenCannotAgree
	}
	agreer, ok := t.kp.(types.KeyAgreementProvider)
	if !ok {
		return nil, ErrTokenCannotAgree
	}
	return agreer.DeriveKeyECDH(ctx, t.attrs, peerPublicKey, kdf)
}

// keyToken is a private key in memory: a software key read from a file.
type keyToken struct {
	priv crypto.PrivateKey
	pub  crypto.PublicKey
}

// NewKeyToken returns the token for an in-memory RSA or EC private key.
func NewKeyToken(priv crypto.PrivateKey) (Token, error) {
	var pub crypto.PublicKey
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	default:
		return nil, ErrUnsupportedKey
	}
	if _, err := algorithmFor(pub); err != nil {
		return nil, err
	}
	return &keyToken{priv: priv, pub: pub}, nil
}

func (t *keyToken) Public() crypto.PublicKey { return t.pub }

func (t *keyToken) DecryptOAEP(_ context.Context, ciphertext []byte) ([]byte, error) {
	k, ok := t.priv.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrTokenCannotDecrypt
	}
	return rsa.DecryptOAEP(crypto.SHA256.New(), nil, k, ciphertext, nil)
}

func (t *keyToken) DeriveKeyECDH(_ context.Context, peerPublicKey []byte, kdf *types.KDFParams) ([]byte, error) {
	k, ok := t.priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrTokenCannotAgree
	}
	peer, err := x509.ParsePKIXPublicKey(peerPublicKey)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	peerEC, ok := peer.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrInvalidPublicKey
	}
	priv, err := k.ECDH()
	if err != nil {
		return nil, ErrUnsupportedKey
	}
	pub, err := peerEC.ECDH()
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	z, err := priv.ECDH(pub)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	defer clear(z)
	return kdf.Derive(z)
}
