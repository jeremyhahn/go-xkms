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

// Package vaultkey is the wire format of a password-vault key factor: a
// factor whose secret only the holder of a private key can recover. The key
// is a PIV slot's, a certificate's or a TPM key's, held on a smart card, a
// PKCS#11 token, a TPM or in software.
//
// The server never holds the private key and never keeps the factor
// secret. At enrollment it draws a fresh 32-byte secret by sealing to the
// key's public half (Seal), wraps the vault's DEK under a key derived from
// that secret, and keeps only the sealed form (the challenge). To unlock, a
// client recovers the secret with the private key (Open) and sends it; the
// server unwraps the DEK with it. The DEK itself never leaves the server.
//
// Two algorithms, chosen by the key type:
//
//   - ECDH-ES+HKDF-SHA256 (EC keys, P-256/P-384/P-521). The server makes an
//     ephemeral key pair on the key's curve and sends its public half as the
//     challenge; the secret is HKDF-SHA256(Z, no salt, info, 32), Z the
//     ECDH shared secret (the x-coordinate, NIST SP 800-56A), and info binds
//     the algorithm and the key's fingerprint. The derivation is
//     types.KDFParams.Derive, the one every xkms backend's DeriveKeyECDH
//     applies, so a PIV card, a PKCS#11 token, a TPM and a software key all
//     reproduce it.
//   - RSA-OAEP-256 (RSA keys, 2048 bits or more). The secret is random and
//     the challenge is its RSA-OAEP encryption (SHA-256, MGF1-SHA-256, no
//     label).
//
// Check is a key-check value: an HMAC of the secret a client compares before
// it unlocks, so a wrong token is reported as such instead of as a rejected
// credential. It reveals nothing about a 256-bit secret.
package vaultkey

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Algorithms a key factor's challenge is sealed with.
const (
	// AlgorithmECDHES is ephemeral-static ECDH with an HKDF-SHA256 KDF.
	AlgorithmECDHES = "ECDH-ES+HKDF-SHA256"

	// AlgorithmRSAOAEP256 is RSA-OAEP with SHA-256 and MGF1-SHA-256.
	AlgorithmRSAOAEP256 = "RSA-OAEP-256"
)

// SecretLength is the length of a factor secret.
const SecretLength = 32

// MinRSABits is the smallest RSA modulus a key factor accepts.
const MinRSABits = 2048

const (
	secretInfoPrefix = "xkms/staticpw/vault/v1/key-secret|"
	checkInfo        = "xkms/staticpw/vault/v1/key-check"
)

// Errors.
var (
	// ErrUnsupportedKey is returned for a key that is neither RSA of at
	// least MinRSABits nor EC on P-256, P-384 or P-521.
	ErrUnsupportedKey = errors.New("vaultkey: unsupported key: need RSA (2048 bits or more) or EC P-256/P-384/P-521")

	// ErrInvalidPublicKey is returned when a public key or certificate does
	// not parse.
	ErrInvalidPublicKey = errors.New("vaultkey: invalid public key or certificate")

	// ErrUnknownAlgorithm is returned for a challenge sealed with an
	// algorithm this package does not know.
	ErrUnknownAlgorithm = errors.New("vaultkey: unknown challenge algorithm")

	// ErrWrongKey is returned when a token's key is not the factor's key:
	// its fingerprint differs, or the secret it recovers fails the factor's
	// key-check value.
	ErrWrongKey = errors.New("vaultkey: this token's key is not the factor's key")

	// ErrTokenCannotAgree is returned when an EC factor's token offers no
	// key agreement.
	ErrTokenCannotAgree = errors.New("vaultkey: the token cannot perform ECDH key agreement")

	// ErrTokenCannotDecrypt is returned when an RSA factor's token offers no
	// decryption.
	ErrTokenCannotDecrypt = errors.New("vaultkey: the token cannot decrypt")
)

// Sealed is a freshly sealed factor secret. The server keeps Algorithm,
// Challenge and Check on the factor and discards the secret once it has
// wrapped the DEK with it.
//
// The secret lives in protected memory until it is taken: TakeSecret hands
// it over exactly once and destroys the protected copy, and Destroy discards
// it unread. Every Sealed must end in one of the two.
type Sealed struct {
	Algorithm string
	Challenge []byte
	Check     []byte

	secret atomic.Pointer[secure.Buffer]
}

// TakeSecret returns the factor secret and destroys the protected copy. It
// succeeds once: the caller owns the returned slice and must wipe it after
// use, and every later call returns *SecretTakenError.
func (s *Sealed) TakeSecret() ([]byte, error) {
	buf := s.secret.Swap(nil)
	if buf == nil {
		return nil, &SecretTakenError{}
	}
	defer buf.Destroy()
	secret, err := secure.CopyOut(buf)
	if err != nil {
		return nil, &ProtectError{Err: err}
	}
	return secret, nil
}

// Destroy discards the factor secret unread. It is safe to call after
// TakeSecret and more than once.
func (s *Sealed) Destroy() {
	if buf := s.secret.Swap(nil); buf != nil {
		buf.Destroy()
	}
}

// ParsePublicKey returns the public key of a factor from its PKIX DER
// public key or its DER certificate (the certificate wins when both are
// given), and the certificate when one was given. The key must be one
// Seal supports.
func ParsePublicKey(publicKeyDER, certificateDER []byte) (crypto.PublicKey, *x509.Certificate, error) {
	var (
		pub  crypto.PublicKey
		cert *x509.Certificate
		err  error
	)
	switch {
	case len(certificateDER) > 0:
		cert, err = x509.ParseCertificate(certificateDER)
		if err != nil {
			return nil, nil, ErrInvalidPublicKey
		}
		pub = cert.PublicKey
	case len(publicKeyDER) > 0:
		pub, err = x509.ParsePKIXPublicKey(publicKeyDER)
		if err != nil {
			return nil, nil, ErrInvalidPublicKey
		}
	default:
		return nil, nil, ErrInvalidPublicKey
	}
	if _, err := algorithmFor(pub); err != nil {
		return nil, nil, err
	}
	return pub, cert, nil
}

// Fingerprint returns the hex SHA-256 of pub's PKIX DER encoding: the
// identifier that selects a key factor and its token.
func Fingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", ErrInvalidPublicKey
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// Seal draws a fresh factor secret only pub's private key can recover. The
// caller takes the secret with TakeSecret, or discards it with Destroy.
func Seal(pub crypto.PublicKey) (*Sealed, error) {
	alg, err := algorithmFor(pub)
	if err != nil {
		return nil, err
	}
	fingerprint, err := Fingerprint(pub)
	if err != nil {
		return nil, err
	}
	var challenge, secret []byte
	switch alg {
	case AlgorithmECDHES:
		challenge, secret, err = sealECDH(pub.(*ecdsa.PublicKey), fingerprint)
	default:
		challenge, secret, err = sealRSA(pub.(*rsa.PublicKey))
	}
	if err != nil {
		return nil, err
	}
	check := Check(secret)
	// NewBufferFromBytes moves secret into protected memory and wipes it on
	// every path, so no ordinary-memory copy outlives this call.
	buf, err := secure.NewBufferFromBytes(secret)
	if err != nil {
		return nil, &ProtectError{Err: err}
	}
	sealed := &Sealed{Algorithm: alg, Challenge: challenge, Check: check}
	sealed.secret.Store(buf)
	return sealed, nil
}

// Check returns the key-check value of secret.
func Check(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(checkInfo))
	return mac.Sum(nil)
}

// Token is the private half of a key factor, on whatever holds it.
// BackendToken adapts any xkms key backend; KeyToken a private key in
// memory.
type Token interface {
	// Public returns the token's public key.
	Public() crypto.PublicKey

	// DecryptOAEP decrypts an RSA-OAEP-256 ciphertext. A token whose key
	// is not RSA returns ErrTokenCannotDecrypt.
	DecryptOAEP(ctx context.Context, ciphertext []byte) ([]byte, error)

	// DeriveKeyECDH performs ECDH with peerPublicKey (PKIX DER) and applies
	// kdf, exactly as types.KeyAgreementProvider.DeriveKeyECDH. A token
	// whose key is not EC returns ErrTokenCannotAgree.
	DeriveKeyECDH(ctx context.Context, peerPublicKey []byte, kdf *types.KDFParams) ([]byte, error)
}

// Factor is what a client needs from a key factor's description to recover
// its secret.
type Factor struct {
	Fingerprint string
	Algorithm   string
	Challenge   []byte
	Check       []byte
}

// Open recovers f's secret with tok. It returns ErrWrongKey when tok holds
// another key: a different fingerprint, or a secret that fails f's check.
// The caller zeroes the secret once sent.
func Open(ctx context.Context, tok Token, f Factor) ([]byte, error) {
	fingerprint, err := Fingerprint(tok.Public())
	if err != nil {
		return nil, err
	}
	if fingerprint != f.Fingerprint {
		return nil, ErrWrongKey
	}
	var secret []byte
	switch f.Algorithm {
	case AlgorithmECDHES:
		secret, err = tok.DeriveKeyECDH(ctx, f.Challenge, secretKDF(fingerprint))
	case AlgorithmRSAOAEP256:
		secret, err = tok.DecryptOAEP(ctx, f.Challenge)
	default:
		return nil, ErrUnknownAlgorithm
	}
	if err != nil {
		return nil, err
	}
	if len(secret) != SecretLength || (len(f.Check) > 0 && subtle.ConstantTimeCompare(Check(secret), f.Check) != 1) {
		clear(secret)
		return nil, ErrWrongKey
	}
	return secret, nil
}

// algorithmFor returns the algorithm a factor over pub is sealed with.
func algorithmFor(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSABits {
			return "", ErrUnsupportedKey
		}
		return AlgorithmRSAOAEP256, nil
	case *ecdsa.PublicKey:
		if _, err := ecdhCurve(k.Curve); err != nil {
			return "", err
		}
		return AlgorithmECDHES, nil
	default:
		return "", ErrUnsupportedKey
	}
}

func ecdhCurve(c elliptic.Curve) (ecdh.Curve, error) {
	switch c {
	case elliptic.P256():
		return ecdh.P256(), nil
	case elliptic.P384():
		return ecdh.P384(), nil
	case elliptic.P521():
		return ecdh.P521(), nil
	default:
		return nil, ErrUnsupportedKey
	}
}

// secretKDF is the KDF that turns an ECDH shared secret into a factor
// secret: the parameters every party passes to types.KDFParams.Derive.
func secretKDF(fingerprint string) *types.KDFParams {
	return &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Info:      []byte(secretInfoPrefix + AlgorithmECDHES + "|" + fingerprint),
		KeyLength: SecretLength,
	}
}

func sealECDH(pub *ecdsa.PublicKey, fingerprint string) (challenge, secret []byte, err error) {
	curve, err := ecdhCurve(pub.Curve)
	if err != nil {
		return nil, nil, err
	}
	static, err := pub.ECDH()
	if err != nil {
		return nil, nil, ErrInvalidPublicKey
	}
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, &RandomError{Err: err}
	}
	z, err := ephemeral.ECDH(static)
	if err != nil {
		return nil, nil, ErrInvalidPublicKey
	}
	defer clear(z)
	secret, err = secretKDF(fingerprint).Derive(z)
	if err != nil {
		return nil, nil, &DeriveError{Err: err}
	}
	challenge, err = x509.MarshalPKIXPublicKey(ephemeral.PublicKey())
	if err != nil {
		clear(secret)
		return nil, nil, &DeriveError{Err: err}
	}
	return challenge, secret, nil
}

func sealRSA(pub *rsa.PublicKey) (challenge, secret []byte, err error) {
	secret = make([]byte, SecretLength)
	if _, err := rand.Read(secret); err != nil {
		clear(secret)
		return nil, nil, &RandomError{Err: err}
	}
	challenge, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, secret, nil)
	if err != nil {
		clear(secret)
		return nil, nil, &RandomError{Err: err}
	}
	return challenge, secret, nil
}

// RandomError wraps a failure of the system random source or of RSA
// encryption with it.
type RandomError struct {
	Err error
}

// Error implements the error interface.
func (e *RandomError) Error() string { return "vaultkey: seal: " + e.Err.Error() }

// Unwrap returns the underlying failure.
func (e *RandomError) Unwrap() error { return e.Err }

// DeriveError wraps a failure deriving or encoding a sealed secret.
type DeriveError struct {
	Err error
}

// Error implements the error interface.
func (e *DeriveError) Error() string { return "vaultkey: derive: " + e.Err.Error() }

// Unwrap returns the underlying failure.
func (e *DeriveError) Unwrap() error { return e.Err }

// SecretTakenError is returned by TakeSecret when the secret was already
// taken or destroyed.
type SecretTakenError struct{}

// Error implements the error interface.
func (e *SecretTakenError) Error() string { return "vaultkey: the sealed secret was already taken" }

// ProtectError wraps a failure moving a sealed secret into, or out of,
// protected memory.
type ProtectError struct {
	Err error
}

// Error implements the error interface.
func (e *ProtectError) Error() string { return "vaultkey: protect secret: " + e.Err.Error() }

// Unwrap returns the underlying failure.
func (e *ProtectError) Unwrap() error { return e.Err }
