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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func factorOf(t *testing.T, s *Sealed, pub crypto.PublicKey) Factor {
	t.Helper()
	fp, err := Fingerprint(pub)
	require.NoError(t, err)
	return Factor{Fingerprint: fp, Algorithm: s.Algorithm, Challenge: s.Challenge, Check: s.Check}
}

func softwareBackend(t *testing.T) types.KeyProvider {
	t.Helper()
	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = kp.Close() })
	return kp
}

// TestSealOpen_EveryKeyTypeOnTheSoftwareBackend proves the round trip
// through an xkms key backend: the server seals to the backend key's public
// half, and the backend recovers the same secret without its private key
// leaving the backend.
func TestSealOpen_EveryKeyTypeOnTheSoftwareBackend(t *testing.T) {
	ctx := context.Background()
	kp := softwareBackend(t)
	cases := map[string]*types.KeyAttributes{
		"P-256": {KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()}},
		"P-384": {KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()}},
		"P-521": {KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P521()}},
		"RSA":   {KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 2048}},
	}
	for name, attrs := range cases {
		t.Run(name, func(t *testing.T) {
			attrs.CN = "vault-" + name
			attrs.KeyType = backend.KEY_TYPE_ENCRYPTION
			attrs.StoreType = backend.STORE_SW
			_, err := kp.GenerateKey(ctx, attrs)
			require.NoError(t, err)

			tok, err := NewBackendToken(ctx, kp, attrs)
			require.NoError(t, err)
			sealed, err := Seal(tok.Public())
			require.NoError(t, err)
			secret, err := sealed.TakeSecret()
			require.NoError(t, err)
			require.Len(t, secret, SecretLength)

			got, err := Open(ctx, tok, factorOf(t, sealed, tok.Public()))
			require.NoError(t, err)
			assert.Equal(t, secret, got)
		})
	}
}

// TestSeal_FreshSecretEveryTime proves two enrollments of one key share no
// secret and no challenge.
func TestSeal_FreshSecretEveryTime(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	a, err := Seal(&k.PublicKey)
	require.NoError(t, err)
	b, err := Seal(&k.PublicKey)
	require.NoError(t, err)
	aSecret, err := a.TakeSecret()
	require.NoError(t, err)
	bSecret, err := b.TakeSecret()
	require.NoError(t, err)
	assert.NotEqual(t, aSecret, bSecret)
	assert.NotEqual(t, a.Challenge, b.Challenge)
	assert.Equal(t, AlgorithmECDHES, a.Algorithm)
}

// TestOpen_WrongKeyIsReported proves another token's key is refused before
// and after it computes: by fingerprint, and by the key-check value when a
// fingerprint is forged to match.
func TestOpen_WrongKeyIsReported(t *testing.T) {
	ctx := context.Background()
	right, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sealed, err := Seal(&right.PublicKey)
	require.NoError(t, err)
	f := factorOf(t, sealed, &right.PublicKey)

	wrongTok, err := NewKeyToken(wrong)
	require.NoError(t, err)
	_, err = Open(ctx, wrongTok, f)
	assert.ErrorIs(t, err, ErrWrongKey)

	forged := f
	forged.Fingerprint, err = Fingerprint(&wrong.PublicKey)
	require.NoError(t, err)
	_, err = Open(ctx, wrongTok, forged)
	assert.ErrorIs(t, err, ErrWrongKey, "the key-check value catches a secret from the wrong key")
}

func TestOpen_RSA(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tok, err := NewKeyToken(k)
	require.NoError(t, err)
	sealed, err := Seal(&k.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, AlgorithmRSAOAEP256, sealed.Algorithm)
	got, err := Open(context.Background(), tok, factorOf(t, sealed, &k.PublicKey))
	require.NoError(t, err)
	secret, err := sealed.TakeSecret()
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

// TestSealed_TakeSecretWipesOnUse proves the protected copy is destroyed by
// the take: the secret comes out once, is the one Check was computed from, and
// a second take is refused rather than served from anywhere.
func TestSealed_TakeSecretWipesOnUse(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sealed, err := Seal(&k.PublicKey)
	require.NoError(t, err)
	buf := sealed.secret.Load()
	require.NotNil(t, buf)

	secret, err := sealed.TakeSecret()
	require.NoError(t, err)
	assert.Len(t, secret, SecretLength)
	assert.Equal(t, sealed.Check, Check(secret))
	assert.Zero(t, buf.Size(), "the protected buffer is destroyed once taken")

	_, err = sealed.TakeSecret()
	var taken *SecretTakenError
	assert.ErrorAs(t, err, &taken)
}

// TestSealed_DestroyDiscardsUnread proves Destroy wipes a secret nobody took,
// is idempotent, and leaves TakeSecret refusing.
func TestSealed_DestroyDiscardsUnread(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sealed, err := Seal(&k.PublicKey)
	require.NoError(t, err)
	buf := sealed.secret.Load()
	require.NotNil(t, buf)

	sealed.Destroy()
	sealed.Destroy()
	assert.Zero(t, buf.Size())
	_, err = sealed.TakeSecret()
	var taken *SecretTakenError
	assert.ErrorAs(t, err, &taken)
}

// TestSealed_ZeroValueHoldsNoSecret proves a Sealed that was never sealed
// refuses to hand out a secret and tolerates Destroy.
func TestProtectError(t *testing.T) {
	cause := errors.New("no enclave")
	err := &ProtectError{Err: cause}
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "no enclave")
}

func TestSeal_UnsupportedKeys(t *testing.T) {
	_, err := Seal(&undersizedRSAKey().PublicKey)
	assert.ErrorIs(t, err, ErrUnsupportedKey)

	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	_, err = Seal(&p224.PublicKey)
	assert.ErrorIs(t, err, ErrUnsupportedKey)
}

// undersizedRSAKey returns an RSA key whose 1024-bit modulus is below
// MinRSABits. Only the modulus size matters to the refusal, so the key is
// built directly: the FIPS 140-3 module refuses to generate a key that small
// under GODEBUG=fips140=only.
func undersizedRSAKey() *rsa.PrivateKey {
	n := new(big.Int).Lsh(big.NewInt(1), 1023)
	n.Add(n, big.NewInt(1))
	return &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 65537}}
}

func TestOpen_UnknownAlgorithmAndMismatchedToken(t *testing.T) {
	ctx := context.Background()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tok, err := NewKeyToken(k)
	require.NoError(t, err)
	fp, err := Fingerprint(&k.PublicKey)
	require.NoError(t, err)

	_, err = Open(ctx, tok, Factor{Fingerprint: fp, Algorithm: "A128KW"})
	assert.ErrorIs(t, err, ErrUnknownAlgorithm)

	_, err = tok.DecryptOAEP(ctx, []byte{1})
	assert.ErrorIs(t, err, ErrTokenCannotDecrypt)
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rtok, err := NewKeyToken(r)
	require.NoError(t, err)
	_, err = rtok.DeriveKeyECDH(ctx, nil, nil)
	assert.ErrorIs(t, err, ErrTokenCannotAgree)
}

func TestParsePublicKey(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vault"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)

	pub, cert, err := ParsePublicKey(der, nil)
	require.NoError(t, err)
	assert.Nil(t, cert)
	assert.True(t, k.PublicKey.Equal(pub))

	pub, cert, err = ParsePublicKey(nil, certDER)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, "vault", cert.Subject.CommonName)
	assert.True(t, k.PublicKey.Equal(pub))

	_, _, err = ParsePublicKey(nil, nil)
	assert.ErrorIs(t, err, ErrInvalidPublicKey)
	_, _, err = ParsePublicKey([]byte("junk"), nil)
	assert.ErrorIs(t, err, ErrInvalidPublicKey)
	_, _, err = ParsePublicKey(nil, []byte("junk"))
	assert.ErrorIs(t, err, ErrInvalidPublicKey)
}
