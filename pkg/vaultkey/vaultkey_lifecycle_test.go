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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func sealP256(t *testing.T) *Sealed {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sealed, err := Seal(&k.PublicKey)
	require.NoError(t, err)
	return sealed
}

// TestSealed_TakeSecretOnAnUnprotectableBufferIsAProtectError proves a
// protected buffer that cannot be read yields *ProtectError, never a short or
// zeroed secret, and that the failed take still consumes the buffer.
func TestSealed_TakeSecretOnAnUnprotectableBufferIsAProtectError(t *testing.T) {
	sealed := sealP256(t)
	buf := sealed.secret.Swap(nil)
	buf.Destroy() // the protected memory is gone before the take
	sealed.secret.Store(buf)

	secret, err := sealed.TakeSecret()
	var protect *ProtectError
	require.ErrorAs(t, err, &protect)
	var gone *secure.NilBufferError
	assert.ErrorAs(t, err, &gone)
	assert.Nil(t, secret)

	_, err = sealed.TakeSecret()
	var taken *SecretTakenError
	assert.ErrorAs(t, err, &taken, "the failed take consumed the buffer")
}

func TestSealed_DestroyAfterTakeAndTwice(t *testing.T) {
	sealed := sealP256(t)
	buf := sealed.secret.Load()
	secret, err := sealed.TakeSecret()
	require.NoError(t, err)
	assert.Len(t, secret, SecretLength)

	sealed.Destroy()
	sealed.Destroy()
	assert.Zero(t, buf.Size())
	_, err = sealed.TakeSecret()
	var taken *SecretTakenError
	assert.ErrorAs(t, err, &taken)
	assert.Equal(t, sealed.Check, Check(secret), "destroying after a take leaves the taken secret intact")
}

// TestSealed_ConcurrentTakesHaveExactlyOneWinner proves racing takers never
// share or split the secret: one gets all of it, the rest are refused.
func TestSealed_ConcurrentTakesHaveExactlyOneWinner(t *testing.T) {
	for round := 0; round < 20; round++ {
		sealed := sealP256(t)
		const takers = 16
		var (
			wg      sync.WaitGroup
			winners atomic.Int32
			refused atomic.Int32
			start   = make(chan struct{})
		)
		for i := 0; i < takers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				secret, err := sealed.TakeSecret()
				var taken *SecretTakenError
				switch {
				case err == nil:
					winners.Add(1)
					assert.Equal(t, sealed.Check, Check(secret), "the winner holds the whole secret")
				case errors.As(err, &taken):
					refused.Add(1)
				default:
					assert.NoError(t, err)
				}
			}()
		}
		close(start)
		wg.Wait()
		assert.EqualValues(t, 1, winners.Load())
		assert.EqualValues(t, takers-1, refused.Load())
	}
}

// TestSealed_TakeRacesDestroy proves a take racing a destroy either returns
// the complete secret or is refused; it never returns a wiped or partial one.
func TestSealed_TakeRacesDestroy(t *testing.T) {
	var took, destroyed int
	for round := 0; round < 200; round++ {
		sealed := sealP256(t)
		buf := sealed.secret.Load()
		var (
			wg     sync.WaitGroup
			secret []byte
			err    error
			start  = make(chan struct{})
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			secret, err = sealed.TakeSecret()
		}()
		go func() {
			defer wg.Done()
			<-start
			sealed.Destroy()
		}()
		close(start)
		wg.Wait()

		if err == nil {
			took++
			require.Len(t, secret, SecretLength)
			assert.Equal(t, sealed.Check, Check(secret), "a secret that was returned is the whole secret")
		} else {
			destroyed++
			var taken *SecretTakenError
			assert.ErrorAs(t, err, &taken)
			assert.Nil(t, secret)
		}
		assert.Zero(t, buf.Size(), "whoever won, the protected copy is gone")
	}
	t.Logf("take won %d, destroy won %d", took, destroyed)
}

func TestSealed_ZeroValueEveryMethod(t *testing.T) {
	var sealed Sealed
	assert.NotPanics(t, sealed.Destroy)
	secret, err := sealed.TakeSecret()
	var taken *SecretTakenError
	assert.ErrorAs(t, err, &taken)
	assert.Nil(t, secret)
	assert.Empty(t, sealed.Algorithm)
	assert.Nil(t, sealed.Challenge)
	assert.Nil(t, sealed.Check)
}

func TestSeal_FailsClosedOnBadKeys(t *testing.T) {
	_, err := Seal(nil)
	assert.ErrorIs(t, err, ErrUnsupportedKey)
	_, err = Seal(struct{}{})
	assert.ErrorIs(t, err, ErrUnsupportedKey)

	// A point that is not on the curve cannot take part in ECDH. The raw
	// coordinates are the only way to build one.
	off := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)} //nolint:staticcheck // SA1019: an off-curve key is the shape under test
	sealed, err := Seal(off)
	assert.Error(t, err)
	assert.Nil(t, sealed)

	// An RSA key whose exponent OAEP refuses fails after the secret is drawn;
	// no Sealed, and so no secret, escapes.
	good, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	badExp := &rsa.PublicKey{N: good.N, E: 1}
	sealed, err = Seal(badExp)
	assert.Error(t, err)
	assert.Nil(t, sealed)
}

func TestSealECDH_RejectsUnsupportedCurve(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	_, _, err = sealECDH(&k.PublicKey, "fp")
	assert.ErrorIs(t, err, ErrUnsupportedKey)
}

func TestSealRSA_RefusesAnExponentOAEPRejects(t *testing.T) {
	good, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	challenge, secret, err := sealRSA(&rsa.PublicKey{N: good.N, E: 1})
	var re *RandomError
	assert.ErrorAs(t, err, &re)
	assert.Nil(t, challenge)
	assert.Nil(t, secret)
}

func TestFingerprint_RejectsUnmarshalableKey(t *testing.T) {
	_, err := Fingerprint(struct{}{})
	assert.ErrorIs(t, err, ErrInvalidPublicKey)
}

func TestParsePublicKey_RejectsUnsupportedKeyType(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	_, _, err = ParsePublicKey(der, nil)
	assert.ErrorIs(t, err, ErrUnsupportedKey)
}

func TestRandomAndDeriveErrors(t *testing.T) {
	cause := errors.New("boom")
	for _, err := range []error{&RandomError{Err: cause}, &DeriveError{Err: cause}} {
		assert.ErrorIs(t, err, cause)
		assert.Contains(t, err.Error(), "boom")
		assert.Contains(t, err.Error(), "vaultkey:")
	}
}

// stubToken is a Token whose operations are scripted.
type stubToken struct {
	pub    crypto.PublicKey
	secret []byte
	err    error
}

func (s stubToken) Public() crypto.PublicKey { return s.pub }
func (s stubToken) DecryptOAEP(context.Context, []byte) ([]byte, error) {
	return s.secret, s.err
}
func (s stubToken) DeriveKeyECDH(context.Context, []byte, *types.KDFParams) ([]byte, error) {
	return s.secret, s.err
}

func TestOpen_TokenFailuresAreReported(t *testing.T) {
	ctx := context.Background()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	fp, err := Fingerprint(&k.PublicKey)
	require.NoError(t, err)
	f := Factor{Fingerprint: fp, Algorithm: AlgorithmECDHES}

	_, err = Open(ctx, stubToken{pub: struct{}{}}, f)
	assert.ErrorIs(t, err, ErrInvalidPublicKey, "a token with no usable public key")

	cause := errors.New("card removed")
	_, err = Open(ctx, stubToken{pub: &k.PublicKey, err: cause}, f)
	assert.ErrorIs(t, err, cause)

	short := []byte{1, 2, 3}
	_, err = Open(ctx, stubToken{pub: &k.PublicKey, secret: short}, f)
	assert.ErrorIs(t, err, ErrWrongKey, "a secret of the wrong length is refused")
	assert.Equal(t, []byte{0, 0, 0}, short, "and wiped")

	rf := Factor{Fingerprint: fp, Algorithm: AlgorithmRSAOAEP256}
	_, err = Open(ctx, stubToken{pub: &k.PublicKey, err: cause}, rf)
	assert.ErrorIs(t, err, cause)
}

func TestKeyToken_Refusals(t *testing.T) {
	ctx := context.Background()
	_, err := NewKeyToken("not a key")
	assert.ErrorIs(t, err, ErrUnsupportedKey)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	_, err = NewKeyToken(small)
	assert.ErrorIs(t, err, ErrUnsupportedKey)

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ectok, err := NewKeyToken(ec)
	require.NoError(t, err)
	kdf := secretKDF("fp")

	_, err = ectok.DeriveKeyECDH(ctx, []byte("junk"), kdf)
	assert.ErrorIs(t, err, ErrInvalidPublicKey)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	_, err = ectok.DeriveKeyECDH(ctx, rsaDER, kdf)
	assert.ErrorIs(t, err, ErrInvalidPublicKey, "an RSA peer cannot take part in ECDH")

	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	otherDER, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	require.NoError(t, err)
	_, err = ectok.DeriveKeyECDH(ctx, otherDER, kdf)
	assert.ErrorIs(t, err, ErrInvalidPublicKey, "a peer on another curve cannot agree")
}

func TestBackendToken_Refusals(t *testing.T) {
	ctx := context.Background()
	kp := softwareBackend(t)

	missing := &types.KeyAttributes{CN: "absent", KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()}, KeyType: backend.KEY_TYPE_ENCRYPTION, StoreType: backend.STORE_SW}
	_, err := NewBackendToken(ctx, kp, missing)
	assert.Error(t, err)

	ecAttrs := &types.KeyAttributes{CN: "ec", KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()}, KeyType: backend.KEY_TYPE_ENCRYPTION, StoreType: backend.STORE_SW}
	_, err = kp.GenerateKey(ctx, ecAttrs)
	require.NoError(t, err)
	ectok, err := NewBackendToken(ctx, kp, ecAttrs)
	require.NoError(t, err)
	_, err = ectok.DecryptOAEP(ctx, []byte{1})
	assert.ErrorIs(t, err, ErrTokenCannotDecrypt)

	rsaAttrs := &types.KeyAttributes{CN: "rsa", KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 2048}, KeyType: backend.KEY_TYPE_ENCRYPTION, StoreType: backend.STORE_SW}
	_, err = kp.GenerateKey(ctx, rsaAttrs)
	require.NoError(t, err)
	rsatok, err := NewBackendToken(ctx, kp, rsaAttrs)
	require.NoError(t, err)
	_, err = rsatok.DeriveKeyECDH(ctx, []byte{1}, secretKDF("fp"))
	assert.ErrorIs(t, err, ErrTokenCannotAgree)
}

// scriptedProvider is a KeyProvider that exposes only the key lookups the
// token's public-key discovery uses. Any other method panics on the nil
// embedded interface, which would fail the test.
type scriptedProvider struct {
	types.KeyProvider
	key       crypto.PrivateKey
	keyErr    error
	signer    crypto.Signer
	signerErr error
	dec       crypto.Decrypter
	decErr    error
}

func (p scriptedProvider) GetKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return p.key, p.keyErr
}

func (p scriptedProvider) Signer(context.Context, *types.KeyAttributes) (crypto.Signer, error) {
	return p.signer, p.signerErr
}

func (p scriptedProvider) Decrypter(context.Context, *types.KeyAttributes) (crypto.Decrypter, error) {
	return p.dec, p.decErr
}

// opaqueKey is a private key handle that does not expose its public half.
type opaqueKey struct{}

func TestBackendPublicKey_FallsBackToSignerThenDecrypter(t *testing.T) {
	ctx := context.Background()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	failed := errors.New("unsupported")

	pub, err := backendPublicKey(ctx, scriptedProvider{key: opaqueKey{}, signer: rsaKey}, nil)
	require.NoError(t, err)
	assert.True(t, rsaKey.PublicKey.Equal(pub), "the signer supplies the public key")

	pub, err = backendPublicKey(ctx, scriptedProvider{key: opaqueKey{}, signerErr: failed, dec: rsaKey}, nil)
	require.NoError(t, err)
	assert.True(t, rsaKey.PublicKey.Equal(pub), "the decrypter supplies it when there is no signer")

	_, err = backendPublicKey(ctx, scriptedProvider{key: opaqueKey{}, signerErr: failed, decErr: failed}, nil)
	assert.ErrorIs(t, err, ErrNoPublicKey)

	cause := errors.New("no such key")
	_, err = backendPublicKey(ctx, scriptedProvider{keyErr: cause}, nil)
	assert.ErrorIs(t, err, cause)
}

func TestBackendToken_DecrypterAndAgreementFailures(t *testing.T) {
	ctx := context.Background()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cause := errors.New("decrypter unavailable")

	tok, err := NewBackendToken(ctx, scriptedProvider{key: rsaKey, decErr: cause}, nil)
	require.NoError(t, err)
	_, err = tok.DecryptOAEP(ctx, []byte{1})
	assert.ErrorIs(t, err, cause)

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ectok, err := NewBackendToken(ctx, scriptedProvider{key: ec}, nil)
	require.NoError(t, err)
	_, err = ectok.DeriveKeyECDH(ctx, []byte{1}, secretKDF("fp"))
	assert.ErrorIs(t, err, ErrTokenCannotAgree, "a backend without key agreement")
}

func TestNewBackendToken_RefusesUnsupportedBackendKey(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = NewBackendToken(context.Background(), scriptedProvider{key: edKey}, nil)
	assert.ErrorIs(t, err, ErrUnsupportedKey)
}
