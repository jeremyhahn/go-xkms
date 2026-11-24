package image

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRepositorySigners hands out one signer per repository, like a
// tenant's signing-key service over its release key and bindings.
type fakeRepositorySigners struct {
	signers map[string]crypto.Signer
	err     error
	asked   []string
}

func (f *fakeRepositorySigners) RepositorySigner(_ context.Context, repository string) (crypto.Signer, error) {
	f.asked = append(f.asked, repository)
	if f.err != nil {
		return nil, f.err
	}
	return f.signers[repository], nil
}

func TestNewRepositorySigner_DefaultsToTheRepositoryKey(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	release := newECDSAKey(t)
	source := &fakeRepositorySigners{signers: map[string]crypto.Signer{"acme/app": release}}

	signer, err := NewRepositorySigner(t.Context(), source, "acme/app", &SignerConfig{
		Certificate: f.pki.codeSigning(t, release.Public()),
		Registry:    f.client,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/app"}, source.asked)
	assert.Same(t, release, signer.signer, "the repository's resolved key signs")
}

func TestNewRepositorySigner_CallerSignerWins(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	own := newECDSAKey(t)
	source := &fakeRepositorySigners{signers: map[string]crypto.Signer{"acme/app": newECDSAKey(t)}}
	cfg := &SignerConfig{Signer: own, Certificate: f.pki.codeSigning(t, own.Public()), Registry: f.client}

	signer, err := NewRepositorySigner(t.Context(), source, "acme/app", cfg)
	require.NoError(t, err)
	assert.Empty(t, source.asked, "a signer the caller set is never replaced")
	assert.Same(t, own, signer.signer)
}

func TestNewRepositorySigner_Refusals(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	key := newECDSAKey(t)
	cfg := &SignerConfig{Certificate: f.pki.codeSigning(t, key.Public()), Registry: f.client}

	_, err := NewRepositorySigner(t.Context(), nil, "acme/app", cfg)
	require.ErrorIs(t, err, ErrSignerRequired, "no source and no signer")

	_, err = NewRepositorySigner(t.Context(), &fakeRepositorySigners{}, "acme/app", nil)
	require.ErrorIs(t, err, ErrSignerRequired, "nil config")

	_, err = NewRepositorySigner(t.Context(), &fakeRepositorySigners{}, "", cfg)
	require.ErrorIs(t, err, ErrRepositoryRequired)

	denied := errors.New("denied")
	_, err = NewRepositorySigner(t.Context(), &fakeRepositorySigners{err: denied}, "acme/app", cfg)
	require.ErrorIs(t, err, denied, "the source's error is returned")

	_, err = NewRepositorySigner(t.Context(), &fakeRepositorySigners{}, "acme/app", cfg)
	require.ErrorIs(t, err, ErrSignerRequired, "a source that names no signer")

	other := &fakeRepositorySigners{signers: map[string]crypto.Signer{"acme/app": newECDSAKey(t)}}
	_, err = NewRepositorySigner(t.Context(), other, "acme/app", cfg)
	require.ErrorIs(t, err, ErrKeyMismatch, "the certificate must certify the resolved key")
	assert.Nil(t, cfg.Signer, "the caller's config is not modified")
}

// strictCurveSigner mirrors Azure Key Vault, which signs a P-384 key only
// as ES384 over a SHA-384 digest (and likewise per curve for P-256/P-521).
type strictCurveSigner struct {
	key  *ecdsa.PrivateKey
	seen crypto.Hash
}

func (s *strictCurveSigner) Public() crypto.PublicKey { return s.key.Public() }

func (s *strictCurveSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.seen = opts.HashFunc()
	want := map[elliptic.Curve]crypto.Hash{
		elliptic.P256(): crypto.SHA256,
		elliptic.P384(): crypto.SHA384,
		elliptic.P521(): crypto.SHA512,
	}[s.key.Curve]
	if opts.HashFunc() != want || len(digest) != want.Size() {
		return nil, fmt.Errorf("strict %s signer: refuses %v over a %d-byte digest", s.key.Curve.Params().Name, opts.HashFunc(), len(digest))
	}
	return s.key.Sign(random, digest, opts)
}

func TestNewRepositorySigner_SignsImagesWithAStrictP384Key(t *testing.T) {
	tests := map[string]struct {
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		"P-256": {curve: elliptic.P256(), hash: crypto.SHA256},
		"P-384": {curve: elliptic.P384(), hash: crypto.SHA384},
		"P-521": {curve: elliptic.P521(), hash: crypto.SHA512},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := newSignerFixture(t, registryConfig{referrers: true})
			key, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)
			strict := &strictCurveSigner{key: key}
			source := &fakeRepositorySigners{signers: map[string]crypto.Signer{"team/app": strict}}

			signer, err := NewRepositorySigner(t.Context(), source, "team/app", &SignerConfig{
				Certificate: f.pki.codeSigning(t, strict.Public()),
				Chain:       []*x509.Certificate{f.pki.certificate},
				Registry:    f.client,
			})
			require.NoError(t, err)
			_, err = signer.SignImage(t.Context(), f.ref, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.hash, strict.seen, "the DSSE digest follows the curve")

			verified, err := f.verifier(t, VerifierConfig[purpose]{}).VerifyImage(t.Context(), f.ref)
			require.NoError(t, err)
			assert.Equal(t, f.digest, verified.Digest)
		})
	}
}
