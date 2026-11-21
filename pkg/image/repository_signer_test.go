package image

import (
	"context"
	"crypto"
	"errors"
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
