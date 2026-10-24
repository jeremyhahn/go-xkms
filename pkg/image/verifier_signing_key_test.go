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

package image

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errTestSigningKeys = errors.New("test: signing keys unavailable")

// repositoryKeys resolves a repository's signing key from a map, with a
// default for repositories the map does not name.
type repositoryKeys struct {
	byRepository map[string]crypto.PublicKey
	fallback     crypto.PublicKey
	err          error
	asked        []string
}

func (k *repositoryKeys) SigningKey(_ context.Context, repository string) (crypto.PublicKey, error) {
	k.asked = append(k.asked, repository)
	if k.err != nil {
		return nil, k.err
	}
	if key, ok := k.byRepository[repository]; ok {
		return key, nil
	}
	return k.fallback, nil
}

func TestVerifier_VerifyImage_SigningKey(t *testing.T) {
	f := newSignerFixture(t, registryConfig{referrers: true})
	reference, err := ParseReference(f.ref)
	require.NoError(t, err)
	signerKey, otherKey := newECDSAKey(t), newECDSAKey(t)
	_, err = f.signer(t, signerKey, nil).SignImage(t.Context(), f.ref, nil)
	require.NoError(t, err)

	t.Run("the repository's key verifies", func(t *testing.T) {
		keys := &repositoryKeys{fallback: signerKey.Public()}
		result, err := f.verifier(t, VerifierConfig[purpose]{SigningKeys: keys}).VerifyImage(t.Context(), f.ref)
		require.NoError(t, err)
		assert.Equal(t, f.digest, result.Digest)
		assert.Equal(t, []string{reference.Repository}, keys.asked)
	})
	t.Run("another key is refused", func(t *testing.T) {
		// The signing certificate chains to the trusted root, so only the
		// key check refuses it.
		keys := &repositoryKeys{fallback: otherKey.Public()}
		result, err := f.verifier(t, VerifierConfig[purpose]{SigningKeys: keys}).VerifyImage(t.Context(), f.ref)
		require.ErrorIs(t, err, ErrNoValidAttestation)
		require.ErrorIs(t, err, ErrSigningKeyMismatch)
		assert.Nil(t, result)
	})
	t.Run("a key bound to another repository does not apply", func(t *testing.T) {
		keys := &repositoryKeys{
			byRepository: map[string]crypto.PublicKey{"other/app": signerKey.Public()},
			fallback:     otherKey.Public(),
		}
		_, err := f.verifier(t, VerifierConfig[purpose]{SigningKeys: keys}).VerifyImage(t.Context(), f.ref)
		require.ErrorIs(t, err, ErrSigningKeyMismatch)
	})
}

func TestVerifier_VerifyImage_SigningKeyErrors(t *testing.T) {
	f := newSignerFixture(t, registryConfig{referrers: true})
	signerKey := newECDSAKey(t)
	_, err := f.signer(t, signerKey, nil).SignImage(t.Context(), f.ref, nil)
	require.NoError(t, err)

	t.Run("resolver fails", func(t *testing.T) {
		keys := &repositoryKeys{err: errTestSigningKeys}
		_, err := f.verifier(t, VerifierConfig[purpose]{SigningKeys: keys}).VerifyImage(t.Context(), f.ref)
		require.ErrorIs(t, err, errTestSigningKeys)
	})
	t.Run("key of another type", func(t *testing.T) {
		keys := &repositoryKeys{fallback: struct{}{}}
		_, err := f.verifier(t, VerifierConfig[purpose]{SigningKeys: keys}).VerifyImage(t.Context(), f.ref)
		require.ErrorIs(t, err, ErrSigningKeyMismatch)
	})
	t.Run("roots still apply", func(t *testing.T) {
		keys := &repositoryKeys{fallback: signerKey.Public()}
		_, err := f.verifier(t, VerifierConfig[purpose]{SigningKeys: keys, Roots: newTestPKI(t).roots()}).VerifyImage(t.Context(), f.ref)
		require.ErrorIs(t, err, ErrUntrustedSigner)
	})
}
