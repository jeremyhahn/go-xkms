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

package appraisal

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
)

var (
	errUnknownSigningKey = errors.New("test: unknown signing key")
	errKeySourceDown     = errors.New("test: key source unavailable")
)

// keySource holds tenant public keys by "tenant/keyID", as the key service
// does by tenant key namespace.
type keySource struct {
	keys map[string]crypto.PublicKey
	err  error
}

func (s *keySource) SigningPublicKey(_ context.Context, tenant string, key *SigningKeyResolution) (crypto.PublicKey, error) {
	if s.err != nil {
		return nil, s.err
	}
	pub, ok := s.keys[tenant+"/"+key.KeyID]
	if !ok {
		return nil, errUnknownSigningKey
	}
	return pub, nil
}

// signingKeyWorld is a verifier world whose tenant holds a release key and
// one other key, "app-key".
type signingKeyWorld struct {
	*verifierWorld
	app     *Appraiser
	source  *keySource
	release *appraisaltest.Authority
	other   *appraisaltest.Authority
}

func newSigningKeyWorld(t *testing.T) *signingKeyWorld {
	t.Helper()
	w := newVerifierWorld(t)
	release, err := appraisaltest.NewAuthority("release")
	require.NoError(t, err)
	other, err := appraisaltest.NewAuthority("app")
	require.NoError(t, err)
	source := &keySource{keys: map[string]crypto.PublicKey{
		w.tenant + "/" + ReleaseSigningKeyID: release.Key.Public(),
		w.tenant + "/app-key":                other.Key.Public(),
	}}
	app, err := NewAppraiser(w.app.store, WithSigningKeySource(source))
	require.NoError(t, err)
	return &signingKeyWorld{verifierWorld: w, app: app, source: source, release: release, other: other}
}

// corimBy returns the world's PCR reference values signed by key alone.
func (w *signingKeyWorld) corimBy(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	signed, err := appraisaltest.SignCoRIM(w.pcrs, key, nil)
	require.NoError(t, err)
	return signed
}

func (w *signingKeyWorld) put(t *testing.T, repository string, key crypto.Signer) error {
	t.Helper()
	_, err := w.app.PutReferenceValues(w.ctx, w.tenant, &PutReferenceValuesRequest{
		Name: "baseline", Repository: repository, SignedCoRIM: w.corimBy(t, key),
	})
	return err
}

// requireRefused asserts a refusal of a repository's reference values by
// the key named keyID.
func requireRefused(t *testing.T, err error, repository, keyID string) {
	t.Helper()
	require.ErrorIs(t, err, ErrSigningKeyRefused)
	require.ErrorIs(t, err, ErrReferenceValuesRejected)
	var refused *SignerRefusedError
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, repository, refused.Repository)
	assert.Equal(t, keyID, refused.KeyID)
}

func TestRepositoryCoRIM_ReleaseKeyByDefault(t *testing.T) {
	w := newSigningKeyWorld(t)

	require.NoError(t, w.put(t, "acme/app", w.release.Key))
	record, err := w.app.GetReferenceValues(w.ctx, w.tenant, &GetReferenceValuesRequest{Name: "baseline"})
	require.NoError(t, err)
	assert.Equal(t, "acme/app", record.Repository)

	requireRefused(t, w.put(t, "acme/app", w.other.Key), "acme/app", ReleaseSigningKeyID)
	requireRefused(t, w.put(t, "acme/app", w.signerKey), "acme/app", ReleaseSigningKeyID)
}

// TestRepositoryCoRIM_BoundKey is the per-repository check: once acme/app is
// bound to app-key, app-key verifies it and the release key is refused,
// while acme/web keeps the release key. Removing the binding lookup from
// ResolveSigningKey makes it fail.
func TestRepositoryCoRIM_BoundKey(t *testing.T) {
	w := newSigningKeyWorld(t)
	_, err := w.app.SetSigningKeyBinding(w.ctx, w.tenant, &SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-key"})
	require.NoError(t, err)

	require.NoError(t, w.put(t, "acme/app", w.other.Key))
	requireRefused(t, w.put(t, "acme/app", w.release.Key), "acme/app", "app-key")

	require.NoError(t, w.put(t, "acme/web", w.release.Key))
	requireRefused(t, w.put(t, "acme/web", w.other.Key), "acme/web", ReleaseSigningKeyID)
}

// TestRepositoryCoRIM_RebindRevokes proves stored reference values are
// verified again under the repository's current key, so rebinding the
// repository withdraws what the old key signed.
func TestRepositoryCoRIM_RebindRevokes(t *testing.T) {
	w := newSigningKeyWorld(t)
	require.NoError(t, w.put(t, "acme/app", w.release.Key))

	pcrs, err := w.app.ReferencePCRs(w.ctx, w.tenant, "baseline", crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, []uint32{0, 4, 7}, pcrs)

	_, err = w.app.SetSigningKeyBinding(w.ctx, w.tenant, &SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-key"})
	require.NoError(t, err)
	_, err = w.app.ReferencePCRs(w.ctx, w.tenant, "baseline", crypto.SHA256)
	requireRefused(t, err, "acme/app", "app-key")
}

func TestRepositoryCoRIM_Errors(t *testing.T) {
	t.Run("invalid repository", func(t *testing.T) {
		w := newSigningKeyWorld(t)
		require.ErrorIs(t, w.put(t, "Acme/App", w.release.Key), ErrInvalidRepository)
	})
	t.Run("no key source", func(t *testing.T) {
		w := newSigningKeyWorld(t)
		_, err := w.verifierWorld.app.PutReferenceValues(w.ctx, w.tenant, &PutReferenceValuesRequest{
			Name: "baseline", Repository: "acme/app", SignedCoRIM: w.corimBy(t, w.release.Key),
		})
		var config *ConfigError
		require.ErrorAs(t, err, &config)
		assert.Equal(t, "signing key source", config.Field)
	})
	t.Run("key source fails", func(t *testing.T) {
		w := newSigningKeyWorld(t)
		w.source.err = errKeySourceDown
		require.ErrorIs(t, w.put(t, "acme/app", w.release.Key), errKeySourceDown)
	})
	t.Run("bound key unknown", func(t *testing.T) {
		w := newSigningKeyWorld(t)
		_, err := w.app.SetSigningKeyBinding(w.ctx, w.tenant, &SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "missing"})
		require.NoError(t, err)
		require.ErrorIs(t, w.put(t, "acme/app", w.release.Key), errUnknownSigningKey)
	})
	t.Run("binding store fails", func(t *testing.T) {
		w := newSigningKeyWorld(t)
		w.kv.failReads = true
		require.Error(t, w.put(t, "acme/app", w.release.Key))
	})
	t.Run("tampered CoRIM", func(t *testing.T) {
		w := newSigningKeyWorld(t)
		signed := w.corimBy(t, w.release.Key)
		signed[len(signed)-1] ^= 0xff
		_, err := w.app.PutReferenceValues(w.ctx, w.tenant, &PutReferenceValuesRequest{
			Name: "baseline", Repository: "acme/app", SignedCoRIM: signed,
		})
		requireRefused(t, err, "acme/app", ReleaseSigningKeyID)
	})
}

func TestTenantSigningKeys_SigningKey(t *testing.T) {
	w := newSigningKeyWorld(t)
	_, err := w.app.SetSigningKeyBinding(w.ctx, w.tenant, &SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-key"})
	require.NoError(t, err)
	keys := w.app.TenantSigningKeys(w.tenant)

	key, err := keys.SigningKey(w.ctx, "acme/app")
	require.NoError(t, err)
	assert.True(t, w.other.Key.PublicKey.Equal(key))

	key, err = keys.SigningKey(w.ctx, "acme/web")
	require.NoError(t, err)
	assert.True(t, w.release.Key.PublicKey.Equal(key))

	_, err = w.app.TenantSigningKeys("other").SigningKey(w.ctx, "acme/app")
	require.ErrorIs(t, err, errUnknownSigningKey, "another tenant's binding and keys are not this tenant's")
}

func TestTenantSigningKeys_Errors(t *testing.T) {
	w := newSigningKeyWorld(t)
	_, err := w.verifierWorld.app.TenantSigningKeys(w.tenant).SigningKey(w.ctx, "acme/app")
	require.ErrorIs(t, err, ErrInvalidConfig)

	_, err = w.app.TenantSigningKeys("a/b").SigningKey(w.ctx, "acme/app")
	require.ErrorIs(t, err, ErrInvalidTenant)
}

func TestSignerRefusedError(t *testing.T) {
	cause := errors.New("signature mismatch")
	err := &SignerRefusedError{Repository: "acme/app", KeyID: "app-key", Cause: cause}
	assert.Equal(t, "attestation: reference values of acme/app are not signed by key app-key: signature mismatch", err.Error())
	assert.ErrorIs(t, err, ErrSigningKeyRefused)
	assert.ErrorIs(t, err, cause)
	assert.NotErrorIs(t, err, ErrReferenceValuesRejected)
}
