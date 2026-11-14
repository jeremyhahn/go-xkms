package xkms

import (
	"context"
	"crypto"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func samePublicKey(t *testing.T, want crypto.PublicKey, signer crypto.Signer) bool {
	t.Helper()
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	require.True(t, ok, "the signer's public key has no Equal")
	return pub.Equal(want)
}

func TestRepositorySigner_ReleaseKeyUnlessTheTenantNamedAnother(t *testing.T) {
	svc, appraiser, ctx := releaseSigningService(t, "attestation_signing_keys:sign")
	release := generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	app := generateSigningKey(t, svc, "tenant-a", "app-release")

	signer, err := svc.RepositorySigner(ctx, "acme/app")
	require.NoError(t, err)
	assert.True(t, samePublicKey(t, release, signer), "an unbound repository signs with the release key")

	_, err = appraiser.SetSigningKeyBinding(ctx, "tenant-a", &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-release", Backend: "software"})
	require.NoError(t, err)
	signer, err = svc.RepositorySigner(ctx, "acme/app")
	require.NoError(t, err)
	assert.True(t, samePublicKey(t, app, signer), "a bound repository signs with its named key")

	signer, err = svc.RepositorySigner(ctx, "acme/other")
	require.NoError(t, err)
	assert.True(t, samePublicKey(t, release, signer), "the binding is per repository")
}

func TestRepositorySigner_Refusals(t *testing.T) {
	svc, _, ctx := releaseSigningService(t, "attestation_signing_keys:get")
	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	_, err := svc.RepositorySigner(ctx, "acme/app")
	require.ErrorIs(t, err, ErrSigningKeyForbidden, "signing needs the sign permission")

	svc, _, ctx = releaseSigningService(t, "attestation_signing_keys:sign")
	generateSigningKey(t, svc, "tenant-b", appraisal.ReleaseSigningKeyID)
	_, err = svc.RepositorySigner(ctx, "acme/app")
	require.ErrorIs(t, err, ErrKeyNotFound, "never another tenant's key")

	_, err = (&XKMSService{}).RepositorySigner(context.Background(), "acme/app")
	require.Error(t, err, "no appraiser configured")
}
