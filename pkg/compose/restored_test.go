// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package compose

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/hostdeps"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuild_EveryDependencyComposesEveryFeature proves every dependency a host
// can supply enables its feature, and that Wire publishes each store into the
// Service.
func TestBuild_EveryDependencyComposesEveryFeature(t *testing.T) {
	svc := hostdeps.NewService(t)
	st, err := Build(context.Background(), fullDeps(t, svc))
	require.NoError(t, err)
	require.Len(t, st.Disabled, 1, "only the TPM policy service may be off: no TPM2 backend is supplied")
	var disabled *FeatureDisabledError
	require.ErrorAs(t, st.Disabled[0], &disabled)
	assert.Equal(t, FeatureTPMPolicies, disabled.Feature)

	assert.NotNil(t, st.PasswordStore)
	assert.NotNil(t, st.PasswordManager)
	assert.NotNil(t, st.PIN)
	assert.NotNil(t, st.PlatformStore)
	assert.NotNil(t, st.Credentials)
	assert.NotNil(t, st.SSH)
	assert.NotNil(t, st.CA)
	assert.Nil(t, st.TPMPolicies)
	assert.NotNil(t, st.KeyVersions)
	assert.NotNil(t, st.Invite)
	assert.NotNil(t, st.OIDCCredentials)
	assert.Equal(t, "barrier", st.Credentials.Strategy())
	t.Cleanup(func() { require.NoError(t, st.Close()) })

	st.Wire(svc)
	ctx := platformCtx()

	// The OIDC credential service is wired over the host's barriers.
	_, err = svc.OIDCCredentialCreate(ctx, &transport.OIDCCredentialCreateRequest{
		OIDCCredentialRef: transport.OIDCCredentialRef{Scope: "tenant", Name: "claude"},
		Config:            transport.OIDCCredentialConfig{Template: "anthropic"},
		Tokens:            &transport.OIDCCredentialTokens{AccessToken: "sk-ant-oat01-x"},
	})
	require.NoError(t, err)
	tok, err := svc.OIDCCredentialGetAccessToken(ctx, &transport.OIDCCredentialRef{Scope: "tenant", Name: "claude"})
	require.NoError(t, err)
	assert.Equal(t, "sk-ant-oat01-x", tok.AccessToken)

	require.NoError(t, svc.SealStorePut(ctx, &transport.SealStorePutRequest{Name: "k", Secret: []byte("v")}))
	got, err := svc.SealStoreGet(ctx, &transport.SealStoreGetRequest{Name: "k"})
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got.Secret)

	caCert, err := svc.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
	require.NoError(t, err)
	assert.Contains(t, caCert.Subject, "Compose Test Root")

	_, err = svc.PasswordStoreStatus(ctx)
	require.NoError(t, err)

	// The key-version store is wired: a key rotates into version 2.
	_, err = svc.GenerateKey(ctx, &transport.GenerateKeyRequest{Backend: hostdeps.BackendName, KeyID: "composed", Algorithm: "ecdsa"})
	require.NoError(t, err)
	rotated, err := svc.RotateKey(ctx, &transport.RotateKeyRequest{Backend: hostdeps.BackendName, KeyID: "composed"})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), rotated.KeyVersion)
}

// TestBuild_NoDependenciesLeavesEveryFeatureOffWithTypedReasons proves a
// missing dependency never fails composition and is never silent: each
// feature is off with a *FeatureDisabledError naming what was missing.
func TestBuild_NoDependenciesLeavesEveryFeatureOffWithTypedReasons(t *testing.T) {
	svc := hostdeps.NewService(t)
	st, err := Build(context.Background(), Deps{Service: svc, CredentialStrategy: "barrier"})
	require.NoError(t, err)

	missing := map[Feature]string{}
	for _, reason := range st.Disabled {
		var disabled *FeatureDisabledError
		require.ErrorAs(t, reason, &disabled, "every reason must be typed: %v", reason)
		if _, seen := missing[disabled.Feature]; !seen {
			missing[disabled.Feature] = disabled.Missing
		}
	}
	assert.Equal(t, map[Feature]string{
		FeaturePasswords:       "DAO factory",
		FeaturePIN:             "PIN backend",
		FeaturePlatformStore:   "storage",
		FeatureCredentials:     "barrier registry",
		FeatureSSH:             "DAO factory",
		FeatureCA:              "CA configuration",
		FeatureTPMPolicies:     "TPM2 backend",
		FeatureKeyVersions:     "DAO factory",
		FeatureOIDCCredentials: "barrier registry",
		FeatureInvite:          "storage",
	}, missing)

	assert.Nil(t, st.PasswordStore)
	assert.Nil(t, st.PlatformStore)
	assert.Nil(t, st.Credentials)
	assert.Nil(t, st.SSH)
	assert.Nil(t, st.CA)
	assert.Nil(t, st.TPMPolicies)
	assert.Nil(t, st.KeyVersions)
	assert.Nil(t, st.Invite)

	// Wiring an empty composition leaves the service answering "not
	// configured" for each feature.
	st.Wire(svc)
	_, err = svc.SealStoreStatus(platformCtx())
	assert.ErrorIs(t, err, xkms.ErrNotConfigured)
	_, err = svc.TPMPolicyList(platformCtx(), &transport.TPMPolicyListRequest{})
	assert.ErrorIs(t, err, xkms.ErrNotConfigured)
	_, err = svc.RotateScopeKeys(platformCtx(), &transport.RotateScopeKeysRequest{})
	assert.ErrorIs(t, err, xkms.ErrNotConfigured, "rotation needs the key-version store")
	assert.NoError(t, st.Close(), "closing stores without a TPM policy service is a no-op")
}
