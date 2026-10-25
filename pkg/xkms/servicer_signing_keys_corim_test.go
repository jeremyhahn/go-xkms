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

package xkms

import (
	"crypto"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
)

const corimSignPermission = "attestation_signing_keys:sign"

// signCoRIMRequest is a valid request for repository acme/app.
func signCoRIMRequest(t *testing.T) *appraisal.SignCoRIMRequest {
	t.Helper()
	unsigned, err := appraisaltest.UnsignedCoRIM(map[uint32][]byte{0: make([]byte, 32)})
	require.NoError(t, err)
	return &appraisal.SignCoRIMRequest{Repository: "acme/app", CoRIM: unsigned, SignerName: "Acme Release Engineering"}
}

// verifyCoRIM checks a signed CoRIM verifies under pub.
func verifyCoRIM(t *testing.T, signed []byte, pub crypto.PublicKey) *refvalue.Manifest {
	t.Helper()
	m, err := refvalue.VerifySigned(signed, refvalue.VerifyOptions{PublicKey: pub})
	require.NoError(t, err)
	return m
}

func TestSignCoRIM_ReleaseKeyByDefault(t *testing.T) {
	svc := setupDeriveService(t)
	release := generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	ctx := withSigningKeys(t, svc, corimSignPermission)

	req := signCoRIMRequest(t)
	req.NotAfter = time.Now().Add(time.Hour)
	resp, err := svc.SignCoRIM(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, appraisal.SigningKeyResolution{Repository: "acme/app", KeyID: appraisal.ReleaseSigningKeyID, Default: true}, resp.Key)
	m := verifyCoRIM(t, resp.CoRIM, release)
	assert.Equal(t, "Acme Release Engineering", m.Signer)
}

func TestSignCoRIM_BoundKeySigns(t *testing.T) {
	svc := setupDeriveService(t)
	release := generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	bound := generateSigningKey(t, svc, "tenant-a", "app-release")
	ctx := withSigningKeys(t, svc, corimSignPermission, "attestation_signing_keys:bind")
	_, err := svc.SetSigningKeyBinding(ctx, &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-release"})
	require.NoError(t, err)

	resp, err := svc.SignCoRIM(ctx, signCoRIMRequest(t))
	require.NoError(t, err)
	assert.Equal(t, "app-release", resp.Key.KeyID)
	assert.False(t, resp.Key.Default)
	verifyCoRIM(t, resp.CoRIM, bound)
	_, err = refvalue.VerifySigned(resp.CoRIM, refvalue.VerifyOptions{PublicKey: release})
	require.ErrorIs(t, err, refvalue.ErrSignature, "the release key did not sign a bound repository's CoRIM")
}

func TestSignCoRIM_NeverSignsWithAnotherTenantsKey(t *testing.T) {
	svc := setupDeriveService(t)
	other := generateSigningKey(t, svc, "tenant-b", appraisal.ReleaseSigningKeyID)
	ctx := withSigningKeys(t, svc, corimSignPermission)

	resp, err := svc.SignCoRIM(ctx, signCoRIMRequest(t))
	require.NoError(t, err, "tenant-a's first signature provisions its own release key")
	_, err = refvalue.VerifySigned(resp.CoRIM, refvalue.VerifyOptions{PublicKey: other})
	require.Error(t, err, "tenant-b's key never signs for tenant-a")
	verifyCoRIM(t, resp.CoRIM, releasePublicKey(t, svc, "tenant-a"))
	assert.True(t, other.(*ecdsa.PublicKey).Equal(releasePublicKey(t, svc, "tenant-b")), "tenant-b's key is untouched")
}

func TestSignCoRIM_Errors(t *testing.T) {
	svc := setupDeriveService(t)
	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	ctx := withSigningKeys(t, svc, corimSignPermission)

	_, err := svc.SignCoRIM(ctx, nil)
	require.ErrorIs(t, err, appraisal.ErrNilRequest)

	req := signCoRIMRequest(t)
	req.Repository = "Not A Repository"
	_, err = svc.SignCoRIM(ctx, req)
	require.ErrorIs(t, err, appraisal.ErrInvalidRepository)

	for name, tc := range map[string]struct {
		mutate func(*appraisal.SignCoRIMRequest)
		want   error
	}{
		"malformed corim":   {func(r *appraisal.SignCoRIMRequest) { r.CoRIM = []byte{0xff} }, refvalue.ErrMalformed},
		"empty signer name": {func(r *appraisal.SignCoRIMRequest) { r.SignerName = "" }, refvalue.ErrMeta},
	} {
		req := signCoRIMRequest(t)
		tc.mutate(req)
		_, err := svc.SignCoRIM(ctx, req)
		require.ErrorIs(t, err, tc.want, name)
		var signErr *CoRIMSignError
		require.ErrorAs(t, err, &signErr, name)
		assert.Equal(t, appraisal.ReleaseSigningKeyID, signErr.KeyID, name)
		assert.Contains(t, signErr.Error(), "acme/app", name)
	}
}

func TestSignCoRIM_RefusedWithoutSignPermission(t *testing.T) {
	svc := setupDeriveService(t)
	generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	ctx := withSigningKeys(t, svc, "attestation_signing_keys:get")

	_, err := svc.SignCoRIM(ctx, signCoRIMRequest(t))
	require.ErrorIs(t, err, ErrSigningKeyForbidden)
	var refusal *SigningKeyPermissionError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, corimSignPermission, refusal.Permission)
}

func TestSignCoRIM_NotConfigured(t *testing.T) {
	svc := setupDeriveService(t)
	_, err := svc.SignCoRIM(t.Context(), signCoRIMRequest(t))
	require.ErrorIs(t, err, ErrNotConfigured)
}
