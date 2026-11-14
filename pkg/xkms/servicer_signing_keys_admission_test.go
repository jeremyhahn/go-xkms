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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
)

// signingAdmissionCase is a key state under which SignCoRIM and SignImage
// refuse to sign, as Sign does: the key the repository resolves to is
// admitted for OpSign on the existing-key and the first-use paths.
type signingAdmissionCase struct {
	name    string
	prepare func(t *testing.T, svc *XKMSService, ctx context.Context)
	refused func(t *testing.T, err error)
}

func revokeTenantKey(t *testing.T, svc *XKMSService, keyID string) {
	t.Helper()
	_, err := svc.RevokeKey(context.Background(), &transport.RevokeKeyRequest{Backend: "software", KeyID: keyID, Reason: "compromised", TenantID: "tenant-a"})
	require.NoError(t, err)
}

func restrictTenantKey(t *testing.T, svc *XKMSService, keyID string) {
	t.Helper()
	_, err := svc.SetKeyPolicy(context.Background(), &transport.SetKeyPolicyRequest{
		Backend: "software", KeyID: keyID, TenantID: "tenant-a",
		Policy: &transport.KeyPolicy{AllowedPrincipals: []string{"build-bot"}},
	})
	require.NoError(t, err)
}

func bindRepository(t *testing.T, svc *XKMSService, ctx context.Context, keyID string) {
	t.Helper()
	generateSigningKey(t, svc, "tenant-a", keyID)
	_, err := svc.SetSigningKeyBinding(ctx, &appraisal.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: keyID})
	require.NoError(t, err)
}

func refusedWithStatus(status keypolicy.Status) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		t.Helper()
		var unavailable *keypolicy.KeyUnavailableError
		require.ErrorAs(t, err, &unavailable)
		assert.Equal(t, status, unavailable.Status)
	}
}

func refusedByPolicy(t *testing.T, err error) {
	t.Helper()
	var denied *keypolicy.PolicyDeniedError
	require.ErrorAs(t, err, &denied)
	assert.Equal(t, keypolicy.OpSign, denied.Operation)
}

func signingAdmissionCases() []signingAdmissionCase {
	return []signingAdmissionCase{
		{
			name: "revoked release key",
			prepare: func(t *testing.T, svc *XKMSService, _ context.Context) {
				generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
				revokeTenantKey(t, svc, appraisal.ReleaseSigningKeyID)
			},
			refused: refusedWithStatus(keypolicy.StatusRevoked),
		},
		{
			name: "release key policy denies the caller",
			prepare: func(t *testing.T, svc *XKMSService, _ context.Context) {
				generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
				restrictTenantKey(t, svc, appraisal.ReleaseSigningKeyID)
			},
			refused: refusedByPolicy,
		},
		{
			name: "revoked bound key",
			prepare: func(t *testing.T, svc *XKMSService, ctx context.Context) {
				bindRepository(t, svc, ctx, "app-release")
				revokeTenantKey(t, svc, "app-release")
			},
			refused: refusedWithStatus(keypolicy.StatusRevoked),
		},
		{
			name: "disabled bound key",
			prepare: func(t *testing.T, svc *XKMSService, ctx context.Context) {
				bindRepository(t, svc, ctx, "app-release")
				_, err := svc.UpdateKeyStatus(context.Background(), &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: "app-release", Status: transport.KeyStatusDisabled, TenantID: "tenant-a"})
				require.NoError(t, err)
			},
			refused: refusedWithStatus(keypolicy.StatusDisabled),
		},
		{
			name: "bound key policy denies the caller",
			prepare: func(t *testing.T, svc *XKMSService, ctx context.Context) {
				bindRepository(t, svc, ctx, "app-release")
				restrictTenantKey(t, svc, "app-release")
			},
			refused: refusedByPolicy,
		},
		{
			// The tenant holds no release key: the first signature provisions
			// it, and the policy already recorded for it is admitted before
			// the provisioned key signs.
			name: "provisioned release key policy denies the caller",
			prepare: func(t *testing.T, svc *XKMSService, _ context.Context) {
				rec := keypolicy.Implicit(appraisal.ReleaseSigningKeyID, "software")
				rec.Policy = &keypolicy.Policy{Version: 1, AllowedPrincipals: []string{"build-bot"}}
				require.NoError(t, svc.KeyPolicyStore().Put(context.Background(), "tenant-a", rec))
			},
			refused: refusedByPolicy,
		},
	}
}

func TestSignCoRIM_AdmittedThroughTheKeyPolicy(t *testing.T) {
	for _, tc := range signingAdmissionCases() {
		t.Run(tc.name, func(t *testing.T) {
			svc := admissionService(t)
			ctx := withSigningKeys(t, svc, corimSignPermission, "attestation_signing_keys:bind")
			tc.prepare(t, svc, ctx)
			_, err := svc.SignCoRIM(ctx, signCoRIMRequest(t))
			tc.refused(t, err)
		})
	}
}

func TestSignImage_AdmittedThroughTheKeyPolicy(t *testing.T) {
	for _, tc := range signingAdmissionCases() {
		t.Run(tc.name, func(t *testing.T) {
			svc := admissionService(t)
			ctx := withSigningKeys(t, svc, corimSignPermission, "attestation_signing_keys:bind")
			svc.SetCA(newCodeSigningCA(t))
			(&memoryRegistry{}).install(svc)
			tc.prepare(t, svc, ctx)
			_, err := svc.SignImage(ctx, signImageRequest())
			tc.refused(t, err)
		})
	}
}

func TestSigningPublicKey_NotAdmittedForSigning(t *testing.T) {
	svc := admissionService(t)
	want := generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	restrictTenantKey(t, svc, appraisal.ReleaseSigningKeyID)

	pub, err := svc.SigningPublicKey(context.Background(), "tenant-a", releaseResolution())
	require.NoError(t, err, "a public-key read is not a signature")
	assert.Equal(t, want, pub)
}
