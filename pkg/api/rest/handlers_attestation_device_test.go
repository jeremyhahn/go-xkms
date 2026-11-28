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

package rest

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// endorseDeviceRoot stores a fresh CA of kind under name through client.
func endorseDeviceRoot(t *testing.T, client wire.AttestationAppraisalClient, name string, kind appraisal.EndorsementKind) *appraisaltest.Authority {
	t.Helper()
	ca, err := appraisaltest.NewAuthority(name)
	require.NoError(t, err)
	_, err = client.PutAttestationEndorsement(context.Background(), &transport.PutAttestationEndorsementRequest{
		Name: name, Kind: kind, CertificatePEM: ca.CertificatePEM(),
	})
	require.NoError(t, err)
	return ca
}

func TestAttestationAppraisalREST_AndroidKeyAttestation(t *testing.T) {
	svc := signingKeyXKMS(t)
	client := appraisalClient(t, appraisalRouter(svc, acmeIdentity()))
	ctx := context.Background()
	root := endorseDeviceRoot(t, client, "handset-root", appraisal.EndorsementAndroidRoot)

	chain, err := appraisaltest.AndroidKeyAttestation(root, appraisaltest.LockedVerifiedBoot())
	require.NoError(t, err)
	result, err := client.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{ChainDER: chain})
	require.NoError(t, err)
	assert.True(t, result.Verified)
	assert.Equal(t, "handset-root", result.TrustAnchor)
	assert.Equal(t, android.VerifiedBootVerified.String(), result.BootState)
	assert.Equal(t, appraisal.KeyOriginGenerated, result.KeyOrigin)

	rot := appraisaltest.LockedVerifiedBoot()
	rot.DeviceLocked = false
	unlocked, err := appraisaltest.AndroidKeyAttestation(root, rot)
	require.NoError(t, err)
	_, err = client.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{ChainDER: unlocked})
	assert.Equal(t, http.StatusBadRequest, statusOf(err))

	// Another tenant's endorsements do not anchor the chain.
	other := appraisalClient(t, appraisalRouter(svc, &auth.Identity{Subject: "x", TenantID: "globex", Roles: []string{"admin"}}))
	_, err = other.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{ChainDER: chain})
	assert.Equal(t, http.StatusBadRequest, statusOf(err))
}

func TestAttestationAppraisalREST_EKCertificate(t *testing.T) {
	svc := signingKeyXKMS(t)
	client := appraisalClient(t, appraisalRouter(svc, acmeIdentity()))
	ctx := context.Background()
	vendor := endorseDeviceRoot(t, client, "tpm-vendor", appraisal.EndorsementEKRoot)
	issuing, err := appraisaltest.NewIntermediateAuthority(vendor, "tpm-vendor-issuing")
	require.NoError(t, err)

	ek, err := appraisaltest.EKCertificate(issuing, true)
	require.NoError(t, err)
	result, err := client.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{
		CertificateDER: ek, IntermediatesDER: [][]byte{issuing.Certificate.Raw},
	})
	require.NoError(t, err)
	assert.True(t, result.Verified)
	assert.Equal(t, "tpm-vendor", result.TrustAnchor)

	_, err = client.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{CertificateDER: ek})
	assert.Equal(t, http.StatusBadRequest, statusOf(err))
}

func TestAttestationAppraisalREST_DeviceWithoutAnAppraiser(t *testing.T) {
	client := appraisalClient(t, appraisalRouter(&xkms.XKMSService{}, acmeIdentity()))
	ctx := context.Background()
	_, err := client.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{ChainDER: [][]byte{{0x30}}})
	assert.Equal(t, http.StatusServiceUnavailable, statusOf(err))
	_, err = client.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{CertificateDER: []byte{0x30}})
	assert.Equal(t, http.StatusServiceUnavailable, statusOf(err))
}

func TestAttestationAppraisalWire_DeviceNilRequests(t *testing.T) {
	client := wire.AttestationAppraisalClient{}
	ctx := context.Background()
	_, err := client.AppraiseAndroidKeyAttestation(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	_, err = client.AppraiseEKCertificate(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
}
