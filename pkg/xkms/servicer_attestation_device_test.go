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

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
)

// endorseRoot stores a CA of kind under name for the tenant ctx carries and
// returns it.
func endorseRoot(t *testing.T, ctx context.Context, svc *XKMSService, name string, kind appraisal.EndorsementKind) *appraisaltest.Authority {
	t.Helper()
	ca, err := appraisaltest.NewAuthority(name)
	require.NoError(t, err)
	_, err = svc.PutAttestationEndorsement(ctx, &appraisal.PutEndorsementRequest{
		Name: name, Kind: kind, CertificatePEM: ca.CertificatePEM(),
	})
	require.NoError(t, err)
	return ca
}

func requireRefused(t *testing.T, err error, check string, cause error) {
	t.Helper()
	require.ErrorIs(t, err, appraisal.ErrEvidenceRefused)
	var refused *appraisal.EvidenceRefusedError
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, check, refused.Check)
	if cause != nil {
		assert.ErrorIs(t, err, cause)
	}
}

func TestXKMSService_AppraiseAndroidKeyAttestation(t *testing.T) {
	f := newVerifierFixture(t)
	ctx := tenantCtx("acme")
	root := endorseRoot(t, ctx, f.svc, "handset-root", appraisal.EndorsementAndroidRoot)

	chain, err := appraisaltest.AndroidKeyAttestation(root, appraisaltest.LockedVerifiedBoot())
	require.NoError(t, err)
	result, err := f.svc.AppraiseAndroidKeyAttestation(ctx, &appraisal.AppraiseAndroidKeyAttestationRequest{ChainDER: chain})
	require.NoError(t, err)
	assert.True(t, result.Verified)
	assert.False(t, result.CryptographicFailure)
	assert.Equal(t, "handset-root", result.TrustAnchor)
	assert.Equal(t, android.VerifiedBootVerified.String(), result.BootState)
	assert.Equal(t, appraisal.KeyOriginGenerated, result.KeyOrigin)
	require.Len(t, result.Checks, 1)
	assert.Equal(t, appraisal.AppraisalCheck{Name: appraisal.AppraisalCheckAndroidKey, Outcome: appraisal.AppraisalPass}, result.Checks[0])
	assert.False(t, result.AppraisedAt.IsZero())

	t.Run("unknown root", func(t *testing.T) {
		foreign, err := appraisaltest.NewAuthority("foreign-root")
		require.NoError(t, err)
		chain, err := appraisaltest.AndroidKeyAttestation(foreign, appraisaltest.LockedVerifiedBoot())
		require.NoError(t, err)
		_, err = f.svc.AppraiseAndroidKeyAttestation(ctx, &appraisal.AppraiseAndroidKeyAttestationRequest{ChainDER: chain})
		requireRefused(t, err, appraisal.AppraisalCheckAndroidKey, android.ErrChainVerificationFailed)
	})

	t.Run("unlocked bootloader", func(t *testing.T) {
		rot := appraisaltest.LockedVerifiedBoot()
		rot.DeviceLocked = false
		chain, err := appraisaltest.AndroidKeyAttestation(root, rot)
		require.NoError(t, err)
		_, err = f.svc.AppraiseAndroidKeyAttestation(ctx, &appraisal.AppraiseAndroidKeyAttestationRequest{ChainDER: chain})
		requireRefused(t, err, appraisal.AppraisalCheckAndroidKey, android.ErrBootloaderUnlocked)
	})

	t.Run("empty chain", func(t *testing.T) {
		_, err := f.svc.AppraiseAndroidKeyAttestation(ctx, &appraisal.AppraiseAndroidKeyAttestationRequest{})
		requireRefused(t, err, appraisal.AppraisalCheckAndroidKey, attestation.ErrEmptyCertificateChain)
	})

	t.Run("another tenant's root", func(t *testing.T) {
		_, err := f.svc.AppraiseAndroidKeyAttestation(tenantCtx("globex"), &appraisal.AppraiseAndroidKeyAttestationRequest{ChainDER: chain})
		requireRefused(t, err, appraisal.AppraisalCheckAndroidKey, attestation.ErrNoTrustAnchors)
	})

	t.Run("nil request", func(t *testing.T) {
		_, err := f.svc.AppraiseAndroidKeyAttestation(ctx, nil)
		assert.ErrorIs(t, err, appraisal.ErrNilRequest)
	})
}

func TestXKMSService_AppraiseEKCertificate(t *testing.T) {
	f := newVerifierFixture(t)
	ctx := tenantCtx("acme")
	manufacturer := endorseRoot(t, ctx, f.svc, "tpm-vendor", appraisal.EndorsementEKRoot)
	intermediate, err := appraisaltest.NewIntermediateAuthority(manufacturer, "tpm-vendor-issuing")
	require.NoError(t, err)

	ek, err := appraisaltest.EKCertificate(intermediate, true)
	require.NoError(t, err)
	result, err := f.svc.AppraiseEKCertificate(ctx, &appraisal.AppraiseEKCertificateRequest{
		CertificateDER: ek, IntermediatesDER: [][]byte{intermediate.Certificate.Raw},
	})
	require.NoError(t, err)
	assert.True(t, result.Verified)
	assert.Equal(t, "tpm-vendor", result.TrustAnchor)
	require.Len(t, result.Checks, 1)
	assert.Equal(t, appraisal.AppraisalCheck{Name: appraisal.AppraisalCheckEKCertificate, Outcome: appraisal.AppraisalPass}, result.Checks[0])

	t.Run("missing EK EKU", func(t *testing.T) {
		ek, err := appraisaltest.EKCertificate(manufacturer, false)
		require.NoError(t, err)
		_, err = f.svc.AppraiseEKCertificate(ctx, &appraisal.AppraiseEKCertificateRequest{CertificateDER: ek})
		requireRefused(t, err, appraisal.AppraisalCheckEKCertificate, nil)
	})

	t.Run("unknown issuer", func(t *testing.T) {
		foreign, err := appraisaltest.NewAuthority("foreign-vendor")
		require.NoError(t, err)
		ek, err := appraisaltest.EKCertificate(foreign, true)
		require.NoError(t, err)
		_, err = f.svc.AppraiseEKCertificate(ctx, &appraisal.AppraiseEKCertificateRequest{CertificateDER: ek})
		requireRefused(t, err, appraisal.AppraisalCheckEKCertificate, nil)
	})

	t.Run("garbage DER", func(t *testing.T) {
		_, err := f.svc.AppraiseEKCertificate(ctx, &appraisal.AppraiseEKCertificateRequest{CertificateDER: []byte("not a certificate")})
		requireRefused(t, err, appraisal.AppraisalCheckEKCertificate, nil)
	})

	t.Run("garbage intermediate", func(t *testing.T) {
		_, err := f.svc.AppraiseEKCertificate(ctx, &appraisal.AppraiseEKCertificateRequest{CertificateDER: ek, IntermediatesDER: [][]byte{[]byte("junk")}})
		requireRefused(t, err, appraisal.AppraisalCheckEKCertificate, nil)
	})

	t.Run("empty certificate", func(t *testing.T) {
		_, err := f.svc.AppraiseEKCertificate(ctx, &appraisal.AppraiseEKCertificateRequest{})
		requireRefused(t, err, appraisal.AppraisalCheckEKCertificate, nil)
	})

	t.Run("an android root does not anchor an EK", func(t *testing.T) {
		globex := tenantCtx("globex")
		other := endorseRoot(t, globex, f.svc, "not-a-vendor", appraisal.EndorsementAndroidRoot)
		ek, err := appraisaltest.EKCertificate(other, true)
		require.NoError(t, err)
		_, err = f.svc.AppraiseEKCertificate(globex, &appraisal.AppraiseEKCertificateRequest{CertificateDER: ek})
		requireRefused(t, err, appraisal.AppraisalCheckEKCertificate, attestation.ErrNoTrustAnchors)
	})

	t.Run("nil request", func(t *testing.T) {
		_, err := f.svc.AppraiseEKCertificate(ctx, nil)
		assert.ErrorIs(t, err, appraisal.ErrNilRequest)
	})
}

func TestXKMSService_AppraiseDevice_NotConfigured(t *testing.T) {
	svc := &XKMSService{}
	ctx := tenantCtx("acme")
	_, err := svc.AppraiseAndroidKeyAttestation(ctx, &appraisal.AppraiseAndroidKeyAttestationRequest{})
	assert.ErrorIs(t, err, ErrNotConfigured)
	_, err = svc.AppraiseEKCertificate(ctx, &appraisal.AppraiseEKCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConfigured)
}
