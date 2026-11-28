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

package embedded

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
)

// deviceAppraisalService answers the two device appraisal verbs and records
// the requests it saw; the other appraisal verbs are never called.
type deviceAppraisalService struct {
	mockService
	transport.AttestationAppraisalService
	android *transport.AppraiseAndroidKeyAttestationRequest
	ek      *transport.AppraiseEKCertificateRequest
}

func (s *deviceAppraisalService) AppraiseAndroidKeyAttestation(_ context.Context, req *transport.AppraiseAndroidKeyAttestationRequest) (*transport.AttestationResult, error) {
	s.android = req
	return &transport.AttestationResult{Verified: true, TrustAnchor: "handset-root", KeyOrigin: appraisal.KeyOriginGenerated}, nil
}

func (s *deviceAppraisalService) AppraiseEKCertificate(_ context.Context, req *transport.AppraiseEKCertificateRequest) (*transport.AttestationResult, error) {
	s.ek = req
	if len(req.CertificateDER) == 0 {
		return nil, &appraisal.EvidenceRefusedError{Check: appraisal.AppraisalCheckEKCertificate, Cause: assert.AnError}
	}
	return &transport.AttestationResult{Verified: true, TrustAnchor: "tpm-vendor"}, nil
}

func TestTransport_AppraiseDeviceEvidence(t *testing.T) {
	svc := &deviceAppraisalService{}
	tr, err := New(svc)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, tr.Connect(ctx))
	t.Cleanup(func() { assert.NoError(t, tr.Close()) })

	chain := &transport.AppraiseAndroidKeyAttestationRequest{ChainDER: [][]byte{{0x30}}}
	result, err := tr.AppraiseAndroidKeyAttestation(ctx, chain)
	require.NoError(t, err)
	assert.True(t, result.Verified)
	assert.Equal(t, "handset-root", result.TrustAnchor)
	assert.Same(t, chain, svc.android)

	ek := &transport.AppraiseEKCertificateRequest{CertificateDER: []byte{0x30}, IntermediatesDER: [][]byte{{0x31}}}
	result, err = tr.AppraiseEKCertificate(ctx, ek)
	require.NoError(t, err)
	assert.Equal(t, "tpm-vendor", result.TrustAnchor)
	assert.Same(t, ek, svc.ek)

	_, err = tr.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{})
	assert.ErrorIs(t, err, appraisal.ErrEvidenceRefused)
}

func TestTransport_AppraiseDeviceEvidence_Unavailable(t *testing.T) {
	ctx := context.Background()

	disconnected, err := New(&deviceAppraisalService{})
	require.NoError(t, err)
	require.NoError(t, disconnected.Close())
	_, err = disconnected.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
	_, err = disconnected.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	noVerifier, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, noVerifier.Connect(ctx))
	t.Cleanup(func() { assert.NoError(t, noVerifier.Close()) })
	_, err = noVerifier.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{})
	assert.ErrorIs(t, err, ErrAppraisalUnsupported)
	_, err = noVerifier.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{})
	assert.ErrorIs(t, err, ErrAppraisalUnsupported)
}
