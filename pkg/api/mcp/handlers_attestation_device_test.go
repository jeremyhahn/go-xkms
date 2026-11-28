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

package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
)

// endorseDeviceRoot stores a fresh CA of kind under name for acme.
func endorseDeviceRoot(t *testing.T, s *Server, name string, kind appraisal.EndorsementKind) *appraisaltest.Authority {
	t.Helper()
	ca, err := appraisaltest.NewAuthority(name)
	require.NoError(t, err)
	var put transport.AttestationEndorsement
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.endorsement.put", transport.PutAttestationEndorsementRequest{
		Name: name, Kind: kind, CertificatePEM: ca.CertificatePEM(),
	}, &put))
	return ca
}

func requireInvalidParams(t *testing.T, err error) {
	t.Helper()
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInvalidParams, keyErr.Code)
}

func TestAttestationAppraisalTools_AndroidKeyAttestation(t *testing.T) {
	s := newSigningKeyMCP(t)
	root := endorseDeviceRoot(t, s, "handset-root", appraisal.EndorsementAndroidRoot)

	chain, err := appraisaltest.AndroidKeyAttestation(root, appraisaltest.LockedVerifiedBoot())
	require.NoError(t, err)
	var result transport.AttestationResult
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.appraise.android_key", transport.AppraiseAndroidKeyAttestationRequest{ChainDER: chain}, &result))
	assert.True(t, result.Verified)
	assert.Equal(t, "handset-root", result.TrustAnchor)
	assert.Equal(t, android.VerifiedBootVerified.String(), result.BootState)
	assert.Equal(t, appraisal.KeyOriginGenerated, result.KeyOrigin)

	rot := appraisaltest.LockedVerifiedBoot()
	rot.DeviceLocked = false
	unlocked, err := appraisaltest.AndroidKeyAttestation(root, rot)
	require.NoError(t, err)
	var out map[string]any
	requireInvalidParams(t, invokeOIDC(t, s, "acme", "alice", "attestation.appraise.android_key", transport.AppraiseAndroidKeyAttestationRequest{ChainDER: unlocked}, &out))

	// Another tenant's endorsements do not anchor the chain.
	requireInvalidParams(t, invokeOIDC(t, s, "globex", "bob", "attestation.appraise.android_key", transport.AppraiseAndroidKeyAttestationRequest{ChainDER: chain}, &out))
}

func TestAttestationAppraisalTools_EKCertificate(t *testing.T) {
	s := newSigningKeyMCP(t)
	vendor := endorseDeviceRoot(t, s, "tpm-vendor", appraisal.EndorsementEKRoot)
	issuing, err := appraisaltest.NewIntermediateAuthority(vendor, "tpm-vendor-issuing")
	require.NoError(t, err)

	ek, err := appraisaltest.EKCertificate(issuing, true)
	require.NoError(t, err)
	var result transport.AttestationResult
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.appraise.ek_certificate", transport.AppraiseEKCertificateRequest{
		CertificateDER: ek, IntermediatesDER: [][]byte{issuing.Certificate.Raw},
	}, &result))
	assert.True(t, result.Verified)
	assert.Equal(t, "tpm-vendor", result.TrustAnchor)

	var out map[string]any
	requireInvalidParams(t, invokeOIDC(t, s, "acme", "alice", "attestation.appraise.ek_certificate", transport.AppraiseEKCertificateRequest{CertificateDER: ek}, &out))
}
