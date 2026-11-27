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
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// appraisalMethods are the Verifier tools.
var appraisalMethods = []string{
	"attestation.endorsement.put", "attestation.endorsement.list", "attestation.endorsement.delete",
	"attestation.reference_values.put", "attestation.reference_values.get",
	"attestation.reference_values.list", "attestation.reference_values.delete",
	"attestation.quote.appraise",
}

// appraisalMCPEvidence is a tenant's trust anchors, signed reference values
// and a genuine quote over the PCRs they bind.
type appraisalMCPEvidence struct {
	akCA, rvCA *appraisaltest.Authority
	corim      []byte
	quote      transport.AppraiseAttestationQuoteRequest
}

func newAppraisalMCPEvidence(t *testing.T) *appraisalMCPEvidence {
	t.Helper()
	pcrs := appraisaltest.PCRValues(0, 4, 7)
	akCA, err := appraisaltest.NewAuthority("AK CA")
	require.NoError(t, err)
	rvCA, err := appraisaltest.NewAuthority("Reference Value CA")
	require.NoError(t, err)
	ak, err := appraisaltest.IssueAttestationKey(akCA, true)
	require.NoError(t, err)
	signerCert, signerKey, err := appraisaltest.SignerUnder(rvCA)
	require.NoError(t, err)
	corim, err := appraisaltest.SignCoRIM(pcrs, signerKey, []*x509.Certificate{signerCert})
	require.NoError(t, err)
	nonce := []byte("mcp-verifier-nonce-0000000000000")
	quote, err := appraisaltest.SignQuote(ak, pcrs, nonce)
	require.NoError(t, err)
	return &appraisalMCPEvidence{
		akCA: akCA, rvCA: rvCA, corim: corim,
		quote: transport.AppraiseAttestationQuoteRequest{
			AKCertificatePEM: ak.CertificatePEM(),
			Quote:            quote.Attest,
			Signature:        quote.Signature,
			Nonce:            nonce,
			PCRs:             pcrs,
			ReferenceValues:  "golden",
		},
	}
}

// endorse stores the evidence's trust anchors and "golden" reference values
// in tenant acme.
func (e *appraisalMCPEvidence) endorse(t *testing.T, s *Server) {
	t.Helper()
	var endorsement transport.AttestationEndorsement
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.endorsement.put", transport.PutAttestationEndorsementRequest{
		Name: "ak-ca", Kind: appraisal.EndorsementAKRoot, CertificatePEM: e.akCA.CertificatePEM(),
	}, &endorsement))
	assert.Equal(t, "ak-ca", endorsement.Name)
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.endorsement.put", transport.PutAttestationEndorsementRequest{
		Name: "rv-ca", Kind: appraisal.EndorsementReferenceSigner, CertificatePEM: e.rvCA.CertificatePEM(),
	}, &endorsement))
	var values transport.AttestationReferenceValues
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.reference_values.put", transport.PutAttestationReferenceValuesRequest{
		Name: "golden", SignedCoRIM: e.corim,
	}, &values))
	assert.Equal(t, "golden", values.Name)
}

// TestAttestationAppraisalTools_Lifecycle proves the tools reach the
// Verifier in the caller's tenant: the stored trust anchors and reference
// values appraise a genuine quote, and each delete removes what it names.
func TestAttestationAppraisalTools_Lifecycle(t *testing.T) {
	s := newSigningKeyMCP(t)
	e := newAppraisalMCPEvidence(t)
	e.endorse(t, s)

	var roots transport.ListAttestationEndorsementsResponse
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.endorsement.list", transport.ListAttestationEndorsementsRequest{Kind: appraisal.EndorsementAKRoot}, &roots))
	require.Len(t, roots.Endorsements, 1)
	assert.Equal(t, "ak-ca", roots.Endorsements[0].Name)

	var golden transport.AttestationReferenceValues
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.reference_values.get", transport.GetAttestationReferenceValuesRequest{Name: "golden"}, &golden))
	assert.Equal(t, "golden", golden.Name)
	var listed transport.ListAttestationReferenceValuesResponse
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.reference_values.list", struct{}{}, &listed))
	assert.Len(t, listed.ReferenceValues, 1)

	var result transport.AttestationResult
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.quote.appraise", e.quote, &result))
	assert.True(t, result.Verified, "genuine evidence must verify: %+v", result.Checks)

	var deletedValues transport.DeleteAttestationReferenceValuesRequest
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.reference_values.delete", transport.DeleteAttestationReferenceValuesRequest{Name: "golden"}, &deletedValues))
	assert.Equal(t, "golden", deletedValues.Name)
	var deletedEndorsement transport.DeleteAttestationEndorsementRequest
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.endorsement.delete", transport.DeleteAttestationEndorsementRequest{Name: "ak-ca"}, &deletedEndorsement))
	assert.Equal(t, "ak-ca", deletedEndorsement.Name)
	var all transport.ListAttestationEndorsementsResponse
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.endorsement.list", transport.ListAttestationEndorsementsRequest{}, &all))
	assert.Len(t, all.Endorsements, 1)
}

// TestAttestationAppraisalTools_TenantIsolation proves another tenant sees
// none of a tenant's records and cannot appraise against them.
func TestAttestationAppraisalTools_TenantIsolation(t *testing.T) {
	s := newSigningKeyMCP(t)
	e := newAppraisalMCPEvidence(t)
	e.endorse(t, s)

	var endorsements transport.ListAttestationEndorsementsResponse
	require.NoError(t, invokeOIDC(t, s, "globex", "bob", "attestation.endorsement.list", transport.ListAttestationEndorsementsRequest{}, &endorsements))
	assert.Empty(t, endorsements.Endorsements)
	var result transport.AttestationResult
	require.NoError(t, invokeOIDC(t, s, "globex", "bob", "attestation.quote.appraise", e.quote, &result))
	assert.False(t, result.Verified, "another tenant's baseline must not verify")
}

// TestAttestationAppraisalTools_MapErrors proves the Verifier's errors reach
// the wire with the codes apierrors.AttestationAppraisalClassOf assigns, and
// every tool of a server with no Verifier answers service unavailable.
func TestAttestationAppraisalTools_MapErrors(t *testing.T) {
	s := newSigningKeyMCP(t)
	tests := []struct {
		name, method string
		params       any
		code         int
	}{
		{"malformed params", "attestation.endorsement.put", "not an object", ErrCodeInvalidParams},
		{"malformed list params", "attestation.reference_values.list", "not an object", ErrCodeInvalidParams},
		{"no certificate", "attestation.endorsement.put", transport.PutAttestationEndorsementRequest{Name: "ak-ca", Kind: appraisal.EndorsementAKRoot}, ErrCodeInvalidParams},
		{"unsigned reference values", "attestation.reference_values.put", transport.PutAttestationReferenceValuesRequest{Name: "golden", SignedCoRIM: []byte{0, 1, 2}}, ErrCodeInvalidParams},
		{"missing reference values", "attestation.reference_values.get", transport.GetAttestationReferenceValuesRequest{Name: "absent"}, sdkssh.JSONRPCCodeNotFound},
		{"missing endorsement", "attestation.endorsement.delete", transport.DeleteAttestationEndorsementRequest{Name: "absent"}, sdkssh.JSONRPCCodeNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out map[string]any
			err := invokeOIDC(t, s, "acme", "alice", tt.method, tt.params, &out)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tt.code, keyErr.Code)
		})
	}

	unserved := createTestServer(t)
	for _, method := range appraisalMethods {
		var out map[string]any
		err := invokeOIDC(t, unserved, "acme", "alice", method, transport.GetAttestationReferenceValuesRequest{Name: "golden"}, &out)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr, method)
		assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code, method)
	}
}
