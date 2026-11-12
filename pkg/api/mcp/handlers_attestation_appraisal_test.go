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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// appraisalMethods lists the attestation appraisal tools with the
// resource:action pair each gates on, the same pair as its REST route.
var appraisalMethods = map[string]string{
	"attestation.endorsement.put":         "attestation_endorsements:create",
	"attestation.endorsement.list":        "attestation_endorsements:list",
	"attestation.endorsement.delete":      "attestation_endorsements:delete",
	"attestation.reference_values.put":    "attestation_reference_values:create",
	"attestation.reference_values.get":    "attestation_reference_values:get",
	"attestation.reference_values.list":   "attestation_reference_values:list",
	"attestation.reference_values.delete": "attestation_reference_values:delete",
	"attestation.appraise":                "attestation_verifier:verify",
}

// appraisalAKRootPEM returns a self-signed CA certificate usable as an AK
// root endorsement.
func appraisalAKRootPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test AK root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestAttestationAppraisalTools_Endorsements puts, lists and deletes an
// endorsement over MCP, bound to the caller's tenant.
func TestAttestationAppraisalTools_Endorsements(t *testing.T) {
	s := newSigningKeyMCP(t)

	var put transport.AttestationEndorsement
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.endorsement.put", transport.PutAttestationEndorsementRequest{
		Name: "fleet-root", Kind: appraisal.EndorsementAKRoot, CertificatePEM: appraisalAKRootPEM(t),
	}, &put))
	assert.Equal(t, "fleet-root", put.Name)

	var list transport.ListAttestationEndorsementsResponse
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.endorsement.list", transport.ListAttestationEndorsementsRequest{Kind: appraisal.EndorsementAKRoot}, &list))
	require.Len(t, list.Endorsements, 1)
	assert.Equal(t, "fleet-root", list.Endorsements[0].Name)

	var other transport.ListAttestationEndorsementsResponse
	require.NoError(t, invokeOIDC(t, s, "globex", "bob", "attestation.endorsement.list", transport.ListAttestationEndorsementsRequest{}, &other))
	assert.Empty(t, other.Endorsements)

	var deleted transport.DeleteAttestationEndorsementRequest
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.endorsement.delete", transport.DeleteAttestationEndorsementRequest{Name: "fleet-root"}, &deleted))
	assert.Equal(t, "fleet-root", deleted.Name)
}

// TestAttestationAppraisalTools_ReferenceValuesAndAppraise lists, gets and
// deletes reference values, refuses an unsigned CoRIM, and appraises a quote.
func TestAttestationAppraisalTools_ReferenceValuesAndAppraise(t *testing.T) {
	s := newSigningKeyMCP(t)

	var list transport.ListAttestationReferenceValuesResponse
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.reference_values.list", struct{}{}, &list))
	assert.Empty(t, list.ReferenceValues)

	var out map[string]any
	err := invokeOIDC(t, s, "acme", "alice", "attestation.reference_values.put", transport.PutAttestationReferenceValuesRequest{Name: "golden", SignedCoRIM: []byte("not a corim")}, &out)
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInvalidParams, keyErr.Code)

	var result transport.AttestationResult
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.appraise", transport.AppraiseAttestationQuoteRequest{
		AKCertificatePEM: appraisalAKRootPEM(t), Quote: []byte{1}, Signature: []byte{1}, Nonce: []byte{1},
		PCRs: map[uint32][]byte{0: make([]byte, 32)}, ReferenceValues: "golden",
	}, &result))
	assert.False(t, result.Verified)
	assert.NotEmpty(t, result.Checks)
}

// TestAttestationAppraisalTools_MapErrors maps malformed params and unknown
// names to their JSON-RPC codes.
func TestAttestationAppraisalTools_MapErrors(t *testing.T) {
	s := newSigningKeyMCP(t)
	tests := []struct {
		name, method string
		params       any
		code         int
	}{
		{"malformed params", "attestation.endorsement.put", "not an object", ErrCodeInvalidParams},
		{"malformed list params", "attestation.reference_values.list", "not an object", ErrCodeInvalidParams},
		{"unknown endorsement", "attestation.endorsement.delete", transport.DeleteAttestationEndorsementRequest{Name: "missing"}, sdkssh.JSONRPCCodeNotFound},
		{"unknown reference values", "attestation.reference_values.get", transport.GetAttestationReferenceValuesRequest{Name: "missing"}, sdkssh.JSONRPCCodeNotFound},
		{"unknown reference values delete", "attestation.reference_values.delete", transport.DeleteAttestationReferenceValuesRequest{Name: "missing"}, sdkssh.JSONRPCCodeNotFound},
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
}

// TestAttestationAppraisalTools_WithoutAnAppraiser fails every tool as
// unavailable when the server has no appraiser.
func TestAttestationAppraisalTools_WithoutAnAppraiser(t *testing.T) {
	s := createTestServer(t)
	for method := range appraisalMethods {
		var out map[string]any
		err := invokeOIDC(t, s, "acme", "alice", method, transport.DeleteAttestationEndorsementRequest{Name: "n"}, &out)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr, method)
		assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code, method)
	}
}

// TestAttestationAppraisalTools_RefusedWithoutThePair refuses a caller that
// lacks the tool's resource:action pair before dispatch.
func TestAttestationAppraisalTools_RefusedWithoutThePair(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()
	for method, perm := range appraisalMethods {
		rbac := newFakeRBAC()
		server := newRBACServer(t, svc, rbac)
		resp := call(server, authedCtx(), method)
		require.NotNil(t, resp.Error, method)
		assert.Equal(t, ErrCodeForbidden, resp.Error.Code, method)
		assert.Equal(t, perm, rbac.lastCall(), method)
	}
}
