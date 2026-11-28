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

package grpc

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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

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

// TestAttestationAppraisalRPCs_Endorsements puts, lists and deletes an
// endorsement over gRPC; a removed endorsement is NotFound.
func TestAttestationAppraisalRPCs_Endorsements(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	s, ctx := newSigningKeyGRPC(t, authorizer)

	put, err := s.PutAttestationEndorsement(ctx, &pb.PutAttestationEndorsementRequest{
		Name: "fleet-root", Kind: string(appraisal.EndorsementAKRoot), CertificatePem: appraisalAKRootPEM(t),
	})
	require.NoError(t, err)
	assert.Equal(t, "fleet-root", put.GetName())
	assert.Equal(t, string(appraisal.EndorsementAKRoot), put.GetKind())

	list, err := s.ListAttestationEndorsements(ctx, &pb.ListAttestationEndorsementsRequest{Kind: string(appraisal.EndorsementAKRoot)})
	require.NoError(t, err)
	require.Len(t, list.GetEndorsements(), 1)
	assert.Equal(t, "fleet-root", list.GetEndorsements()[0].GetName())

	_, err = s.DeleteAttestationEndorsement(ctx, &pb.DeleteAttestationEndorsementRequest{Name: "fleet-root"})
	require.NoError(t, err)
	list, err = s.ListAttestationEndorsements(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, list.GetEndorsements())
	_, err = s.DeleteAttestationEndorsement(ctx, &pb.DeleteAttestationEndorsementRequest{Name: "fleet-root"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestAttestationAppraisalRPCs_ReferenceValuesAndAppraise lists reference
// values, refuses an unsigned CoRIM, maps an unknown name to NotFound and
// appraises a quote.
func TestAttestationAppraisalRPCs_ReferenceValuesAndAppraise(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	s, ctx := newSigningKeyGRPC(t, authorizer)

	list, err := s.ListAttestationReferenceValues(ctx, &pb.ListAttestationReferenceValuesRequest{})
	require.NoError(t, err)
	assert.Empty(t, list.GetReferenceValues())

	_, err = s.PutAttestationReferenceValues(ctx, &pb.PutAttestationReferenceValuesRequest{Name: "golden", SignedCorim: []byte("not a corim")})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = s.GetAttestationReferenceValues(ctx, &pb.GetAttestationReferenceValuesRequest{Name: "missing"})
	assert.Equal(t, codes.NotFound, status.Code(err))
	_, err = s.DeleteAttestationReferenceValues(ctx, &pb.DeleteAttestationReferenceValuesRequest{Name: "missing"})
	assert.Equal(t, codes.NotFound, status.Code(err))

	result, err := s.AppraiseAttestationQuote(ctx, &pb.AppraiseAttestationQuoteRequest{
		AkCertificatePem: appraisalAKRootPEM(t), Quote: []byte{1}, Signature: []byte{1}, Nonce: []byte{1},
		Pcrs: map[uint32][]byte{0: make([]byte, 32)}, ReferenceValues: "golden",
	})
	require.NoError(t, err)
	assert.False(t, result.GetVerified())
	assert.NotEmpty(t, result.GetChecks())
	assert.NotNil(t, result.GetAppraisedAt())
}

// TestAttestationAppraisalRPCs_WithoutAnAppraiser proves a server with no
// service is Unavailable, and one with no appraiser wired fails with the
// not-configured code, Unavailable.
func TestAttestationAppraisalRPCs_WithoutAnAppraiser(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	_, ctx := newSigningKeyGRPC(t, authorizer)

	empty := NewService(authorizer, nil, nil)
	_, err := empty.ListAttestationReferenceValues(ctx, &pb.ListAttestationReferenceValuesRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))

	unconfigured := NewService(authorizer, nil, &xkms.XKMSService{})
	_, err = unconfigured.AppraiseAttestationQuote(ctx, &pb.AppraiseAttestationQuoteRequest{ReferenceValues: "golden"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = unconfigured.ListAttestationEndorsements(ctx, &pb.ListAttestationEndorsementsRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = unconfigured.AppraiseAndroidKeyAttestation(ctx, &pb.AppraiseAndroidKeyAttestationRequest{ChainDer: [][]byte{{1}}})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = unconfigured.AppraiseEKCertificate(ctx, &pb.AppraiseEKCertificateRequest{CertificateDer: []byte{1}})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// TestAttestationAppraisalRPCs_GateEachPermission proves each RPC asks the
// authorizer for the resource:action pair of its REST and MCP route, and a
// caller without it is refused.
func TestAttestationAppraisalRPCs_GateEachPermission(t *testing.T) {
	authorizer, rbac := denyAuthorizer("denied")
	s, ctx := newSigningKeyGRPC(t, authorizer)
	calls := map[string]struct {
		resource, action string
		call             func() error
	}{
		"endorsement put": {auth.ResourceAttestationEndorsements, auth.ActionCreate, func() error {
			_, err := s.PutAttestationEndorsement(ctx, &pb.PutAttestationEndorsementRequest{Name: "r"})
			return err
		}},
		"endorsement list": {auth.ResourceAttestationEndorsements, auth.ActionList, func() error {
			_, err := s.ListAttestationEndorsements(ctx, &pb.ListAttestationEndorsementsRequest{})
			return err
		}},
		"endorsement delete": {auth.ResourceAttestationEndorsements, auth.ActionDelete, func() error {
			_, err := s.DeleteAttestationEndorsement(ctx, &pb.DeleteAttestationEndorsementRequest{Name: "r"})
			return err
		}},
		"reference values put": {auth.ResourceAttestationReferenceValues, auth.ActionCreate, func() error {
			_, err := s.PutAttestationReferenceValues(ctx, &pb.PutAttestationReferenceValuesRequest{Name: "g"})
			return err
		}},
		"reference values get": {auth.ResourceAttestationReferenceValues, auth.ActionGet, func() error {
			_, err := s.GetAttestationReferenceValues(ctx, &pb.GetAttestationReferenceValuesRequest{Name: "g"})
			return err
		}},
		"reference values list": {auth.ResourceAttestationReferenceValues, auth.ActionList, func() error {
			_, err := s.ListAttestationReferenceValues(ctx, &pb.ListAttestationReferenceValuesRequest{})
			return err
		}},
		"reference values delete": {auth.ResourceAttestationReferenceValues, auth.ActionDelete, func() error {
			_, err := s.DeleteAttestationReferenceValues(ctx, &pb.DeleteAttestationReferenceValuesRequest{Name: "g"})
			return err
		}},
		"appraise": {auth.ResourceAttestationVerifier, auth.ActionVerify, func() error {
			_, err := s.AppraiseAttestationQuote(ctx, &pb.AppraiseAttestationQuoteRequest{ReferenceValues: "g"})
			return err
		}},
		"appraise android key": {auth.ResourceAttestationVerifier, auth.ActionVerify, func() error {
			_, err := s.AppraiseAndroidKeyAttestation(ctx, &pb.AppraiseAndroidKeyAttestationRequest{ChainDer: [][]byte{{1}}})
			return err
		}},
		"appraise ek certificate": {auth.ResourceAttestationVerifier, auth.ActionVerify, func() error {
			_, err := s.AppraiseEKCertificate(ctx, &pb.AppraiseEKCertificateRequest{CertificateDer: []byte{1}})
			return err
		}},
	}
	for name, c := range calls {
		err := c.call()
		assert.Equal(t, codes.PermissionDenied, status.Code(err), name)
		_, resource, action, seen := rbac.Last()
		require.True(t, seen, name)
		assert.Equal(t, c.resource, resource, name)
		assert.Equal(t, c.action, action, name)
	}
}

// TestMapAttestationAppraisalError_Unclassified proves an error the table
// does not classify is an internal fault.
func TestMapAttestationAppraisalError_Unclassified(t *testing.T) {
	assert.Equal(t, codes.Internal, status.Code(mapAttestationAppraisalError(errOIDCUnclassified)))
	assert.Equal(t, codes.NotFound, status.Code(mapAttestationAppraisalError(appraisal.ErrRecordNotFound)))
}
