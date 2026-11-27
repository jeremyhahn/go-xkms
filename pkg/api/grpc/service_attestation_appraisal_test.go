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
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// appraisalGRPC is a gRPC service over an XKMSService wired with an
// Appraiser on an in-memory store.
type appraisalGRPC struct {
	s *Service
}

func newAppraisalGRPC(t *testing.T, authorizer *auth.Authorizer) *appraisalGRPC {
	t.Helper()
	store, err := appraisal.NewStore(appraisal.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	appraiser, err := appraisal.NewAppraiser(store)
	require.NoError(t, err)
	svc := &xkms.XKMSService{}
	svc.SetAttestationAppraiser(appraiser)
	return &appraisalGRPC{s: NewService(authorizer, nil, svc)}
}

// appraisalTenant is a caller of the tenant named.
func appraisalTenant(tenantID string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: "verifier@" + tenantID, TenantID: tenantID})
}

// appraisalEvidence is a tenant's trust anchors, signed reference values and
// a genuine quote over the PCRs they bind.
type appraisalEvidence struct {
	akCA, rvCA *appraisaltest.Authority
	corim      []byte
	quote      *pb.AppraiseAttestationQuoteRequest
}

func newAppraisalEvidence(t *testing.T) *appraisalEvidence {
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
	nonce := []byte("grpc-verifier-nonce-000000000000")
	quote, err := appraisaltest.SignQuote(ak, pcrs, nonce)
	require.NoError(t, err)
	return &appraisalEvidence{
		akCA: akCA, rvCA: rvCA, corim: corim,
		quote: &pb.AppraiseAttestationQuoteRequest{
			AkCertificatePem: ak.CertificatePEM(),
			Quote:            quote.Attest,
			Signature:        quote.Signature,
			Nonce:            nonce,
			Pcrs:             pcrs,
			ReferenceValues:  "golden",
		},
	}
}

// endorse stores the evidence's trust anchors and "golden" reference values
// for the tenant ctx carries.
func (g *appraisalGRPC) endorse(t *testing.T, ctx context.Context, e *appraisalEvidence) {
	t.Helper()
	_, err := g.s.PutAttestationEndorsement(ctx, &pb.PutAttestationEndorsementRequest{
		Name: "ak-ca", Kind: string(appraisal.EndorsementAKRoot), CertificatePem: e.akCA.CertificatePEM(),
	})
	require.NoError(t, err)
	_, err = g.s.PutAttestationEndorsement(ctx, &pb.PutAttestationEndorsementRequest{
		Name: "rv-ca", Kind: string(appraisal.EndorsementReferenceSigner), CertificatePem: e.rvCA.CertificatePEM(),
	})
	require.NoError(t, err)
	_, err = g.s.PutAttestationReferenceValues(ctx, &pb.PutAttestationReferenceValuesRequest{Name: "golden", SignedCorim: e.corim})
	require.NoError(t, err)
}

// TestAttestationAppraisalGRPC_Lifecycle drives every Verifier RPC: the
// trust anchors and reference values a tenant stores appraise its genuine
// quote, and each delete removes what it names.
func TestAttestationAppraisalGRPC_Lifecycle(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	g := newAppraisalGRPC(t, authorizer)
	e := newAppraisalEvidence(t)
	ctx := appraisalTenant("acme")
	g.endorse(t, ctx, e)

	all, err := g.s.ListAttestationEndorsements(ctx, &pb.ListAttestationEndorsementsRequest{})
	require.NoError(t, err)
	assert.Len(t, all.GetEndorsements(), 2)
	roots, err := g.s.ListAttestationEndorsements(ctx, &pb.ListAttestationEndorsementsRequest{Kind: string(appraisal.EndorsementAKRoot)})
	require.NoError(t, err)
	require.Len(t, roots.GetEndorsements(), 1)
	assert.Equal(t, "ak-ca", roots.GetEndorsements()[0].GetName())

	golden, err := g.s.GetAttestationReferenceValues(ctx, &pb.GetAttestationReferenceValuesRequest{Name: "golden"})
	require.NoError(t, err)
	assert.Equal(t, "golden", golden.GetName())
	listed, err := g.s.ListAttestationReferenceValues(ctx, &pb.ListAttestationReferenceValuesRequest{})
	require.NoError(t, err)
	assert.Len(t, listed.GetReferenceValues(), 1)

	result, err := g.s.AppraiseAttestationQuote(ctx, e.quote)
	require.NoError(t, err)
	assert.True(t, result.GetVerified(), "genuine evidence must verify: %+v", result.GetChecks())
	assert.Equal(t, "golden", result.GetReferenceValues())

	_, err = g.s.DeleteAttestationReferenceValues(ctx, &pb.DeleteAttestationReferenceValuesRequest{Name: "golden"})
	require.NoError(t, err)
	_, err = g.s.GetAttestationReferenceValues(ctx, &pb.GetAttestationReferenceValuesRequest{Name: "golden"})
	assert.Equal(t, codes.NotFound, status.Code(err))
	_, err = g.s.DeleteAttestationEndorsement(ctx, &pb.DeleteAttestationEndorsementRequest{Name: "ak-ca"})
	require.NoError(t, err)
	all, err = g.s.ListAttestationEndorsements(ctx, &pb.ListAttestationEndorsementsRequest{})
	require.NoError(t, err)
	assert.Len(t, all.GetEndorsements(), 1)
}

// TestAttestationAppraisalGRPC_TenantIsolation proves another tenant sees
// none of a tenant's records and cannot appraise against them.
func TestAttestationAppraisalGRPC_TenantIsolation(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	g := newAppraisalGRPC(t, authorizer)
	e := newAppraisalEvidence(t)
	g.endorse(t, appraisalTenant("acme"), e)
	other := appraisalTenant("globex")

	endorsements, err := g.s.ListAttestationEndorsements(other, &pb.ListAttestationEndorsementsRequest{})
	require.NoError(t, err)
	assert.Empty(t, endorsements.GetEndorsements())
	values, err := g.s.ListAttestationReferenceValues(other, &pb.ListAttestationReferenceValuesRequest{})
	require.NoError(t, err)
	assert.Empty(t, values.GetReferenceValues())
	_, err = g.s.GetAttestationReferenceValues(other, &pb.GetAttestationReferenceValuesRequest{Name: "golden"})
	assert.Equal(t, codes.NotFound, status.Code(err))
	result, err := g.s.AppraiseAttestationQuote(other, e.quote)
	require.NoError(t, err)
	assert.False(t, result.GetVerified(), "another tenant's baseline must not verify")
}

// TestAttestationAppraisalGRPC_BadRequests proves a malformed request is
// InvalidArgument and a missing record NotFound.
func TestAttestationAppraisalGRPC_BadRequests(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	g := newAppraisalGRPC(t, authorizer)
	ctx := appraisalTenant("acme")

	_, err := g.s.PutAttestationEndorsement(ctx, &pb.PutAttestationEndorsementRequest{Name: "bad/name", Kind: string(appraisal.EndorsementAKRoot)})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = g.s.PutAttestationReferenceValues(ctx, &pb.PutAttestationReferenceValuesRequest{Name: "golden", SignedCorim: []byte("not a corim")})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = g.s.DeleteAttestationEndorsement(ctx, &pb.DeleteAttestationEndorsementRequest{Name: "absent"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// appraisalRPCs calls each Verifier RPC once, keyed by the resource and
// action it must authorize.
func appraisalRPCs(ctx context.Context, s *Service) map[string]struct {
	resource, action string
	call             func() error
} {
	return map[string]struct {
		resource, action string
		call             func() error
	}{
		"put endorsement": {auth.ResourceAttestationEndorsements, auth.ActionCreate, func() error {
			_, err := s.PutAttestationEndorsement(ctx, &pb.PutAttestationEndorsementRequest{Name: "ak-ca"})
			return err
		}},
		"list endorsements": {auth.ResourceAttestationEndorsements, auth.ActionList, func() error {
			_, err := s.ListAttestationEndorsements(ctx, &pb.ListAttestationEndorsementsRequest{})
			return err
		}},
		"delete endorsement": {auth.ResourceAttestationEndorsements, auth.ActionDelete, func() error {
			_, err := s.DeleteAttestationEndorsement(ctx, &pb.DeleteAttestationEndorsementRequest{Name: "ak-ca"})
			return err
		}},
		"put reference values": {auth.ResourceAttestationReferenceValues, auth.ActionCreate, func() error {
			_, err := s.PutAttestationReferenceValues(ctx, &pb.PutAttestationReferenceValuesRequest{Name: "golden"})
			return err
		}},
		"get reference values": {auth.ResourceAttestationReferenceValues, auth.ActionGet, func() error {
			_, err := s.GetAttestationReferenceValues(ctx, &pb.GetAttestationReferenceValuesRequest{Name: "golden"})
			return err
		}},
		"list reference values": {auth.ResourceAttestationReferenceValues, auth.ActionList, func() error {
			_, err := s.ListAttestationReferenceValues(ctx, &pb.ListAttestationReferenceValuesRequest{})
			return err
		}},
		"delete reference values": {auth.ResourceAttestationReferenceValues, auth.ActionDelete, func() error {
			_, err := s.DeleteAttestationReferenceValues(ctx, &pb.DeleteAttestationReferenceValuesRequest{Name: "golden"})
			return err
		}},
		"appraise": {auth.ResourceAttestationVerifier, auth.ActionVerify, func() error {
			_, err := s.AppraiseAttestationQuote(ctx, &pb.AppraiseAttestationQuoteRequest{ReferenceValues: "golden"})
			return err
		}},
	}
}

// TestAttestationAppraisalGRPC_GateEachPermission proves each RPC asks the
// authorizer for its own permission and refuses when it is denied.
func TestAttestationAppraisalGRPC_GateEachPermission(t *testing.T) {
	authorizer, rbac := denyAuthorizer("denied")
	g := newAppraisalGRPC(t, authorizer)
	for name, rpc := range appraisalRPCs(appraisalTenant("acme"), g.s) {
		assert.Equal(t, codes.PermissionDenied, status.Code(rpc.call()), name)
		_, resource, action, seen := rbac.Last()
		require.True(t, seen, name)
		assert.Equal(t, rpc.resource, resource, name)
		assert.Equal(t, rpc.action, action, name)
	}
}

// TestAttestationAppraisalGRPC_Unavailable proves a server without an
// XKMSService, or whose service has no Appraiser, answers Unavailable.
func TestAttestationAppraisalGRPC_Unavailable(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	ctx := appraisalTenant("acme")
	servers := map[string]*Service{
		"no service":   NewService(authorizer, nil, nil),
		"no appraiser": NewService(authorizer, nil, &xkms.XKMSService{}),
	}
	for server, s := range servers {
		for name, rpc := range appraisalRPCs(ctx, s) {
			assert.Equal(t, codes.Unavailable, status.Code(rpc.call()), server+": "+name)
		}
	}
}

// TestMapAppraisalError_Unclassified proves an error outside the Verifier
// model is an internal fault.
func TestMapAppraisalError_Unclassified(t *testing.T) {
	assert.Equal(t, codes.Internal, status.Code(mapAppraisalError(errOIDCUnclassified)))
}
