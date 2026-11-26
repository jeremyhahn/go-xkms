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

package pbconv

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
)

var appraisalTime = time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)

// TestAttestationAppraisalConversions_RoundTrip proves an endorsement,
// reference values, quote evidence and an attestation result, and their
// lists, survive the wire unchanged.
func TestAttestationAppraisalConversions_RoundTrip(t *testing.T) {
	endorsement := &transport.AttestationEndorsement{
		Name: "fleet-root", Kind: appraisal.EndorsementAKRoot,
		CertificatePEM: []byte("cert"), PublicKeyPEM: []byte("key"), CreatedAt: appraisalTime,
	}
	assert.Equal(t, endorsement, AttestationEndorsementFromProto(AttestationEndorsementToProto(endorsement)))
	endorsements := &transport.ListAttestationEndorsementsResponse{Endorsements: []*transport.AttestationEndorsement{endorsement}}
	assert.Equal(t, endorsements, ListAttestationEndorsementsResponseFromProto(ListAttestationEndorsementsResponseToProto(endorsements)))

	values := &transport.AttestationReferenceValues{
		Name: "fleet-baseline", ManifestID: "m-1", Profile: "tag:xkms", Signer: "release",
		Repository: "acme/app", NotBefore: appraisalTime, NotAfter: appraisalTime.Add(time.Hour),
		PCRIndices: []uint32{0, 7}, StoredAt: appraisalTime, SignedCoRIM: []byte("corim"),
	}
	assert.Equal(t, values, AttestationReferenceValuesFromProto(AttestationReferenceValuesToProto(values)))
	list := &transport.ListAttestationReferenceValuesResponse{ReferenceValues: []*transport.AttestationReferenceValues{values}}
	assert.Equal(t, list, ListAttestationReferenceValuesResponseFromProto(ListAttestationReferenceValuesResponseToProto(list)))

	evidence := &transport.AppraiseAttestationQuoteRequest{
		AKCertificatePEM: []byte("ak"), Quote: []byte("quote"), Signature: []byte("sig"), Nonce: []byte("nonce"),
		PCRs: map[uint32][]byte{7: {0x01}}, EventLog: []byte("log"), ReferenceValues: "fleet-baseline",
	}
	assert.Equal(t, evidence, AppraiseAttestationQuoteRequestFromProto(AppraiseAttestationQuoteRequestToProto(evidence)))

	result := &transport.AttestationResult{
		Verified: false, CryptographicFailure: true,
		Checks:          []transport.AttestationAppraisalCheck{{Name: "pcrs", Outcome: appraisal.AppraisalForged, Reason: "pcr 7 differs"}},
		ReferenceValues: "fleet-baseline", ManifestID: "m-1", Signer: "release",
		BaselineSource: appraisal.BaselineSourceSigned, AppraisedAt: appraisalTime,
	}
	assert.Equal(t, result, AttestationResultFromProto(AttestationResultToProto(result)))
}

// TestAttestationAppraisalConversions_NilMessages proves an absent message
// converts to nil, and an absent list to an empty one.
func TestAttestationAppraisalConversions_NilMessages(t *testing.T) {
	assert.Nil(t, AttestationEndorsementToProto(nil))
	assert.Nil(t, AttestationEndorsementFromProto(nil))
	assert.Nil(t, AttestationReferenceValuesToProto(nil))
	assert.Nil(t, AttestationReferenceValuesFromProto(nil))
	assert.Nil(t, AttestationResultToProto(nil))
	assert.Nil(t, AttestationResultFromProto(nil))
	assert.Empty(t, ListAttestationEndorsementsResponseToProto(nil).GetEndorsements())
	assert.Empty(t, ListAttestationReferenceValuesResponseToProto(nil).GetReferenceValues())
	endorsements := ListAttestationEndorsementsResponseFromProto(nil)
	require.NotNil(t, endorsements.Endorsements)
	assert.Empty(t, endorsements.Endorsements)
	values := ListAttestationReferenceValuesResponseFromProto(nil)
	require.NotNil(t, values.ReferenceValues)
	assert.Empty(t, values.ReferenceValues)
}

// TestAttestationAppraisalRequests_FromProto proves the server side reads
// every field of a request, and reads an absent message as an empty request,
// which the Appraiser then refuses.
func TestAttestationAppraisalRequests_FromProto(t *testing.T) {
	put := PutAttestationEndorsementRequestFromProto(&pb.PutAttestationEndorsementRequest{
		Name: "fleet-root", Kind: "ak-root", CertificatePem: []byte("cert"), PublicKeyPem: []byte("key"),
	})
	assert.Equal(t, &transport.PutAttestationEndorsementRequest{
		Name: "fleet-root", Kind: appraisal.EndorsementAKRoot, CertificatePEM: []byte("cert"), PublicKeyPEM: []byte("key"),
	}, put)
	values := PutAttestationReferenceValuesRequestFromProto(&pb.PutAttestationReferenceValuesRequest{
		Name: "fleet-baseline", SignedCorim: []byte("corim"), Repository: "acme/app",
	})
	assert.Equal(t, &transport.PutAttestationReferenceValuesRequest{Name: "fleet-baseline", SignedCoRIM: []byte("corim"), Repository: "acme/app"}, values)

	assert.Equal(t, &transport.PutAttestationEndorsementRequest{}, PutAttestationEndorsementRequestFromProto(nil))
	assert.Equal(t, &transport.PutAttestationReferenceValuesRequest{}, PutAttestationReferenceValuesRequestFromProto(nil))
	assert.Equal(t, &transport.AppraiseAttestationQuoteRequest{}, AppraiseAttestationQuoteRequestFromProto(nil))
}

// appraisalRecordingServer answers each Verifier RPC and records the name
// each request carried.
type appraisalRecordingServer struct {
	pb.UnimplementedKeystoreServiceServer
	names []string
}

func (s *appraisalRecordingServer) PutAttestationEndorsement(_ context.Context, r *pb.PutAttestationEndorsementRequest) (*pb.AttestationEndorsement, error) {
	s.names = append(s.names, r.GetName())
	return &pb.AttestationEndorsement{Name: r.GetName(), Kind: r.GetKind()}, nil
}

func (s *appraisalRecordingServer) ListAttestationEndorsements(_ context.Context, r *pb.ListAttestationEndorsementsRequest) (*pb.ListAttestationEndorsementsResponse, error) {
	s.names = append(s.names, r.GetKind())
	return &pb.ListAttestationEndorsementsResponse{Endorsements: []*pb.AttestationEndorsement{{Name: "fleet-root", Kind: r.GetKind()}}}, nil
}

func (s *appraisalRecordingServer) DeleteAttestationEndorsement(_ context.Context, r *pb.DeleteAttestationEndorsementRequest) (*pb.DeleteAttestationEndorsementResponse, error) {
	s.names = append(s.names, r.GetName())
	return &pb.DeleteAttestationEndorsementResponse{}, nil
}

func (s *appraisalRecordingServer) PutAttestationReferenceValues(_ context.Context, r *pb.PutAttestationReferenceValuesRequest) (*pb.AttestationReferenceValues, error) {
	s.names = append(s.names, r.GetName())
	return &pb.AttestationReferenceValues{Name: r.GetName(), Repository: r.GetRepository()}, nil
}

func (s *appraisalRecordingServer) GetAttestationReferenceValues(_ context.Context, r *pb.GetAttestationReferenceValuesRequest) (*pb.AttestationReferenceValues, error) {
	s.names = append(s.names, r.GetName())
	return nil, status.Error(codes.NotFound, "no reference values")
}

func (s *appraisalRecordingServer) ListAttestationReferenceValues(context.Context, *pb.ListAttestationReferenceValuesRequest) (*pb.ListAttestationReferenceValuesResponse, error) {
	return &pb.ListAttestationReferenceValuesResponse{ReferenceValues: []*pb.AttestationReferenceValues{{Name: "fleet-baseline"}}}, nil
}

func (s *appraisalRecordingServer) DeleteAttestationReferenceValues(_ context.Context, r *pb.DeleteAttestationReferenceValuesRequest) (*pb.DeleteAttestationReferenceValuesResponse, error) {
	s.names = append(s.names, r.GetName())
	return &pb.DeleteAttestationReferenceValuesResponse{}, nil
}

func (s *appraisalRecordingServer) AppraiseAttestationQuote(_ context.Context, r *pb.AppraiseAttestationQuoteRequest) (*pb.AttestationResult, error) {
	s.names = append(s.names, r.GetReferenceValues())
	return &pb.AttestationResult{Verified: true, ReferenceValues: r.GetReferenceValues()}, nil
}

// TestAttestationAppraisalClient_OverTheWire proves the client sends each
// request and returns the server's answer, and the server's status error
// unchanged.
func TestAttestationAppraisalClient_OverTheWire(t *testing.T) {
	srv := &appraisalRecordingServer{}
	c := AttestationAppraisalClient{Client: serveOIDC(t, srv).Client}
	ctx := context.Background()

	endorsement, err := c.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{Name: "fleet-root", Kind: appraisal.EndorsementAKRoot})
	require.NoError(t, err)
	assert.Equal(t, appraisal.EndorsementAKRoot, endorsement.Kind)

	endorsements, err := c.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{Kind: appraisal.EndorsementReferenceSigner})
	require.NoError(t, err)
	require.Len(t, endorsements.Endorsements, 1)

	require.NoError(t, c.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: "old-root"}))

	values, err := c.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{Name: "fleet-baseline", Repository: "acme/app"})
	require.NoError(t, err)
	assert.Equal(t, "acme/app", values.Repository)

	_, err = c.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: "missing"})
	assert.Equal(t, codes.NotFound, status.Code(err))

	list, err := c.ListAttestationReferenceValues(ctx)
	require.NoError(t, err)
	require.Len(t, list.ReferenceValues, 1)

	require.NoError(t, c.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{Name: "stale"}))

	result, err := c.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{ReferenceValues: "fleet-baseline"})
	require.NoError(t, err)
	assert.True(t, result.Verified)

	assert.Equal(t, []string{"fleet-root", "reference-signer", "old-root", "fleet-baseline", "missing", "stale", "fleet-baseline"}, srv.names)
}

// TestAttestationAppraisalClient_NilRequests proves a nil request is refused
// before it reaches the wire.
func TestAttestationAppraisalClient_NilRequests(t *testing.T) {
	c := AttestationAppraisalClient{}
	ctx := context.Background()
	_, err := c.PutAttestationEndorsement(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = c.ListAttestationEndorsements(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	assert.ErrorIs(t, c.DeleteAttestationEndorsement(ctx, nil), ErrNilRequest)
	_, err = c.PutAttestationReferenceValues(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = c.GetAttestationReferenceValues(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	assert.ErrorIs(t, c.DeleteAttestationReferenceValues(ctx, nil), ErrNilRequest)
	_, err = c.AppraiseAttestationQuote(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
}

// TestAttestationAppraisalClient_WireErrors proves every call returns the
// server's error when the server does not serve the API.
func TestAttestationAppraisalClient_WireErrors(t *testing.T) {
	c := AttestationAppraisalClient{Client: serveOIDC(t, &pb.UnimplementedKeystoreServiceServer{}).Client}
	ctx := context.Background()
	_, err := c.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = c.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	assert.Equal(t, codes.Unimplemented, status.Code(c.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{})))
	_, err = c.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = c.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = c.ListAttestationReferenceValues(ctx)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	assert.Equal(t, codes.Unimplemented, status.Code(c.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{})))
	_, err = c.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}
