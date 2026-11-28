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

// TestAttestationAppraisalConversions_RoundTrip proves every appraisal
// message survives the wire unchanged.
func TestAttestationAppraisalConversions_RoundTrip(t *testing.T) {
	at := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)

	endorsement := &transport.AttestationEndorsement{
		Name: "fleet-root", Kind: appraisal.EndorsementAKRoot,
		CertificatePEM: []byte("cert"), PublicKeyPEM: []byte("key"), CreatedAt: at,
	}
	assert.Equal(t, endorsement, AttestationEndorsementFromProto(AttestationEndorsementToProto(endorsement)))

	putEndorsement := &transport.PutAttestationEndorsementRequest{
		Name: "signer", Kind: appraisal.EndorsementReferenceSigner, PublicKeyPEM: []byte("key"),
	}
	assert.Equal(t, putEndorsement, PutAttestationEndorsementRequestFromProto(PutAttestationEndorsementRequestToProto(putEndorsement)))

	endorsements := &transport.ListAttestationEndorsementsResponse{Endorsements: []*transport.AttestationEndorsement{endorsement}}
	assert.Equal(t, endorsements, ListAttestationEndorsementsResponseFromProto(ListAttestationEndorsementsResponseToProto(endorsements)))

	assert.Equal(t, &transport.ListAttestationEndorsementsRequest{Kind: appraisal.EndorsementAKRoot},
		ListAttestationEndorsementsRequestFromProto(&pb.ListAttestationEndorsementsRequest{Kind: "ak-root"}))
	assert.Equal(t, &transport.DeleteAttestationEndorsementRequest{Name: "fleet-root"},
		DeleteAttestationEndorsementRequestFromProto(&pb.DeleteAttestationEndorsementRequest{Name: "fleet-root"}))

	values := &transport.AttestationReferenceValues{
		Name: "golden", ManifestID: "m-1", Profile: "tpm", Signer: "signer", Repository: "acme/app",
		NotBefore: at, NotAfter: at.Add(time.Hour), PCRIndices: []uint32{0, 7}, StoredAt: at,
		SignedCoRIM: []byte("corim"),
	}
	assert.Equal(t, values, AttestationReferenceValuesFromProto(AttestationReferenceValuesToProto(values)))

	putValues := &transport.PutAttestationReferenceValuesRequest{Name: "golden", SignedCoRIM: []byte("corim"), Repository: "acme/app"}
	assert.Equal(t, putValues, PutAttestationReferenceValuesRequestFromProto(PutAttestationReferenceValuesRequestToProto(putValues)))

	valuesList := &transport.ListAttestationReferenceValuesResponse{ReferenceValues: []*transport.AttestationReferenceValues{values}}
	assert.Equal(t, valuesList, ListAttestationReferenceValuesResponseFromProto(ListAttestationReferenceValuesResponseToProto(valuesList)))

	assert.Equal(t, &transport.GetAttestationReferenceValuesRequest{Name: "golden"},
		GetAttestationReferenceValuesRequestFromProto(&pb.GetAttestationReferenceValuesRequest{Name: "golden"}))
	assert.Equal(t, &transport.DeleteAttestationReferenceValuesRequest{Name: "golden"},
		DeleteAttestationReferenceValuesRequestFromProto(&pb.DeleteAttestationReferenceValuesRequest{Name: "golden"}))

	appraise := &transport.AppraiseAttestationQuoteRequest{
		AKCertificatePEM: []byte("ak"), Quote: []byte("q"), Signature: []byte("s"), Nonce: []byte("n"),
		PCRs: map[uint32][]byte{0: {1}, 7: {2}}, EventLog: []byte("log"), ReferenceValues: "golden",
	}
	assert.Equal(t, appraise, AppraiseAttestationQuoteRequestFromProto(AppraiseAttestationQuoteRequestToProto(appraise)))

	result := &transport.AttestationResult{
		Verified: false, CryptographicFailure: true,
		Checks: []appraisal.AppraisalCheck{
			{Name: "quote-signature", Outcome: appraisal.AppraisalForged, Reason: "bad signature"},
			{Name: "event-log", Outcome: appraisal.AppraisalSkipped},
		},
		ReferenceValues: "golden", ManifestID: "m-1", Signer: "signer", BaselineSource: "signed", AppraisedAt: at,
	}
	assert.Equal(t, result, AttestationResultFromProto(AttestationResultToProto(result)))
}

// TestAttestationAppraisalConversions_NilMessages proves an absent message
// converts to nil, and an absent list to an empty one.
func TestAttestationAppraisalConversions_NilMessages(t *testing.T) {
	assert.Nil(t, AttestationEndorsementToProto(nil))
	assert.Nil(t, AttestationEndorsementFromProto(nil))
	assert.Nil(t, PutAttestationEndorsementRequestToProto(nil))
	assert.Nil(t, PutAttestationEndorsementRequestFromProto(nil))
	assert.Nil(t, ListAttestationEndorsementsRequestFromProto(nil))
	assert.Nil(t, DeleteAttestationEndorsementRequestFromProto(nil))
	assert.Nil(t, AttestationReferenceValuesToProto(nil))
	assert.Nil(t, AttestationReferenceValuesFromProto(nil))
	assert.Nil(t, PutAttestationReferenceValuesRequestToProto(nil))
	assert.Nil(t, PutAttestationReferenceValuesRequestFromProto(nil))
	assert.Nil(t, GetAttestationReferenceValuesRequestFromProto(nil))
	assert.Nil(t, DeleteAttestationReferenceValuesRequestFromProto(nil))
	assert.Nil(t, AppraiseAttestationQuoteRequestToProto(nil))
	assert.Nil(t, AppraiseAttestationQuoteRequestFromProto(nil))
	assert.Nil(t, AttestationResultToProto(nil))
	assert.Nil(t, AttestationResultFromProto(nil))

	assert.Empty(t, ListAttestationEndorsementsResponseToProto(nil).GetEndorsements())
	endorsements := ListAttestationEndorsementsResponseFromProto(nil)
	require.NotNil(t, endorsements.Endorsements)
	assert.Empty(t, endorsements.Endorsements)

	assert.Empty(t, ListAttestationReferenceValuesResponseToProto(nil).GetReferenceValues())
	values := ListAttestationReferenceValuesResponseFromProto(nil)
	require.NotNil(t, values.ReferenceValues)
	assert.Empty(t, values.ReferenceValues)
}

// appraisalRecordingServer answers each appraisal RPC and records the name
// it carried.
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
	return &pb.ListAttestationEndorsementsResponse{Endorsements: []*pb.AttestationEndorsement{{Name: "fleet-root"}}}, nil
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
	return &pb.ListAttestationReferenceValuesResponse{ReferenceValues: []*pb.AttestationReferenceValues{{Name: "golden"}}}, nil
}

func (s *appraisalRecordingServer) DeleteAttestationReferenceValues(_ context.Context, r *pb.DeleteAttestationReferenceValuesRequest) (*pb.DeleteAttestationReferenceValuesResponse, error) {
	s.names = append(s.names, r.GetName())
	return &pb.DeleteAttestationReferenceValuesResponse{}, nil
}

func (s *appraisalRecordingServer) AppraiseAttestationQuote(_ context.Context, r *pb.AppraiseAttestationQuoteRequest) (*pb.AttestationResult, error) {
	s.names = append(s.names, r.GetReferenceValues())
	return &pb.AttestationResult{Verified: true, ReferenceValues: r.GetReferenceValues()}, nil
}

// TestDeviceAppraisalRequests_RoundTrip proves both device appraisal
// requests survive the protobuf conversion, and nil stays nil.
func TestDeviceAppraisalRequests_RoundTrip(t *testing.T) {
	android := &transport.AppraiseAndroidKeyAttestationRequest{ChainDER: [][]byte{{1}, {2}}}
	assert.Equal(t, android, AppraiseAndroidKeyAttestationRequestFromProto(AppraiseAndroidKeyAttestationRequestToProto(android)))
	ek := &transport.AppraiseEKCertificateRequest{CertificateDER: []byte{3}, IntermediatesDER: [][]byte{{4}}}
	assert.Equal(t, ek, AppraiseEKCertificateRequestFromProto(AppraiseEKCertificateRequestToProto(ek)))

	assert.Nil(t, AppraiseAndroidKeyAttestationRequestToProto(nil))
	assert.Nil(t, AppraiseAndroidKeyAttestationRequestFromProto(nil))
	assert.Nil(t, AppraiseEKCertificateRequestToProto(nil))
	assert.Nil(t, AppraiseEKCertificateRequestFromProto(nil))
}

// TestAttestationAppraisalClient_OverTheWire proves the client sends each
// request and returns the server's answer, and the server's status error
// unchanged.
func TestAttestationAppraisalClient_OverTheWire(t *testing.T) {
	srv := &appraisalRecordingServer{}
	c := AttestationAppraisalClient{Client: serveOIDC(t, srv).Client}
	ctx := context.Background()

	e, err := c.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{Name: "fleet-root", Kind: appraisal.EndorsementAKRoot})
	require.NoError(t, err)
	assert.Equal(t, appraisal.EndorsementAKRoot, e.Kind)

	list, err := c.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{Kind: appraisal.EndorsementAKRoot})
	require.NoError(t, err)
	require.Len(t, list.Endorsements, 1)

	require.NoError(t, c.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: "fleet-root"}))

	v, err := c.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{Name: "golden", Repository: "acme/app"})
	require.NoError(t, err)
	assert.Equal(t, "acme/app", v.Repository)

	_, err = c.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: "missing"})
	assert.Equal(t, codes.NotFound, status.Code(err))

	values, err := c.ListAttestationReferenceValues(ctx)
	require.NoError(t, err)
	require.Len(t, values.ReferenceValues, 1)

	require.NoError(t, c.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{Name: "golden"}))

	result, err := c.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{ReferenceValues: "golden"})
	require.NoError(t, err)
	assert.True(t, result.Verified)

	assert.Equal(t, []string{"fleet-root", "ak-root", "fleet-root", "golden", "missing", "golden", "golden"}, srv.names)
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
	_, err = c.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = c.ListAttestationReferenceValues(ctx)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = c.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}
