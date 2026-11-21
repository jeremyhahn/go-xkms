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

func sampleVerdict() *transport.AttestationVerdict {
	return &transport.AttestationVerdict{
		Tenant: "acme", DeviceID: "dev-1", Verified: false, Cause: "pcr mismatch",
		At: time.Date(2026, 11, 12, 8, 0, 1, 0, time.UTC),
		Result: &appraisal.AttestationResult{
			Verified: false, CryptographicFailure: true,
			Checks: []appraisal.AppraisalCheck{
				{Name: "signature", Outcome: appraisal.AppraisalOutcome("pass")},
				{Name: "pcrs", Outcome: appraisal.AppraisalOutcome("fail"), Reason: "pcr 7 differs"},
			},
			ReferenceValues: "rv-1", ManifestID: "m-1", Signer: "release", BaselineSource: "manifest",
			AppraisedAt: time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC),
		},
	}
}

// TestVerdictConversions_RoundTrip proves a verdict, a verdict list and a
// request survive the wire unchanged.
func TestVerdictConversions_RoundTrip(t *testing.T) {
	v := sampleVerdict()
	assert.Equal(t, v, AttestationVerdictFromProto(AttestationVerdictToProto(v)))

	bare := &transport.AttestationVerdict{Tenant: "acme", DeviceID: "dev-2", Verified: true}
	assert.Equal(t, bare, AttestationVerdictFromProto(AttestationVerdictToProto(bare)))

	list := &transport.ListAttestationVerdictsResponse{Verdicts: []transport.AttestationVerdict{*v, *bare}}
	assert.Equal(t, list, ListAttestationVerdictsResponseFromProto(ListAttestationVerdictsResponseToProto(list)))

	req := &transport.AttestationVerdictRequest{DeviceID: "dev-1"}
	assert.Equal(t, req, AttestationVerdictRequestFromProto(AttestationVerdictRequestToProto(req)))
}

// TestVerdictConversions_NilMessages proves an absent message converts to
// nil.
func TestVerdictConversions_NilMessages(t *testing.T) {
	assert.Nil(t, AttestationVerdictToProto(nil))
	assert.Nil(t, AttestationVerdictFromProto(nil))
	assert.Nil(t, ListAttestationVerdictsResponseToProto(nil))
	assert.Nil(t, ListAttestationVerdictsResponseFromProto(nil))
	assert.Nil(t, AttestationVerdictRequestToProto(nil))
	assert.Nil(t, AttestationVerdictRequestFromProto(nil))
}

type verdictRecordingServer struct {
	pb.UnimplementedKeystoreServiceServer
	devices []string
}

func (s *verdictRecordingServer) ListAttestationVerdicts(_ context.Context, r *pb.AttestationVerdictRequest) (*pb.ListAttestationVerdictsResponse, error) {
	s.devices = append(s.devices, r.GetDeviceId())
	return &pb.ListAttestationVerdictsResponse{Verdicts: []*pb.AttestationVerdict{{Tenant: "acme", DeviceId: r.GetDeviceId()}}}, nil
}

func (s *verdictRecordingServer) GetLatestAttestationVerdict(_ context.Context, r *pb.AttestationVerdictRequest) (*pb.AttestationVerdict, error) {
	s.devices = append(s.devices, r.GetDeviceId())
	return nil, status.Error(codes.NotFound, "no verdict")
}

func (s *verdictRecordingServer) ReattestDevice(_ context.Context, r *pb.AttestationVerdictRequest) (*pb.AttestationVerdict, error) {
	s.devices = append(s.devices, r.GetDeviceId())
	return AttestationVerdictToProto(sampleVerdict()), nil
}

// TestVerdictClient_OverTheWire proves each client method sends its device
// and decodes the server's answer, and a server status reaches the caller.
func TestVerdictClient_OverTheWire(t *testing.T) {
	srv := &verdictRecordingServer{}
	c := AttestationVerdictClient{Client: serveOIDC(t, srv).Client}
	ctx := context.Background()

	v, err := c.ReattestDevice(ctx, &transport.AttestationVerdictRequest{DeviceID: "dev-1"})
	require.NoError(t, err)
	assert.Equal(t, sampleVerdict(), v)

	_, err = c.GetLatestAttestationVerdict(ctx, &transport.AttestationVerdictRequest{DeviceID: "dev-2"})
	assert.Equal(t, codes.NotFound, status.Code(err))

	list, err := c.ListAttestationVerdicts(ctx, &transport.AttestationVerdictRequest{DeviceID: "dev-3"})
	require.NoError(t, err)
	require.Len(t, list.Verdicts, 1)
	assert.Equal(t, "dev-3", list.Verdicts[0].DeviceID)

	assert.Equal(t, []string{"dev-1", "dev-2", "dev-3"}, srv.devices)
}

// TestVerdictClient_NilRequests proves every method refuses a nil request
// without calling the server.
func TestVerdictClient_NilRequests(t *testing.T) {
	c := AttestationVerdictClient{}
	ctx := context.Background()
	calls := map[string]func() error{
		"list":     func() error { _, err := c.ListAttestationVerdicts(ctx, nil); return err },
		"latest":   func() error { _, err := c.GetLatestAttestationVerdict(ctx, nil); return err },
		"reattest": func() error { _, err := c.ReattestDevice(ctx, nil); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNilRequest) })
	}
}
