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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// AppraiseAttestationQuote answers with a verified result naming the
// requested reference values, so a client test can see the request arrive.
func (s *mockKeystoreServer) AppraiseAttestationQuote(_ context.Context, req *pb.AppraiseAttestationQuoteRequest) (*pb.AttestationResult, error) {
	return &pb.AttestationResult{
		Verified:        true,
		ReferenceValues: req.GetReferenceValues(),
		Checks:          []*pb.AttestationAppraisalCheck{{Name: "quote-signature", Outcome: "pass"}},
	}, nil
}

// ListAttestationReferenceValues answers with one stored baseline.
func (s *mockKeystoreServer) ListAttestationReferenceValues(context.Context, *pb.ListAttestationReferenceValuesRequest) (*pb.ListAttestationReferenceValuesResponse, error) {
	return &pb.ListAttestationReferenceValuesResponse{ReferenceValues: []*pb.AttestationReferenceValues{{Name: "golden", PcrIndices: []uint32{0, 7}}}}, nil
}

// TestAttestationAppraisal_ReachesTheServer proves a connected transport
// serves the appraisal API over its connection. The conversions themselves
// are tested once, in pkg/api/grpc/pbconv.
func TestAttestationAppraisal_ReachesTheServer(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	ctx := context.Background()

	result, err := tr.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{ReferenceValues: "golden", Nonce: []byte{1}})
	require.NoError(t, err)
	assert.True(t, result.Verified)
	assert.Equal(t, "golden", result.ReferenceValues)
	require.Len(t, result.Checks, 1)
	assert.Equal(t, "quote-signature", result.Checks[0].Name)

	list, err := tr.ListAttestationReferenceValues(ctx)
	require.NoError(t, err)
	require.Len(t, list.ReferenceValues, 1)
	assert.Equal(t, []uint32{0, 7}, list.ReferenceValues[0].PCRIndices)
}

// AppraiseAndroidKeyAttestation answers with a verified result whose check
// names the chain length, so a client test can see the chain arrive.
func (s *mockKeystoreServer) AppraiseAndroidKeyAttestation(_ context.Context, req *pb.AppraiseAndroidKeyAttestationRequest) (*pb.AttestationResult, error) {
	return &pb.AttestationResult{
		Verified: len(req.GetChainDer()) == 2,
		Checks:   []*pb.AttestationAppraisalCheck{{Name: "android-key-chain", Outcome: "pass"}},
	}, nil
}

// AppraiseEKCertificate answers with a verified result when the certificate
// and its intermediate arrive.
func (s *mockKeystoreServer) AppraiseEKCertificate(_ context.Context, req *pb.AppraiseEKCertificateRequest) (*pb.AttestationResult, error) {
	return &pb.AttestationResult{
		Verified: string(req.GetCertificateDer()) == "ek" && len(req.GetIntermediatesDer()) == 1,
		Checks:   []*pb.AttestationAppraisalCheck{{Name: "ek-certificate", Outcome: "pass"}},
	}, nil
}

// TestAttestationAppraisal_DeviceCallsReachTheServer proves a connected
// transport serves both device appraisal calls over its connection.
func TestAttestationAppraisal_DeviceCallsReachTheServer(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	ctx := context.Background()

	android, err := tr.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{ChainDER: [][]byte{[]byte("leaf"), []byte("root")}})
	require.NoError(t, err)
	assert.True(t, android.Verified)
	require.Len(t, android.Checks, 1)
	assert.Equal(t, "android-key-chain", android.Checks[0].Name)

	ek, err := tr.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{CertificateDER: []byte("ek"), IntermediatesDER: [][]byte{[]byte("ca")}})
	require.NoError(t, err)
	assert.True(t, ek.Verified)
	require.Len(t, ek.Checks, 1)
	assert.Equal(t, "ek-certificate", ek.Checks[0].Name)

	_, err = tr.AppraiseAndroidKeyAttestation(ctx, nil)
	assert.ErrorIs(t, err, pbconv.ErrNilRequest)
	_, err = tr.AppraiseEKCertificate(ctx, nil)
	assert.ErrorIs(t, err, pbconv.ErrNilRequest)
}

// TestAttestationAppraisal_NilRequests proves a connected transport refuses
// a nil request before it reaches the wire.
func TestAttestationAppraisal_NilRequests(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	ctx := context.Background()

	_, err := tr.PutAttestationEndorsement(ctx, nil)
	assert.ErrorIs(t, err, pbconv.ErrNilRequest)
	_, err = tr.ListAttestationEndorsements(ctx, nil)
	assert.ErrorIs(t, err, pbconv.ErrNilRequest)
	assert.ErrorIs(t, tr.DeleteAttestationEndorsement(ctx, nil), pbconv.ErrNilRequest)
	_, err = tr.PutAttestationReferenceValues(ctx, nil)
	assert.ErrorIs(t, err, pbconv.ErrNilRequest)
	_, err = tr.GetAttestationReferenceValues(ctx, nil)
	assert.ErrorIs(t, err, pbconv.ErrNilRequest)
	assert.ErrorIs(t, tr.DeleteAttestationReferenceValues(ctx, nil), pbconv.ErrNilRequest)
	_, err = tr.AppraiseAttestationQuote(ctx, nil)
	assert.ErrorIs(t, err, pbconv.ErrNilRequest)
}

// TestAttestationAppraisal_NotConnected proves every appraisal method
// refuses before the transport is connected.
func TestAttestationAppraisal_NotConnected(t *testing.T) {
	tr := newDisconnected(t)
	ctx := context.Background()
	calls := map[string]func() error{
		"PutAttestationEndorsement": func() error {
			_, err := tr.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{})
			return err
		},
		"ListAttestationEndorsements": func() error {
			_, err := tr.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
			return err
		},
		"DeleteAttestationEndorsement": func() error {
			return tr.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{})
		},
		"PutAttestationReferenceValues": func() error {
			_, err := tr.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{})
			return err
		},
		"GetAttestationReferenceValues": func() error {
			_, err := tr.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{})
			return err
		},
		"ListAttestationReferenceValues": func() error {
			_, err := tr.ListAttestationReferenceValues(ctx)
			return err
		},
		"DeleteAttestationReferenceValues": func() error {
			return tr.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{})
		},
		"AppraiseAttestationQuote": func() error {
			_, err := tr.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{})
			return err
		},
		"AppraiseAndroidKeyAttestation": func() error {
			_, err := tr.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{})
			return err
		},
		"AppraiseEKCertificate": func() error {
			_, err := tr.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}
