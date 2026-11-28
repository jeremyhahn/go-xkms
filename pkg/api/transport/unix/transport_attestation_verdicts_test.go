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

package unix

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// ListAttestationVerdicts answers with one verdict of the requested device.
func (s *mockKeystoreServer) ListAttestationVerdicts(_ context.Context, req *pb.AttestationVerdictRequest) (*pb.ListAttestationVerdictsResponse, error) {
	return &pb.ListAttestationVerdictsResponse{Verdicts: []*pb.AttestationVerdict{{Tenant: "acme", DeviceId: req.GetDeviceId(), Verified: true}}}, nil
}

// GetLatestAttestationVerdict answers with a verdict of the requested device.
func (s *mockKeystoreServer) GetLatestAttestationVerdict(_ context.Context, req *pb.AttestationVerdictRequest) (*pb.AttestationVerdict, error) {
	return &pb.AttestationVerdict{Tenant: "acme", DeviceId: req.GetDeviceId(), Cause: "latest"}, nil
}

// ReattestDevice answers with a fresh verdict of the requested device.
func (s *mockKeystoreServer) ReattestDevice(_ context.Context, req *pb.AttestationVerdictRequest) (*pb.AttestationVerdict, error) {
	return &pb.AttestationVerdict{Tenant: "acme", DeviceId: req.GetDeviceId(), Cause: "reattest"}, nil
}

// verdictCalls returns one call per verdict method of svc.
func verdictCalls(ctx context.Context, svc transport.AttestationVerdictService) map[string]func() error {
	req := &transport.AttestationVerdictRequest{DeviceID: "dev-1"}
	return map[string]func() error{
		"list":     func() error { _, err := svc.ListAttestationVerdicts(ctx, req); return err },
		"latest":   func() error { _, err := svc.GetLatestAttestationVerdict(ctx, req); return err },
		"reattest": func() error { _, err := svc.ReattestDevice(ctx, req); return err },
	}
}

// TestAttestationVerdicts_ReachesTheServer proves a connected transport
// serves the verdict API over its connection.
func TestAttestationVerdicts_ReachesTheServer(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	ctx := context.Background()
	req := &transport.AttestationVerdictRequest{DeviceID: "dev-1"}

	list, err := tr.ListAttestationVerdicts(ctx, req)
	require.NoError(t, err)
	require.Len(t, list.Verdicts, 1)
	assert.Equal(t, "dev-1", list.Verdicts[0].DeviceID)
	assert.True(t, list.Verdicts[0].Verified)

	latest, err := tr.GetLatestAttestationVerdict(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "latest", latest.Cause)

	fresh, err := tr.ReattestDevice(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "reattest", fresh.Cause)
	assert.Equal(t, "dev-1", fresh.DeviceID)
}

// TestAttestationVerdicts_NotConnected proves every verdict method refuses
// before the transport is connected.
func TestAttestationVerdicts_NotConnected(t *testing.T) {
	for name, call := range verdictCalls(context.Background(), newDisconnected(t)) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}
