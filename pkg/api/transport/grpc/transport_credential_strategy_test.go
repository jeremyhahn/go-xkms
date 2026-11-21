// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

func (s *mockKeystoreServer) GetCredentialStrategy(_ context.Context, _ *pb.GetCredentialStrategyRequest) (*pb.CredentialStrategyResponse, error) {
	return &pb.CredentialStrategyResponse{Strategy: "manual", AutoUnseal: true, BackendPinStrategy: "sealed"}, nil
}

func (s *errorKeystoreServer) GetCredentialStrategy(_ context.Context, _ *pb.GetCredentialStrategyRequest) (*pb.CredentialStrategyResponse, error) {
	return nil, status.Error(codes.Internal, "get credential strategy failed")
}

// The gRPC client maps the GetCredentialStrategy response, backend PIN
// strategy included, into transport.CredentialStrategyResponse (#2262).
func TestGetCredentialStrategy_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.GetCredentialStrategy(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "manual", resp.Strategy)
	assert.True(t, resp.AutoUnseal)
	assert.Equal(t, "sealed", resp.BackendPINStrategy)
}

func TestGetCredentialStrategy_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.GetCredentialStrategy(context.Background())
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}
