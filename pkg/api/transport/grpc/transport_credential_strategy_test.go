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
