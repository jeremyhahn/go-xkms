package grpc

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newCredentialStrategyGRPCService returns a gRPC Service over an
// XKMSService with a manual credential service configured.
func newCredentialStrategyGRPCService(t *testing.T) (*Service, *xkms.XKMSService) {
	t.Helper()
	credSvc, err := credentialspkg.New(&credentialspkg.Config{Strategy: "manual"}, nil, nil, slog.Default())
	require.NoError(t, err)
	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetCredentialService(credSvc)
	return NewService(nil, nil, xkmsSvc), xkmsSvc
}

// GetCredentialStrategy carries every field REST's HandleGetStrategy returns,
// including the backend PIN strategy, and an empty strategy maps to an empty
// field (#2262).
func TestServiceGetCredentialStrategy_BackendPINStrategy(t *testing.T) {
	svc, xkmsSvc := newCredentialStrategyGRPCService(t)

	resp, err := svc.GetCredentialStrategy(context.Background(), &pb.GetCredentialStrategyRequest{})
	require.NoError(t, err)
	assert.Equal(t, "manual", resp.Strategy)
	assert.False(t, resp.AutoUnseal)
	assert.Empty(t, resp.BackendPinStrategy)

	xkmsSvc.SetBackendPINStrategy(func() string { return "sealed" })
	resp, err = svc.GetCredentialStrategy(context.Background(), &pb.GetCredentialStrategyRequest{})
	require.NoError(t, err)
	assert.Equal(t, "manual", resp.Strategy)
	assert.Equal(t, "sealed", resp.BackendPinStrategy)
}

func TestServiceGetCredentialStrategy_NotConfigured(t *testing.T) {
	svc := NewService(nil, nil, &xkms.XKMSService{})
	_, err := svc.GetCredentialStrategy(context.Background(), &pb.GetCredentialStrategyRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceGetCredentialStrategy_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.GetCredentialStrategy(context.Background(), &pb.GetCredentialStrategyRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}
