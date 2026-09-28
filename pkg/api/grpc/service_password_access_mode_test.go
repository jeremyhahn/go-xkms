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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// PasswordStoreSetAccessMode and mapAccessModeError had no direct tests:
// these pin the request-validation, fail-closed-with-no-service, and
// error-classification behavior the REST equivalent
// (POST /api/v1/passwords/access-mode) depends on being mirrored here.

// TestPasswordStoreSetAccessMode_RequiresMode proves a request with no mode
// (nil request or an empty Mode field) is refused before authorization or
// the service layer run.
func TestPasswordStoreSetAccessMode_RequiresMode(t *testing.T) {
	svc := newTestService()

	_, err := svc.PasswordStoreSetAccessMode(context.Background(), nil)
	assertGRPCCode(t, err, codes.InvalidArgument)

	_, err = svc.PasswordStoreSetAccessMode(context.Background(), &pb.PasswordStoreSetAccessModeRequest{})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

// TestPasswordStoreSetAccessMode_UnavailableWithNoXKMSService proves a
// well-formed request still fails closed (Unavailable, not a nil-pointer
// panic) when no xkms service is configured.
func TestPasswordStoreSetAccessMode_UnavailableWithNoXKMSService(t *testing.T) {
	svc := newTestService()
	_, err := svc.PasswordStoreSetAccessMode(context.Background(), &pb.PasswordStoreSetAccessModeRequest{Mode: "session_based"})
	assertGRPCCode(t, err, codes.Unavailable)
}

// TestMapAccessModeError_KnownSentinels pins every sentinel
// mapAccessModeError classifies before it falls through to mapPasswordError,
// including the doc comment's specific claim that an unsupported mode is a
// FailedPrecondition capability boundary, not an InvalidArgument malformed
// request.
func TestMapAccessModeError_KnownSentinels(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"nil is nil", nil, codes.OK},
		{"invalid access mode is a capability boundary", xkms.ErrInvalidAccessMode, codes.FailedPrecondition},
		{"unconfigured store", xkms.ErrNotConfigured, codes.Unavailable},
		{"nil request", xkms.ErrNilRequest, codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapAccessModeError(tt.err)
			if tt.err == nil {
				assert.NoError(t, err)
				return
			}
			assertGRPCCode(t, err, tt.want)
		})
	}
}

// TestMapAccessModeError_FallsThroughToMapPasswordError proves an error
// mapAccessModeError does not itself recognize is delegated to
// mapPasswordError rather than swallowed or defaulted to Internal directly,
// so the shared password error vocabulary (not found, already exists, ...)
// still applies to this RPC.
func TestMapAccessModeError_FallsThroughToMapPasswordError(t *testing.T) {
	err := mapAccessModeError(staticpw.ErrPasswordNotFound)
	assertGRPCCode(t, err, codes.NotFound)
}

// assertGRPCCode fails the test unless err is a gRPC status with the given
// code.
func assertGRPCCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status error, got %v", err)
	assert.Equal(t, want, st.Code())
}
