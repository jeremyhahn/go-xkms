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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// The barrier and PIN backend the barrier and PIN tests compose onto the
// XKMSService newPlatformTestService serves over. The RPCs reach both only
// through the service, which is where the platform scope is enforced.
var (
	testPINManager qrdbsdk.PINBackend
)

// newPlatformTestService returns a Service (no-op authz and audit) over an
// XKMSService composed with the current testBarrier and testPINManager; either
// may be nil, which the service reports as not configured.
func newPlatformTestService() *Service {
	svc := &xkms.XKMSService{}
	svc.SetPINManager(testPINManager)
	return NewService(nil, nil, svc)
}

// setupPINManager creates an in-memory PIN backend for testing and composes
// it as the PIN backend newPlatformTestService serves over.
func setupPINManager(t *testing.T) qrdbsdk.PINBackend {
	t.Helper()

	backend, err := qrdbsdk.NewSoftwareBackend(nil, qrdbsdk.DefaultHashConfig())
	require.NoError(t, err)

	useTestPINManager(t, backend)
	return backend
}

// useTestPINManager composes pm as the PIN backend newPlatformTestService
// serves over, for the duration of the test.
func useTestPINManager(t *testing.T, pm qrdbsdk.PINBackend) {
	t.Helper()
	testPINManager = pm
	t.Cleanup(func() { testPINManager = nil })
}

// newTestService returns a Service with no-op authz and audit.
func newTestService() *Service {
	return NewService(nil, nil, nil)
}

// ==================== Barrier Handler Tests ====================

// ==================== PIN Handler Tests ====================

func TestSetSOPIN_Success(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	resp, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{
		CurrentSoPin: "",
		NewSoPin:     "so-pin-123456",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSetSOPIN_NotConfigured(t *testing.T) {
	svc := newPlatformTestService()

	_, err := svc.SetSOPIN(context.Background(), &pb.SetSOPINRequest{
		NewSoPin: "so-pin-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestSetSOPIN_TooShort(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	_, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{
		NewSoPin: "123", // Too short (min 6 chars).
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestSetUserPIN_Success(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	// Must set SO PIN first.
	_, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{
		NewSoPin: "so-pin-123456",
	})
	require.NoError(t, err)

	// Now set user PIN using SO PIN authorization.
	resp, err := svc.SetUserPIN(ctx, &pb.SetUserPINRequest{
		SoPin:      "so-pin-123456",
		NewUserPin: "user-pin-654321",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSetUserPIN_NotConfigured(t *testing.T) {
	svc := newPlatformTestService()

	_, err := svc.SetUserPIN(context.Background(), &pb.SetUserPINRequest{
		SoPin:      "so-pin-123456",
		NewUserPin: "user-pin-654321",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestChangeSOPIN_Success(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	// Set initial SO PIN.
	_, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{
		NewSoPin: "so-pin-123456",
	})
	require.NoError(t, err)

	// Change SO PIN.
	resp, err := svc.ChangeSOPIN(ctx, &pb.ChangeSOPINRequest{
		CurrentSoPin: "so-pin-123456",
		NewSoPin:     "new-so-pin-789",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestChangeSOPIN_NotConfigured(t *testing.T) {
	svc := newPlatformTestService()

	_, err := svc.ChangeSOPIN(context.Background(), &pb.ChangeSOPINRequest{
		CurrentSoPin: "old",
		NewSoPin:     "new-pin-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestChangeSOPIN_InvalidCurrent(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	// Set initial SO PIN.
	_, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{
		NewSoPin: "so-pin-123456",
	})
	require.NoError(t, err)

	// Change with wrong current PIN.
	_, err = svc.ChangeSOPIN(ctx, &pb.ChangeSOPINRequest{
		CurrentSoPin: "wrong-pin-00000",
		NewSoPin:     "new-so-pin-789",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestChangeUserPIN_Success(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	soPIN := "so-pin-123456"
	userPIN := "user-pin-654321"

	// Set SO PIN and user PIN.
	_, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{NewSoPin: soPIN})
	require.NoError(t, err)
	_, err = svc.SetUserPIN(ctx, &pb.SetUserPINRequest{SoPin: soPIN, NewUserPin: userPIN})
	require.NoError(t, err)

	// Change user PIN.
	resp, err := svc.ChangeUserPIN(ctx, &pb.ChangeUserPINRequest{
		CurrentUserPin: userPIN,
		NewUserPin:     "new-user-pin-000",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestChangeUserPIN_NotConfigured(t *testing.T) {
	svc := newPlatformTestService()

	_, err := svc.ChangeUserPIN(context.Background(), &pb.ChangeUserPINRequest{
		CurrentUserPin: "old",
		NewUserPin:     "new-pin-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestVerifySOPIN_Success(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	soPIN := "so-pin-123456"

	// Set SO PIN.
	_, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{NewSoPin: soPIN})
	require.NoError(t, err)

	// Verify correct SO PIN.
	resp, err := svc.VerifySOPIN(ctx, &pb.VerifySOPINRequest{SoPin: soPIN})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestVerifySOPIN_NotConfigured(t *testing.T) {
	svc := newPlatformTestService()

	_, err := svc.VerifySOPIN(context.Background(), &pb.VerifySOPINRequest{
		SoPin: "test-pin-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestVerifySOPIN_Invalid(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	// Set SO PIN.
	_, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{NewSoPin: "so-pin-123456"})
	require.NoError(t, err)

	// Verify wrong SO PIN.
	_, err = svc.VerifySOPIN(ctx, &pb.VerifySOPINRequest{SoPin: "wrong-pin-00000"})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestVerifyUserPIN_Success(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	soPIN := "so-pin-123456"
	userPIN := "user-pin-654321"

	// Set SO PIN and user PIN.
	_, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{NewSoPin: soPIN})
	require.NoError(t, err)
	_, err = svc.SetUserPIN(ctx, &pb.SetUserPINRequest{SoPin: soPIN, NewUserPin: userPIN})
	require.NoError(t, err)

	// Verify correct user PIN.
	resp, err := svc.VerifyUserPIN(ctx, &pb.VerifyUserPINRequest{UserPin: userPIN})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestVerifyUserPIN_NotConfigured(t *testing.T) {
	svc := newPlatformTestService()

	_, err := svc.VerifyUserPIN(context.Background(), &pb.VerifyUserPINRequest{
		UserPin: "test-pin-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestVerifyUserPIN_Invalid(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	soPIN := "so-pin-123456"
	userPIN := "user-pin-654321"

	// Set SO PIN and user PIN.
	_, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{NewSoPin: soPIN})
	require.NoError(t, err)
	_, err = svc.SetUserPIN(ctx, &pb.SetUserPINRequest{SoPin: soPIN, NewUserPin: userPIN})
	require.NoError(t, err)

	// Verify wrong user PIN.
	_, err = svc.VerifyUserPIN(ctx, &pb.VerifyUserPINRequest{UserPin: "wrong-pin-00000"})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestGetLockoutStatus_Success(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	resp, err := svc.GetLockoutStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.IsLocked)
	assert.Equal(t, int32(0), resp.FailedAttempts)
	assert.Equal(t, int32(0), resp.MaxAttempts) // SoftwareBackend does not track lockout.
}

func TestGetLockoutStatus_NotConfigured(t *testing.T) {
	svc := newPlatformTestService()

	_, err := svc.GetLockoutStatus(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestResetLockout_Success(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	soPIN := "so-pin-123456"

	// Set SO PIN.
	_, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{NewSoPin: soPIN})
	require.NoError(t, err)

	// Reset lockout.
	resp, err := svc.ResetLockout(ctx, &pb.ResetLockoutRequest{SoPin: soPIN})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestResetLockout_NotConfigured(t *testing.T) {
	svc := newPlatformTestService()

	_, err := svc.ResetLockout(context.Background(), &pb.ResetLockoutRequest{
		SoPin: "test-pin-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestResetLockout_InvalidSOPIN(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	// Set SO PIN.
	_, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{NewSoPin: "so-pin-123456"})
	require.NoError(t, err)

	// SoftwareBackend has no lockout mechanism, so ResetLockout is a no-op
	// that succeeds regardless of SO PIN. Backends with lockout support
	// (e.g., TPM2Backend) would return Unauthenticated for wrong SO PIN.
	_, err = svc.ResetLockout(ctx, &pb.ResetLockoutRequest{SoPin: "wrong-pin-00000"})
	require.NoError(t, err)
}

// ==================== Error Mapping Tests ====================

func TestMapPINError_NilReturnsNil(t *testing.T) {
	assert.Nil(t, mapPINError(nil, "test"))
}

func TestMapPINError_KnownErrors(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode codes.Code
	}{
		{"pin_not_set", qrdbsdk.ErrPINNotSet, codes.FailedPrecondition},
		{"pin_locked", qrdbsdk.ErrPINLocked, codes.ResourceExhausted},
		{"pin_invalid", qrdbsdk.ErrPINInvalid, codes.Unauthenticated},
		{"so_pin_required", qrdbsdk.ErrSOPINRequired, codes.Unauthenticated},
		{"pin_too_short", qrdbsdk.ErrPINTooShort, codes.InvalidArgument},
		{"pin_already_set", qrdbsdk.ErrPINAlreadySet, codes.AlreadyExists},
		{"invalid_current_pin", qrdbsdk.ErrInvalidCurrentPIN, codes.Unauthenticated},
		{"state_corrupted", qrdbsdk.ErrPINStateCorrupted, codes.DataLoss},
		{"strategy_not_set", qrdbsdk.ErrPINStrategyNotSet, codes.FailedPrecondition},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := mapPINError(tt.err, "test")
			st, ok := status.FromError(grpcErr)
			require.True(t, ok)
			assert.Equal(t, tt.expectedCode, st.Code())
		})
	}
}

// TestMapPINError_UnknownError verifies that unknown errors map to Internal.
func TestMapPINError_UnknownError(t *testing.T) {
	unknownErr := assert.AnError
	grpcErr := mapPINError(unknownErr, "test")
	st, ok := status.FromError(grpcErr)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

// ==================== Full Lifecycle Integration ====================

func TestPIN_FullLifecycle(t *testing.T) {
	setupPINManager(t)
	svc := newPlatformTestService()
	ctx := context.Background()

	soPIN := "so-pin-123456"
	userPIN := "user-pin-654321"

	// 1. Check lockout status: clean.
	lockout, err := svc.GetLockoutStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, int32(0), lockout.FailedAttempts)
	assert.False(t, lockout.IsLocked)

	// 2. Set SO PIN.
	_, err = svc.SetSOPIN(ctx, &pb.SetSOPINRequest{NewSoPin: soPIN})
	require.NoError(t, err)

	// 3. Set User PIN.
	_, err = svc.SetUserPIN(ctx, &pb.SetUserPINRequest{SoPin: soPIN, NewUserPin: userPIN})
	require.NoError(t, err)

	// 4. Verify SO PIN.
	_, err = svc.VerifySOPIN(ctx, &pb.VerifySOPINRequest{SoPin: soPIN})
	require.NoError(t, err)

	// 5. Verify User PIN.
	_, err = svc.VerifyUserPIN(ctx, &pb.VerifyUserPINRequest{UserPin: userPIN})
	require.NoError(t, err)

	// 6. Change SO PIN.
	newSoPIN := "new-so-pin-789"
	_, err = svc.ChangeSOPIN(ctx, &pb.ChangeSOPINRequest{
		CurrentSoPin: soPIN,
		NewSoPin:     newSoPIN,
	})
	require.NoError(t, err)

	// 7. Verify new SO PIN works.
	_, err = svc.VerifySOPIN(ctx, &pb.VerifySOPINRequest{SoPin: newSoPIN})
	require.NoError(t, err)

	// 8. Change User PIN.
	newUserPIN := "new-user-pin-000"
	_, err = svc.ChangeUserPIN(ctx, &pb.ChangeUserPINRequest{
		CurrentUserPin: userPIN,
		NewUserPin:     newUserPIN,
	})
	require.NoError(t, err)

	// 9. Verify new User PIN works.
	_, err = svc.VerifyUserPIN(ctx, &pb.VerifyUserPINRequest{UserPin: newUserPIN})
	require.NoError(t, err)

	// 10. Reset lockout.
	_, err = svc.ResetLockout(ctx, &pb.ResetLockoutRequest{SoPin: newSoPIN})
	require.NoError(t, err)
}
