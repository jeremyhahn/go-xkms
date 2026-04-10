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
	"log/slog"
	"os"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// testBarrierLogger returns a quiet logger for test output.
func testBarrierLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// setupBarrier creates an in-memory barrier for testing and registers it
// with the package-level variable. Returns the barrier and a cleanup function.
func setupBarrier(t *testing.T) *seal.Barrier {
	t.Helper()

	base := storage.New()
	b, err := seal.NewBarrier(
		testBarrierLogger(),
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	SetBarrier(b)
	t.Cleanup(func() { SetBarrier(nil) })
	return b
}

// setupPINManager creates an in-memory PIN manager for testing
// and registers it with the package-level variable.
func setupPINManager(t *testing.T) pin.PINManager { //nolint:staticcheck // TODO: migrate to PINBackend
	t.Helper()

	backend, err := pin.NewSoftwareBackend(nil, pin.DefaultHashConfig())
	require.NoError(t, err)

	pm := &pin.PINManagerAdapter{PINBackend: backend} //nolint:staticcheck // TODO: migrate to PINBackend
	SetPINManager(pm)
	t.Cleanup(func() { SetPINManager(nil) })
	return pm
}

// newTestService returns a Service with no-op authz and audit.
func newTestService() *Service {
	return NewService(nil, nil)
}

// ==================== Setter/Getter Tests ====================

func TestSetGetBarrier(t *testing.T) {
	// Initially nil after cleanup.
	original := GetBarrier()
	defer SetBarrier(original)

	SetBarrier(nil)
	assert.Nil(t, GetBarrier())

	b := setupBarrier(t)
	assert.Equal(t, b, GetBarrier())
}

func TestSetGetPINManager(t *testing.T) {
	original := GetPINManager()
	defer SetPINManager(original)

	SetPINManager(nil)
	assert.Nil(t, GetPINManager())

	pm := setupPINManager(t)
	assert.Equal(t, pm, GetPINManager())
}

// ==================== Barrier Handler Tests ====================

func TestBarrierInitialize_Success(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()
	ctx := context.Background()

	resp, err := svc.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{
		Secret: "test-secret-123456",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)

	// Barrier should now be unsealed after init.
	assert.False(t, barrier.IsSealed())
}

func TestBarrierInitialize_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierInitialize(context.Background(), &pb.BarrierInitializeRequest{
		Secret: "test-secret-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "barrier not configured")
}

func TestBarrierInitialize_AlreadyInitialized(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()
	ctx := context.Background()

	// First init succeeds.
	_, err := svc.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{
		Secret: "test-secret-123456",
	})
	require.NoError(t, err)

	// Second init fails with AlreadyExists.
	_, err = svc.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{
		Secret: "test-secret-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())
}

func TestBarrierUnseal_Success(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()
	ctx := context.Background()
	secret := "test-secret-123456"

	// Initialize first.
	_, err := svc.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{Secret: secret})
	require.NoError(t, err)

	// Seal.
	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.True(t, barrier.IsSealed())

	// Unseal.
	_, err = svc.BarrierUnseal(ctx, &pb.BarrierUnsealRequest{Secret: secret})
	require.NoError(t, err)
	assert.False(t, barrier.IsSealed())
}

func TestBarrierUnseal_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierUnseal(context.Background(), &pb.BarrierUnsealRequest{
		Secret: "test",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierUnseal_InvalidCredentials(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()
	ctx := context.Background()

	// Initialize.
	_, err := svc.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{Secret: "correct-secret123"})
	require.NoError(t, err)

	// Seal.
	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	// Unseal with wrong credentials.
	_, err = svc.BarrierUnseal(ctx, &pb.BarrierUnsealRequest{Secret: "wrong-secret12345"})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestBarrierSeal_Success(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()
	ctx := context.Background()

	// Initialize.
	_, err := svc.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{Secret: "test-secret-123456"})
	require.NoError(t, err)
	assert.False(t, barrier.IsSealed())

	// Seal.
	resp, err := svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, barrier.IsSealed())
}

func TestBarrierSeal_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierSeal(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierSeal_Idempotent(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()
	ctx := context.Background()

	// Barrier starts sealed. Sealing again should be idempotent.
	resp, err := svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierStatus_Success(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()
	ctx := context.Background()

	// Initially sealed.
	resp, err := svc.BarrierStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.True(t, resp.Sealed)
	assert.Empty(t, resp.Strategy)

	// Initialize and check status again.
	_, err = svc.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{Secret: "test-secret-123456"})
	require.NoError(t, err)

	resp, err = svc.BarrierStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.False(t, resp.Sealed)
	assert.Equal(t, "software", resp.Strategy)
	assert.False(t, resp.HardwareBacked)
}

func TestBarrierStatus_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierStatus(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

// ==================== PIN Handler Tests ====================

func TestSetSOPIN_Success(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
	ctx := context.Background()

	resp, err := svc.SetSOPIN(ctx, &pb.SetSOPINRequest{
		CurrentSoPin: "",
		NewSoPin:     "so-pin-123456",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSetSOPIN_NotConfigured(t *testing.T) {
	SetPINManager(nil)
	defer SetPINManager(nil)
	svc := newTestService()

	_, err := svc.SetSOPIN(context.Background(), &pb.SetSOPINRequest{
		NewSoPin: "so-pin-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestSetSOPIN_TooShort(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
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
	svc := newTestService()
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
	SetPINManager(nil)
	defer SetPINManager(nil)
	svc := newTestService()

	_, err := svc.SetUserPIN(context.Background(), &pb.SetUserPINRequest{
		SoPin:      "so-pin-123456",
		NewUserPin: "user-pin-654321",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestChangeSOPIN_Success(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
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
	SetPINManager(nil)
	defer SetPINManager(nil)
	svc := newTestService()

	_, err := svc.ChangeSOPIN(context.Background(), &pb.ChangeSOPINRequest{
		CurrentSoPin: "old",
		NewSoPin:     "new-pin-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestChangeSOPIN_InvalidCurrent(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
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
	svc := newTestService()
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
	SetPINManager(nil)
	defer SetPINManager(nil)
	svc := newTestService()

	_, err := svc.ChangeUserPIN(context.Background(), &pb.ChangeUserPINRequest{
		CurrentUserPin: "old",
		NewUserPin:     "new-pin-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestVerifySOPIN_Success(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
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
	SetPINManager(nil)
	defer SetPINManager(nil)
	svc := newTestService()

	_, err := svc.VerifySOPIN(context.Background(), &pb.VerifySOPINRequest{
		SoPin: "test-pin-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestVerifySOPIN_Invalid(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
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
	svc := newTestService()
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
	SetPINManager(nil)
	defer SetPINManager(nil)
	svc := newTestService()

	_, err := svc.VerifyUserPIN(context.Background(), &pb.VerifyUserPINRequest{
		UserPin: "test-pin-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestVerifyUserPIN_Invalid(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
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
	svc := newTestService()
	ctx := context.Background()

	resp, err := svc.GetLockoutStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.IsLocked)
	assert.Equal(t, int32(0), resp.FailedAttempts)
	assert.Equal(t, int32(0), resp.MaxAttempts) // SoftwareBackend does not track lockout.
}

func TestGetLockoutStatus_NotConfigured(t *testing.T) {
	SetPINManager(nil)
	defer SetPINManager(nil)
	svc := newTestService()

	_, err := svc.GetLockoutStatus(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestResetLockout_Success(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
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
	SetPINManager(nil)
	defer SetPINManager(nil)
	svc := newTestService()

	_, err := svc.ResetLockout(context.Background(), &pb.ResetLockoutRequest{
		SoPin: "test-pin-123456",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestResetLockout_InvalidSOPIN(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
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

func TestMapBarrierError_NilReturnsNil(t *testing.T) {
	assert.Nil(t, mapBarrierError(nil, "test"))
}

func TestMapBarrierError_KnownErrors(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode codes.Code
	}{
		{"sealed", seal.ErrSealed, codes.FailedPrecondition},
		{"already_unsealed", seal.ErrAlreadyUnsealed, codes.AlreadyExists},
		{"already_initialized", seal.ErrAlreadyInitialized, codes.AlreadyExists},
		{"not_initialized", seal.ErrNotInitialized, codes.FailedPrecondition},
		{"invalid_credentials", seal.ErrInvalidCredentials, codes.Unauthenticated},
		{"no_available_strategy", seal.ErrNoAvailableStrategy, codes.Unavailable},
		{"strategy_not_found", seal.ErrStrategyNotFound, codes.NotFound},
		{"corrupt_root_key", seal.ErrCorruptRootKey, codes.DataLoss},
		{"encryptor_not_available", seal.ErrEncryptorNotAvailable, codes.FailedPrecondition},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := mapBarrierError(tt.err, "test")
			st, ok := status.FromError(grpcErr)
			require.True(t, ok)
			assert.Equal(t, tt.expectedCode, st.Code())
		})
	}
}

func TestMapPINError_NilReturnsNil(t *testing.T) {
	assert.Nil(t, mapPINError(nil, "test"))
}

func TestMapPINError_KnownErrors(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode codes.Code
	}{
		{"pin_not_set", pin.ErrPINNotSet, codes.FailedPrecondition},
		{"pin_locked", pin.ErrPINLocked, codes.ResourceExhausted},
		{"pin_invalid", pin.ErrPINInvalid, codes.Unauthenticated},
		{"so_pin_required", pin.ErrSOPINRequired, codes.Unauthenticated},
		{"pin_too_short", pin.ErrPINTooShort, codes.InvalidArgument},
		{"pin_already_set", pin.ErrPINAlreadySet, codes.AlreadyExists},
		{"invalid_current_pin", pin.ErrInvalidCurrentPIN, codes.Unauthenticated},
		{"state_corrupted", pin.ErrStateCorrupted, codes.DataLoss},
		{"strategy_not_set", pin.ErrStrategyNotSet, codes.FailedPrecondition},
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

// TestMapBarrierError_UnknownError verifies that unknown errors map to Internal.
func TestMapBarrierError_UnknownError(t *testing.T) {
	unknownErr := assert.AnError
	grpcErr := mapBarrierError(unknownErr, "test")
	st, ok := status.FromError(grpcErr)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
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

func TestBarrier_FullLifecycle(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()
	ctx := context.Background()
	secret := "lifecycle-secret-123"

	// 1. Status: sealed, no strategy.
	statusResp, err := svc.BarrierStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.True(t, statusResp.Sealed)

	// 2. Initialize.
	_, err = svc.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{Secret: secret})
	require.NoError(t, err)

	// 3. Status: unsealed, software strategy.
	statusResp, err = svc.BarrierStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.False(t, statusResp.Sealed)
	assert.Equal(t, "software", statusResp.Strategy)

	// 4. Seal.
	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	// 5. Status: sealed.
	statusResp, err = svc.BarrierStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.True(t, statusResp.Sealed)

	// 6. Unseal.
	_, err = svc.BarrierUnseal(ctx, &pb.BarrierUnsealRequest{Secret: secret})
	require.NoError(t, err)

	// 7. Status: unsealed.
	statusResp, err = svc.BarrierStatus(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.False(t, statusResp.Sealed)
}

func TestPIN_FullLifecycle(t *testing.T) {
	setupPINManager(t)
	svc := newTestService()
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
