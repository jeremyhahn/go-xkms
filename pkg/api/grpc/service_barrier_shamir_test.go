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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// setupShamirBarrier creates a barrier with StrategyShamir registered and
// Shamir config enabled. Returns the barrier and the share storage backend.
func setupShamirBarrier(t *testing.T, threshold, total int) *seal.Barrier {
	t.Helper()

	base := storage.New()
	shareStore := storage.New()

	shamirStrat, err := seal.NewShamirStrategy(shareStore, threshold, total)
	require.NoError(t, err)

	b, err := seal.NewBarrier(
		testBarrierLogger(),
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategyShamir},
			Shamir: &seal.ShamirConfig{
				Threshold:   threshold,
				TotalShares: total,
			},
		},
		shamirStrat,
	)
	require.NoError(t, err)

	SetBarrier(b)
	t.Cleanup(func() { SetBarrier(nil) })
	return b
}

// setupCredentialShamirBarrier creates a barrier with StrategySoftware that
// uses credential-mode Shamir (the password is split into shares).
func setupCredentialShamirBarrier(t *testing.T, threshold, total int) *seal.Barrier {
	t.Helper()

	base := storage.New()
	b, err := seal.NewBarrier(
		testBarrierLogger(),
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
			Shamir: &seal.ShamirConfig{
				Threshold:   threshold,
				TotalShares: total,
			},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	SetBarrier(b)
	t.Cleanup(func() { SetBarrier(nil) })
	return b
}

// ==================== BarrierInitializeShamir Tests ====================

func TestBarrierInitializeShamir_Success(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	resp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Shares, 3)
	assert.Equal(t, int32(2), resp.Threshold)
	assert.Equal(t, int32(3), resp.TotalShares)

	// Barrier should be unsealed after initialization.
	assert.False(t, barrier.IsSealed())
}

func TestBarrierInitializeShamir_CredentialMode(t *testing.T) {
	setupCredentialShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	resp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{
		Secret: "test-secret-123456",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Shares, 3)
	assert.Equal(t, int32(2), resp.Threshold)
	assert.Equal(t, int32(3), resp.TotalShares)
}

func TestBarrierInitializeShamir_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierInitializeShamir(context.Background(), &pb.BarrierInitializeShamirRequest{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "barrier not configured")
}

func TestBarrierInitializeShamir_AlreadyInitialized(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	// First init succeeds.
	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Second init fails.
	_, err = svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())
}

func TestBarrierInitializeShamir_NoShamirConfig(t *testing.T) {
	// Create a barrier without Shamir config.
	setupBarrier(t)
	svc := newTestService()

	_, err := svc.BarrierInitializeShamir(context.Background(), &pb.BarrierInitializeShamirRequest{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

// ==================== BarrierUnsealShare Tests ====================

func TestBarrierUnsealShare_Success(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	// Initialize to get shares.
	initResp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)
	shares := initResp.Shares

	// Seal the barrier.
	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.True(t, barrier.IsSealed())

	// Submit first share -- not yet complete.
	resp, err := svc.BarrierUnsealShare(ctx, &pb.BarrierUnsealShareRequest{
		Share: shares[0],
	})
	require.NoError(t, err)
	assert.Equal(t, int32(2), resp.Required)
	assert.Equal(t, int32(1), resp.Submitted)
	assert.False(t, resp.Complete)
	assert.True(t, barrier.IsSealed())

	// Submit second share -- quorum reached, barrier unseals.
	resp, err = svc.BarrierUnsealShare(ctx, &pb.BarrierUnsealShareRequest{
		Share: shares[1],
	})
	require.NoError(t, err)
	assert.True(t, resp.Complete)
	assert.False(t, barrier.IsSealed())
}

func TestBarrierUnsealShare_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierUnsealShare(context.Background(), &pb.BarrierUnsealShareRequest{
		Share: "some-share",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierUnsealShare_DuplicateShare(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	initResp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)
	shares := initResp.Shares

	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	// Submit first share.
	_, err = svc.BarrierUnsealShare(ctx, &pb.BarrierUnsealShareRequest{
		Share: shares[0],
	})
	require.NoError(t, err)

	// Submit same share again -- duplicate.
	_, err = svc.BarrierUnsealShare(ctx, &pb.BarrierUnsealShareRequest{
		Share: shares[0],
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())
}

func TestBarrierUnsealShare_AlreadyUnsealed(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	initResp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Barrier is already unsealed after init. Submitting a share should error.
	_, err = svc.BarrierUnsealShare(ctx, &pb.BarrierUnsealShareRequest{
		Share: initResp.Shares[0],
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())
}

// ==================== BarrierUnsealShares Tests ====================

func TestBarrierUnsealShares_Success(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	initResp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Seal the barrier.
	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.True(t, barrier.IsSealed())

	// Unseal with all shares at once.
	resp, err := svc.BarrierUnsealShares(ctx, &pb.BarrierUnsealSharesRequest{
		Shares: initResp.Shares[:2], // Only need threshold (2) shares.
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, barrier.IsSealed())
}

func TestBarrierUnsealShares_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierUnsealShares(context.Background(), &pb.BarrierUnsealSharesRequest{
		Shares: []string{"share1", "share2"},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierUnsealShares_InsufficientShares(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	initResp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	// Only provide one share when threshold is 2.
	_, err = svc.BarrierUnsealShares(ctx, &pb.BarrierUnsealSharesRequest{
		Shares: initResp.Shares[:1],
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierUnsealShares_AlreadyUnsealed(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	initResp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Barrier is unsealed. Attempt to unseal again.
	_, err = svc.BarrierUnsealShares(ctx, &pb.BarrierUnsealSharesRequest{
		Shares: initResp.Shares[:2],
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())
}

// ==================== BarrierShamirListShares Tests ====================

func TestBarrierShamirListShares_Success(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	// Initialize to create shares.
	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	resp, err := svc.BarrierShamirListShares(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, int32(3), resp.Count)
	assert.Equal(t, int32(2), resp.Threshold)
	assert.Equal(t, int32(3), resp.Total)
}

func TestBarrierShamirListShares_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierShamirListShares(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "barrier not configured")
}

func TestBarrierShamirListShares_NoShamirStrategy(t *testing.T) {
	// Create a barrier without Shamir strategy.
	setupBarrier(t)
	svc := newTestService()

	_, err := svc.BarrierShamirListShares(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "shamir not configured")
}

// ==================== BarrierShamirDeleteShare Tests ====================

func TestBarrierShamirDeleteShare_Success(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Delete share at index 1.
	resp, err := svc.BarrierShamirDeleteShare(ctx, &pb.BarrierShamirDeleteShareRequest{
		Index: 1,
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)

	// Verify count decreased.
	listResp, err := svc.BarrierShamirListShares(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, int32(2), listResp.Count)
}

func TestBarrierShamirDeleteShare_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierShamirDeleteShare(context.Background(), &pb.BarrierShamirDeleteShareRequest{
		Index: 1,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierShamirDeleteShare_NoShamirStrategy(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()

	_, err := svc.BarrierShamirDeleteShare(context.Background(), &pb.BarrierShamirDeleteShareRequest{
		Index: 1,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierShamirDeleteShare_NotFound(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Delete a non-existent share index.
	_, err = svc.BarrierShamirDeleteShare(ctx, &pb.BarrierShamirDeleteShareRequest{
		Index: 99,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ==================== BarrierShamirDeleteAllShares Tests ====================

func TestBarrierShamirDeleteAllShares_Success(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	resp, err := svc.BarrierShamirDeleteAllShares(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, resp)

	// Verify all shares are gone.
	listResp, err := svc.BarrierShamirListShares(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, int32(0), listResp.Count)
}

func TestBarrierShamirDeleteAllShares_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierShamirDeleteAllShares(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierShamirDeleteAllShares_NoShamirStrategy(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()

	_, err := svc.BarrierShamirDeleteAllShares(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

// ==================== BarrierShamirVerify Tests ====================

func TestBarrierShamirVerify_Success(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	resp, err := svc.BarrierShamirVerify(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierShamirVerify_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierShamirVerify(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierShamirVerify_NoShamirStrategy(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()

	_, err := svc.BarrierShamirVerify(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierShamirVerify_FailsAfterShareDeletion(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Delete all shares, then verify should fail.
	_, err = svc.BarrierShamirDeleteAllShares(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	_, err = svc.BarrierShamirVerify(ctx, &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ==================== BarrierRekey Tests ====================

func TestBarrierRekey_Success(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Rekey with new parameters.
	resp, err := svc.BarrierRekey(ctx, &pb.BarrierRekeyRequest{
		Threshold: 3,
		Total:     5,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Shares, 5)
	assert.Equal(t, int32(3), resp.Threshold)
	assert.Equal(t, int32(5), resp.TotalShares)

	// Verify share count reflects new total.
	listResp, err := svc.BarrierShamirListShares(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, int32(5), listResp.Count)
	assert.Equal(t, int32(3), listResp.Threshold)
	assert.Equal(t, int32(5), listResp.Total)
}

func TestBarrierRekey_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierRekey(context.Background(), &pb.BarrierRekeyRequest{
		Threshold: 2,
		Total:     3,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierRekey_InvalidThreshold(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Threshold of 1 is invalid (must be >= 2).
	_, err = svc.BarrierRekey(ctx, &pb.BarrierRekeyRequest{
		Threshold: 1,
		Total:     3,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestBarrierRekey_ThresholdExceedsTotal(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Threshold > total is invalid.
	_, err = svc.BarrierRekey(ctx, &pb.BarrierRekeyRequest{
		Threshold: 5,
		Total:     3,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestBarrierRekey_Sealed(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	// Rekey should fail when sealed.
	_, err = svc.BarrierRekey(ctx, &pb.BarrierRekeyRequest{
		Threshold: 2,
		Total:     3,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierRekey_NoShamirStrategy(t *testing.T) {
	setupBarrier(t)
	svc := newTestService()
	ctx := context.Background()

	// Initialize with software strategy.
	_, err := svc.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{Secret: "test-secret-123456"})
	require.NoError(t, err)

	// Rekey should fail because no ShamirStrategy is registered.
	_, err = svc.BarrierRekey(ctx, &pb.BarrierRekeyRequest{
		Threshold: 2,
		Total:     3,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

// ==================== BarrierGenerateRecoveryKeys Tests ====================

func TestBarrierGenerateRecoveryKeys_Success(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	resp, err := svc.BarrierGenerateRecoveryKeys(ctx, &pb.BarrierGenerateRecoveryKeysRequest{
		Threshold: 2,
		Total:     5,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Shares, 5)
	assert.Equal(t, int32(2), resp.Threshold)
	assert.Equal(t, int32(5), resp.TotalShares)
}

func TestBarrierGenerateRecoveryKeys_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierGenerateRecoveryKeys(context.Background(), &pb.BarrierGenerateRecoveryKeysRequest{
		Threshold: 2,
		Total:     3,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierGenerateRecoveryKeys_InvalidThreshold(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Threshold of 1 is invalid.
	_, err = svc.BarrierGenerateRecoveryKeys(ctx, &pb.BarrierGenerateRecoveryKeysRequest{
		Threshold: 1,
		Total:     3,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestBarrierGenerateRecoveryKeys_ThresholdExceedsTotal(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	_, err = svc.BarrierGenerateRecoveryKeys(ctx, &pb.BarrierGenerateRecoveryKeysRequest{
		Threshold: 5,
		Total:     3,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestBarrierGenerateRecoveryKeys_Sealed(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	// Barrier is sealed (not initialized). Recovery keys need an unsealed barrier.
	_, err := svc.BarrierGenerateRecoveryKeys(ctx, &pb.BarrierGenerateRecoveryKeysRequest{
		Threshold: 2,
		Total:     3,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

// ==================== BarrierRecoverWithKeys Tests ====================

func TestBarrierRecoverWithKeys_Success(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Generate recovery keys.
	recoveryResp, err := svc.BarrierGenerateRecoveryKeys(ctx, &pb.BarrierGenerateRecoveryKeysRequest{
		Threshold: 2,
		Total:     3,
	})
	require.NoError(t, err)

	// Seal the barrier.
	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.True(t, barrier.IsSealed())

	// Recover with the recovery keys.
	resp, err := svc.BarrierRecoverWithKeys(ctx, &pb.BarrierRecoverWithKeysRequest{
		Keys: recoveryResp.Shares[:2],
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, barrier.IsSealed())
}

func TestBarrierRecoverWithKeys_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierRecoverWithKeys(context.Background(), &pb.BarrierRecoverWithKeysRequest{
		Keys: []string{"key1", "key2"},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierRecoverWithKeys_NoRecoveryKeys(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	// Recovery without generating keys should fail.
	_, err = svc.BarrierRecoverWithKeys(ctx, &pb.BarrierRecoverWithKeysRequest{
		Keys: []string{"fake1", "fake2"},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestBarrierRecoverWithKeys_AlreadyUnsealed(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Generate recovery keys while unsealed.
	recoveryResp, err := svc.BarrierGenerateRecoveryKeys(ctx, &pb.BarrierGenerateRecoveryKeysRequest{
		Threshold: 2,
		Total:     3,
	})
	require.NoError(t, err)

	// Barrier is unsealed. Attempting to recover should fail.
	_, err = svc.BarrierRecoverWithKeys(ctx, &pb.BarrierRecoverWithKeysRequest{
		Keys: recoveryResp.Shares[:2],
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())
}

// ==================== BarrierDeleteRecoveryKeys Tests ====================

func TestBarrierDeleteRecoveryKeys_Success(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Generate recovery keys.
	_, err = svc.BarrierGenerateRecoveryKeys(ctx, &pb.BarrierGenerateRecoveryKeysRequest{
		Threshold: 2,
		Total:     3,
	})
	require.NoError(t, err)

	// Delete recovery keys.
	resp, err := svc.BarrierDeleteRecoveryKeys(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestBarrierDeleteRecoveryKeys_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierDeleteRecoveryKeys(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierDeleteRecoveryKeys_Sealed(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	// Barrier is sealed (not initialized). Deleting recovery keys should fail.
	_, err := svc.BarrierDeleteRecoveryKeys(ctx, &emptypb.Empty{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

// ==================== BarrierGenerateRootToken Tests ====================

func TestBarrierGenerateRootToken_Success(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	initResp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	resp, err := svc.BarrierGenerateRootToken(ctx, &pb.BarrierGenerateRootTokenRequest{
		Shares: initResp.Shares[:2],
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.CreatedAt)
}

func TestBarrierGenerateRootToken_NotConfigured(t *testing.T) {
	SetBarrier(nil)
	defer SetBarrier(nil)
	svc := newTestService()

	_, err := svc.BarrierGenerateRootToken(context.Background(), &pb.BarrierGenerateRootTokenRequest{
		Shares: []string{"share1", "share2"},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierGenerateRootToken_InsufficientShares(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	initResp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Only provide one share when threshold is 2.
	_, err = svc.BarrierGenerateRootToken(ctx, &pb.BarrierGenerateRootTokenRequest{
		Shares: initResp.Shares[:1],
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestBarrierGenerateRootToken_InvalidShares(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Provide invalid (fabricated) shares.
	_, err = svc.BarrierGenerateRootToken(ctx, &pb.BarrierGenerateRootTokenRequest{
		Shares: []string{"invalid-share-1", "invalid-share-2"},
	})
	require.Error(t, err)
}

func TestBarrierGenerateRootToken_UniqueTokens(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	initResp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Generate two tokens and verify they are different (randomness).
	resp1, err := svc.BarrierGenerateRootToken(ctx, &pb.BarrierGenerateRootTokenRequest{
		Shares: initResp.Shares[:2],
	})
	require.NoError(t, err)

	resp2, err := svc.BarrierGenerateRootToken(ctx, &pb.BarrierGenerateRootTokenRequest{
		Shares: initResp.Shares[:2],
	})
	require.NoError(t, err)

	assert.NotEqual(t, resp1.Token, resp2.Token)
}

func TestBarrierGenerateRootToken_CredentialMode(t *testing.T) {
	setupCredentialShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	initResp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{
		Secret: "test-secret-123456",
	})
	require.NoError(t, err)

	resp, err := svc.BarrierGenerateRootToken(ctx, &pb.BarrierGenerateRootTokenRequest{
		Shares: initResp.Shares[:2],
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.CreatedAt)
}

// ==================== Error Mapping Tests ====================

func TestBarrierErrorMapping_ShamirErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{
			name:     "ShamirNotConfigured",
			err:      seal.ErrShamirNotConfigured,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "ShamirThresholdInvalid",
			err:      seal.ErrShamirThresholdInvalid,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "ShamirQuorumIncomplete",
			err:      seal.ErrShamirQuorumIncomplete,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "ShamirQuorumExpired",
			err:      seal.ErrShamirQuorumExpired,
			wantCode: codes.DeadlineExceeded,
		},
		{
			name:     "ShamirDuplicateShare",
			err:      seal.ErrShamirDuplicateShare,
			wantCode: codes.AlreadyExists,
		},
		{
			name:     "ShamirCombineFailed",
			err:      seal.ErrShamirCombineFailed,
			wantCode: codes.Internal,
		},
		{
			name:     "ShamirShareNotFound",
			err:      seal.ErrShamirShareNotFound,
			wantCode: codes.NotFound,
		},
		{
			name:     "ShamirNoSharesFound",
			err:      seal.ErrShamirNoSharesFound,
			wantCode: codes.NotFound,
		},
		{
			name:     "ShamirVerificationFailed",
			err:      seal.ErrShamirVerificationFailed,
			wantCode: codes.DataLoss,
		},
		{
			name:     "ShamirStorageFailed",
			err:      seal.ErrShamirStorageFailed,
			wantCode: codes.Internal,
		},
		{
			name:     "RecoveryKeysNotFound",
			err:      seal.ErrRecoveryKeysNotFound,
			wantCode: codes.NotFound,
		},
		{
			name:     "RootTokenVerificationFailed",
			err:      seal.ErrRootTokenVerificationFailed,
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := mapBarrierError(tt.err, "test operation")
			st, ok := status.FromError(grpcErr)
			require.True(t, ok)
			assert.Equal(t, tt.wantCode, st.Code())
			assert.Contains(t, st.Message(), "test operation")
		})
	}
}

// ==================== Full Lifecycle Tests ====================

func TestBarrierShamir_FullLifecycle(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	// 1. Initialize with Shamir.
	initResp, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)
	assert.Len(t, initResp.Shares, 3)

	// 2. Verify shares are valid.
	_, err = svc.BarrierShamirVerify(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	// 3. List shares.
	listResp, err := svc.BarrierShamirListShares(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, int32(3), listResp.Count)

	// 4. Generate recovery keys.
	recoveryResp, err := svc.BarrierGenerateRecoveryKeys(ctx, &pb.BarrierGenerateRecoveryKeysRequest{
		Threshold: 2,
		Total:     3,
	})
	require.NoError(t, err)
	assert.Len(t, recoveryResp.Shares, 3)

	// 5. Generate root token.
	tokenResp, err := svc.BarrierGenerateRootToken(ctx, &pb.BarrierGenerateRootTokenRequest{
		Shares: initResp.Shares[:2],
	})
	require.NoError(t, err)
	assert.NotEmpty(t, tokenResp.Token)

	// 6. Seal the barrier.
	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.True(t, barrier.IsSealed())

	// 7. Unseal with shares one at a time.
	progress, err := svc.BarrierUnsealShare(ctx, &pb.BarrierUnsealShareRequest{
		Share: initResp.Shares[0],
	})
	require.NoError(t, err)
	assert.False(t, progress.Complete)

	progress, err = svc.BarrierUnsealShare(ctx, &pb.BarrierUnsealShareRequest{
		Share: initResp.Shares[1],
	})
	require.NoError(t, err)
	assert.True(t, progress.Complete)
	assert.False(t, barrier.IsSealed())

	// 8. Rekey with new parameters.
	rekeyResp, err := svc.BarrierRekey(ctx, &pb.BarrierRekeyRequest{
		Threshold: 3,
		Total:     5,
	})
	require.NoError(t, err)
	assert.Len(t, rekeyResp.Shares, 5)

	// 9. Seal and unseal with new shares (batch mode).
	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	_, err = svc.BarrierUnsealShares(ctx, &pb.BarrierUnsealSharesRequest{
		Shares: rekeyResp.Shares[:3],
	})
	require.NoError(t, err)
	assert.False(t, barrier.IsSealed())

	// 10. Delete recovery keys.
	_, err = svc.BarrierDeleteRecoveryKeys(ctx, &emptypb.Empty{})
	require.NoError(t, err)
}

func TestBarrierShamir_RecoveryKeyLifecycle(t *testing.T) {
	setupShamirBarrier(t, 2, 3)
	svc := newTestService()
	ctx := context.Background()

	// Initialize.
	_, err := svc.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{})
	require.NoError(t, err)

	// Generate recovery keys.
	recoveryResp, err := svc.BarrierGenerateRecoveryKeys(ctx, &pb.BarrierGenerateRecoveryKeysRequest{
		Threshold: 2,
		Total:     3,
	})
	require.NoError(t, err)

	// Seal.
	_, err = svc.BarrierSeal(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	// Recover with keys.
	_, err = svc.BarrierRecoverWithKeys(ctx, &pb.BarrierRecoverWithKeysRequest{
		Keys: recoveryResp.Shares[:2],
	})
	require.NoError(t, err)
	assert.False(t, barrier.IsSealed())

	// Delete recovery keys.
	_, err = svc.BarrierDeleteRecoveryKeys(ctx, &emptypb.Empty{})
	require.NoError(t, err)
}
