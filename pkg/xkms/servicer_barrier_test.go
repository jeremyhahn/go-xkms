package xkms

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	quicraftShamir "github.com/jeremyhahn/go-quicraft/pkg/crypto/shamir"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCaptureDistributor implements seal.CeremonyDistributor for use in unit
// tests. It splits the secret using the real Shamir library and records the
// share strings so tests can later call UnsealWithShare / RecoverWithKeys.
type testCaptureDistributor struct {
	mu     sync.Mutex
	shares []string
}

// SealAndDistribute splits secret into total shares with the given threshold,
// records them, and returns the count.
func (c *testCaptureDistributor) SealAndDistribute(_ context.Context, secret []byte, threshold, total int) (int, error) {
	raw, err := quicraftShamir.Split(secret, threshold, total)
	if err != nil {
		return 0, fmt.Errorf("shamir split failed: %w", err)
	}
	c.mu.Lock()
	c.shares = make([]string, len(raw))
	for i, s := range raw {
		c.shares[i] = s.Value
	}
	c.mu.Unlock()
	return len(raw), nil
}

// RekeyAndDistribute destroys the prior round and produces fresh shares.
func (c *testCaptureDistributor) RekeyAndDistribute(ctx context.Context, newSecret []byte, newThreshold, newTotal int) (int, error) {
	c.mu.Lock()
	c.shares = nil
	c.mu.Unlock()
	return c.SealAndDistribute(ctx, newSecret, newThreshold, newTotal)
}

// Shares returns the share strings captured by the last SealAndDistribute call.
func (c *testCaptureDistributor) Shares() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.shares))
	copy(out, c.shares)
	return out
}

// --- ErrNotConfigured guards ---

func TestBarrierInitialize_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.BarrierInitialize(context.Background(), &transport.BarrierInitializeRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBarrierUnseal_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBarrierSeal_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.BarrierSeal(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBarrierStatus_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.BarrierStatus(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBarrierInitializeShamir_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.BarrierInitializeShamir(context.Background(), &transport.BarrierInitializeShamirRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBarrierUnsealWithShare_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.BarrierUnsealWithShare(context.Background(), &transport.BarrierUnsealShareRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBarrierUnsealWithShares_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.BarrierUnsealWithShares(context.Background(), &transport.BarrierUnsealSharesRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBarrierRekey_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.BarrierRekey(context.Background(), &transport.BarrierRekeyRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBarrierGenerateRecoveryKeys_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.BarrierGenerateRecoveryKeys(context.Background(), &transport.BarrierGenerateRecoveryKeysRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBarrierRecoverWithKeys_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.BarrierRecoverWithKeys(context.Background(), &transport.BarrierRecoverWithKeysRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBarrierDeleteRecoveryKeys_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.BarrierDeleteRecoveryKeys(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBarrierHasRecoveryKeys_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.BarrierHasRecoveryKeys(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBarrierGenerateRootToken_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.BarrierGenerateRootToken(context.Background(), &transport.BarrierGenerateRootTokenRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// --- Nil request guards with barrier set ---
// These tests create a real Barrier (software strategy) to exercise
// the nil request check that occurs after the barrier nil check.

func setupBarrier(t *testing.T) (*seal.Barrier, *testCaptureDistributor, *testCaptureDistributor) {
	t.Helper()
	barrierStore := storage.NewMemory()
	softStrat := seal.NewSoftwareStrategy()
	barrier, err := seal.NewBarrier(
		slog.Default(),
		barrierStore,
		seal.BarrierConfig{
			RootKeyPath:     "barrier/root-key",
			PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
		},
		softStrat,
	)
	require.NoError(t, err)

	// Wire ceremony and recovery distributors so all Shamir operations succeed.
	dist := &testCaptureDistributor{}
	recoveryDist := &testCaptureDistributor{}
	barrier.SetCeremonyDistributor(dist)
	barrier.SetRecoveryDistributor(recoveryDist)
	return barrier, dist, recoveryDist
}

func setupServiceWithBarrier(t *testing.T) *XKMSService {
	t.Helper()
	svc, _, _ := setupServiceWithBarrierDistributors(t)
	return svc
}

// setupServiceWithBarrierDistributors returns the service along with the
// ceremony and recovery capture distributors so tests can retrieve the
// Shamir shares produced by the share-free seal contract.
func setupServiceWithBarrierDistributors(t *testing.T) (*XKMSService, *testCaptureDistributor, *testCaptureDistributor) {
	t.Helper()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	barrier, dist, recoveryDist := setupBarrier(t)
	svc.SetBarrier(barrier)
	return svc, dist, recoveryDist
}

func setupBarrierWithShamir(t *testing.T, threshold, total int) (*seal.Barrier, *testCaptureDistributor, *testCaptureDistributor) {
	t.Helper()
	barrierStore := storage.NewMemory()
	softStrat := seal.NewSoftwareStrategy()
	shamirStrat, err := seal.NewShamirStrategy(threshold, total)
	require.NoError(t, err)
	barrier, err := seal.NewBarrier(
		slog.Default(),
		barrierStore,
		seal.BarrierConfig{
			RootKeyPath:     "barrier/root-key",
			PreferenceOrder: []seal.StrategyID{seal.StrategyShamir, seal.StrategyPassphrase},
			Shamir: &seal.ShamirConfig{
				Threshold:   threshold,
				TotalShares: total,
			},
		},
		softStrat,
		shamirStrat,
	)
	require.NoError(t, err)

	// Wire ceremony and recovery distributors so all Shamir operations succeed.
	dist := &testCaptureDistributor{}
	recoveryDist := &testCaptureDistributor{}
	barrier.SetCeremonyDistributor(dist)
	barrier.SetRecoveryDistributor(recoveryDist)
	return barrier, dist, recoveryDist
}

func setupServiceWithShamirBarrier(t *testing.T, threshold, total int) (*XKMSService, *testCaptureDistributor, *testCaptureDistributor) {
	t.Helper()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	barrier, dist, recoveryDist := setupBarrierWithShamir(t, threshold, total)
	svc.SetBarrier(barrier)
	return svc, dist, recoveryDist
}

func TestBarrierInitialize_NilRequest(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	err := svc.BarrierInitialize(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestBarrierUnseal_NilRequest(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	err := svc.BarrierUnseal(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestBarrierInitializeShamir_NilRequest(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	_, err := svc.BarrierInitializeShamir(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestBarrierUnsealWithShare_NilRequest(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	_, err := svc.BarrierUnsealWithShare(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestBarrierUnsealWithShares_NilRequest(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	err := svc.BarrierUnsealWithShares(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestBarrierRekey_NilRequest(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	_, err := svc.BarrierRekey(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestBarrierGenerateRecoveryKeys_NilRequest(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	_, err := svc.BarrierGenerateRecoveryKeys(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestBarrierRecoverWithKeys_NilRequest(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	err := svc.BarrierRecoverWithKeys(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestBarrierGenerateRootToken_NilRequest(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	_, err := svc.BarrierGenerateRootToken(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilRequest)
}

// --- BarrierStatus with barrier set ---

func TestBarrierStatus_WithBarrier(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	ctx := context.Background()

	resp, err := svc.BarrierStatus(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Barrier is sealed by default (not initialized), strategy is empty
	assert.True(t, resp.Sealed)
}

// --- BarrierSeal with barrier set ---

func TestBarrierSeal_WithBarrier(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	ctx := context.Background()

	// Sealing an already sealed barrier is a no-op
	err := svc.BarrierSeal(ctx)
	require.NoError(t, err)
}

// --- Barrier initialize and lifecycle ---

func TestBarrierInitialize_AndStatus(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	ctx := context.Background()

	// Initialize the barrier with a secret
	err := svc.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{
		Secret: "test-secret-12345",
	})
	require.NoError(t, err)

	// Status should show unsealed after initialization
	resp, err := svc.BarrierStatus(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.Sealed)
	assert.NotEmpty(t, resp.Strategy)
}

func TestBarrierSeal_AfterInitialize(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	ctx := context.Background()

	// Initialize first
	err := svc.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{
		Secret: "test-secret-12345",
	})
	require.NoError(t, err)

	// Seal the barrier
	err = svc.BarrierSeal(ctx)
	require.NoError(t, err)

	// Status should show sealed
	resp, err := svc.BarrierStatus(ctx)
	require.NoError(t, err)
	assert.True(t, resp.Sealed)
}

func TestBarrierUnseal_AfterSeal(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	ctx := context.Background()

	// Initialize
	err := svc.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{
		Secret: "test-secret-12345",
	})
	require.NoError(t, err)

	// Seal
	err = svc.BarrierSeal(ctx)
	require.NoError(t, err)

	// Unseal with the same secret
	err = svc.BarrierUnseal(ctx, &transport.BarrierUnsealRequest{
		Secret: "test-secret-12345",
	})
	require.NoError(t, err)

	// Status should show unsealed
	resp, err := svc.BarrierStatus(ctx)
	require.NoError(t, err)
	assert.False(t, resp.Sealed)
}

func TestBarrierHasRecoveryKeys_AfterInit(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	ctx := context.Background()

	// Initialize first so barrier is unsealed
	err := svc.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{
		Secret: "test-secret-12345",
	})
	require.NoError(t, err)

	// Check for recovery keys - should be false since none generated
	resp, err := svc.BarrierHasRecoveryKeys(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.HasKeys)
}

func TestBarrierDeleteRecoveryKeys_AfterInit(t *testing.T) {
	svc := setupServiceWithBarrier(t)
	ctx := context.Background()

	// Initialize first so barrier is unsealed
	err := svc.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{
		Secret: "test-secret-12345",
	})
	require.NoError(t, err)

	// Delete recovery keys when none exist returns storage: not found error
	// which is expected since no recovery keys were generated
	err = svc.BarrierDeleteRecoveryKeys(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- Recovery key generation and lifecycle ---

func TestBarrierGenerateRecoveryKeys_AfterInit(t *testing.T) {
	svc, _, recoveryDist := setupServiceWithBarrierDistributors(t)
	ctx := context.Background()

	// Initialize first
	err := svc.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{
		Secret: "test-secret-recovery",
	})
	require.NoError(t, err)

	// Generate recovery keys. Key material is never returned; the recovery
	// distributor receives the shares under the share-free seal contract.
	resp, err := svc.BarrierGenerateRecoveryKeys(ctx, &transport.BarrierGenerateRecoveryKeysRequest{
		Threshold: 2,
		Total:     3,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 2, resp.Threshold)
	assert.Equal(t, 3, resp.TotalShares)
	assert.Equal(t, 3, resp.ShareCount)
	assert.Len(t, recoveryDist.Shares(), 3)

	// Verify recovery keys exist
	hasKeysResp, err := svc.BarrierHasRecoveryKeys(ctx)
	require.NoError(t, err)
	assert.True(t, hasKeysResp.HasKeys)

	// Delete recovery keys (should succeed now)
	err = svc.BarrierDeleteRecoveryKeys(ctx)
	require.NoError(t, err)

	// Verify they are gone
	hasKeysResp, err = svc.BarrierHasRecoveryKeys(ctx)
	require.NoError(t, err)
	assert.False(t, hasKeysResp.HasKeys)
}

// --- Barrier rekey ---

func TestBarrierRekey_AfterInit(t *testing.T) {
	svc, dist, _ := setupServiceWithShamirBarrier(t, 2, 3)
	ctx := context.Background()

	// Initialize with Shamir (direct mode with ShamirStrategy). Shares are
	// delivered through the ceremony distributor, never in the response.
	shamirResp, err := svc.BarrierInitializeShamir(ctx, &transport.BarrierInitializeShamirRequest{
		Threshold:   2,
		TotalShares: 3,
	})
	require.NoError(t, err)
	require.NotNil(t, shamirResp)
	assert.Equal(t, 3, shamirResp.TotalShares)
	assert.Equal(t, 3, shamirResp.ShareCount)
	assert.Len(t, dist.Shares(), 3)

	// Rekey with different config
	rekeyResp, err := svc.BarrierRekey(ctx, &transport.BarrierRekeyRequest{
		Threshold: 3,
		Total:     5,
	})
	require.NoError(t, err)
	require.NotNil(t, rekeyResp)
	assert.Equal(t, 5, rekeyResp.TotalShares)
	assert.Equal(t, 3, rekeyResp.Threshold)
	assert.Equal(t, 5, rekeyResp.ShareCount)
	assert.Len(t, dist.Shares(), 5)
}

// --- Barrier Shamir unseal ---

func TestBarrierUnsealWithShares_AfterShamirInit(t *testing.T) {
	svc, dist, _ := setupServiceWithBarrierDistributors(t)
	ctx := context.Background()

	// Initialize with Shamir; shares are captured by the ceremony distributor.
	_, err := svc.BarrierInitializeShamir(ctx, &transport.BarrierInitializeShamirRequest{
		Secret:      "test-secret-shamir-unseal",
		Threshold:   2,
		TotalShares: 3,
	})
	require.NoError(t, err)
	shares := dist.Shares()
	require.Len(t, shares, 3)

	// Seal the barrier
	err = svc.BarrierSeal(ctx)
	require.NoError(t, err)

	// Unseal with all shares at once
	err = svc.BarrierUnsealWithShares(ctx, &transport.BarrierUnsealSharesRequest{
		Shares: shares[:2], // only need threshold
	})
	require.NoError(t, err)

	// Verify unsealed
	status, err := svc.BarrierStatus(ctx)
	require.NoError(t, err)
	assert.False(t, status.Sealed)
}

func TestBarrierUnsealWithShare_AfterShamirInit(t *testing.T) {
	svc, dist, _ := setupServiceWithBarrierDistributors(t)
	ctx := context.Background()

	// Initialize with Shamir (threshold=2, total=3); shares are captured by
	// the ceremony distributor.
	_, err := svc.BarrierInitializeShamir(ctx, &transport.BarrierInitializeShamirRequest{
		Secret:      "test-secret-shamir-share",
		Threshold:   2,
		TotalShares: 3,
	})
	require.NoError(t, err)
	shares := dist.Shares()
	require.Len(t, shares, 3)

	// Seal the barrier
	err = svc.BarrierSeal(ctx)
	require.NoError(t, err)

	// Submit first share
	progress1, err := svc.BarrierUnsealWithShare(ctx, &transport.BarrierUnsealShareRequest{
		Share: shares[0],
	})
	require.NoError(t, err)
	require.NotNil(t, progress1)
	assert.Equal(t, 2, progress1.Required)
	assert.Equal(t, 1, progress1.Submitted)
	assert.False(t, progress1.Complete)

	// Submit second share (should complete quorum)
	progress2, err := svc.BarrierUnsealWithShare(ctx, &transport.BarrierUnsealShareRequest{
		Share: shares[1],
	})
	require.NoError(t, err)
	require.NotNil(t, progress2)
	assert.True(t, progress2.Complete)
}

// --- BarrierRecoverWithKeys ---

func TestBarrierRecoverWithKeys_AfterInit(t *testing.T) {
	svc, _, recoveryDist := setupServiceWithBarrierDistributors(t)
	ctx := context.Background()

	// Initialize the barrier
	err := svc.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{
		Secret: "test-secret-recover",
	})
	require.NoError(t, err)

	// Generate recovery keys; key material is captured by the recovery
	// distributor.
	_, err = svc.BarrierGenerateRecoveryKeys(ctx, &transport.BarrierGenerateRecoveryKeysRequest{
		Threshold: 2,
		Total:     3,
	})
	require.NoError(t, err)
	keys := recoveryDist.Shares()
	require.Len(t, keys, 3)

	// Seal the barrier
	err = svc.BarrierSeal(ctx)
	require.NoError(t, err)

	// Recover with keys
	err = svc.BarrierRecoverWithKeys(ctx, &transport.BarrierRecoverWithKeysRequest{
		Keys: keys[:2], // only need threshold
	})
	require.NoError(t, err)

	// Verify unsealed
	status, err := svc.BarrierStatus(ctx)
	require.NoError(t, err)
	assert.False(t, status.Sealed)
}

// --- BarrierGenerateRootToken success ---

func TestBarrierGenerateRootToken_AfterShamirInit(t *testing.T) {
	svc, dist, _ := setupServiceWithBarrierDistributors(t)
	ctx := context.Background()

	// Initialize with Shamir (credential mode); shares are captured by the
	// ceremony distributor.
	shamirResp, err := svc.BarrierInitializeShamir(ctx, &transport.BarrierInitializeShamirRequest{
		Secret:      "root-token-secret",
		Threshold:   2,
		TotalShares: 3,
	})
	require.NoError(t, err)
	require.NotNil(t, shamirResp)
	shares := dist.Shares()
	require.Len(t, shares, 3)

	// Generate root token using the Shamir shares
	tokenResp, err := svc.BarrierGenerateRootToken(ctx, &transport.BarrierGenerateRootTokenRequest{
		Shares: shares,
	})
	require.NoError(t, err)
	require.NotNil(t, tokenResp)
	assert.NotEmpty(t, tokenResp.Token)
	assert.NotEmpty(t, tokenResp.CreatedAt)
}
