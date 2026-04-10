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

package services

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	pcrpolicy "github.com/jeremyhahn/go-xkms/xkey/pkg/pcr_policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock policy store
// ---------------------------------------------------------------------------

// barrierMockPolicyStore implements pcrpolicy.PolicyStore for testing.
type barrierMockPolicyStore struct {
	autoUnsealPolicy *pcrpolicy.PCRPolicyEntity
	autoUnsealErr    error
	policies         map[string]*pcrpolicy.PCRPolicyEntity
}

// Compile-time interface check.
var _ pcrpolicy.PolicyStore = (*barrierMockPolicyStore)(nil)

func newBarrierMockPolicyStore() *barrierMockPolicyStore {
	return &barrierMockPolicyStore{
		policies: make(map[string]*pcrpolicy.PCRPolicyEntity),
	}
}

func (m *barrierMockPolicyStore) GetAutoUnsealPolicy(_ context.Context) (*pcrpolicy.PCRPolicyEntity, error) {
	if m.autoUnsealErr != nil {
		return nil, m.autoUnsealErr
	}
	if m.autoUnsealPolicy == nil {
		return nil, pcrpolicy.ErrPolicyNotFound
	}
	return m.autoUnsealPolicy, nil
}

func (m *barrierMockPolicyStore) Get(_ context.Context, name string) (*pcrpolicy.PCRPolicyEntity, error) {
	p, ok := m.policies[name]
	if !ok {
		return nil, pcrpolicy.ErrPolicyNotFound
	}
	return p, nil
}

func (m *barrierMockPolicyStore) Create(_ context.Context, _, _ string, _ map[uint][]byte) (*pcrpolicy.PCRPolicyEntity, error) {
	return nil, nil
}

func (m *barrierMockPolicyStore) List(_ context.Context) ([]*pcrpolicy.PCRPolicyEntity, error) {
	return nil, nil
}

func (m *barrierMockPolicyStore) Page(_ context.Context, _ dao.PageQuery) (dao.PageResult[*pcrpolicy.PCRPolicyEntity], error) {
	return dao.PageResult[*pcrpolicy.PCRPolicyEntity]{}, nil
}

func (m *barrierMockPolicyStore) Delete(_ context.Context, _ string) error {
	return nil
}

func (m *barrierMockPolicyStore) SetAutoUnseal(_ context.Context, _ string) error {
	return nil
}

func (m *barrierMockPolicyStore) ClearAutoUnseal(_ context.Context) error {
	return nil
}

func (m *barrierMockPolicyStore) Close() error {
	return nil
}

// ---------------------------------------------------------------------------
// barrierAutoUnsealMockTPM embeds the base mockTPM with configurable PCR banks.
// ---------------------------------------------------------------------------

type barrierAutoUnsealMockTPM struct {
	mockTPM
	pcrBanksOverride []tpm2pkg.PCRBank
	pcrBanksErr      error
}

func (m *barrierAutoUnsealMockTPM) ReadPCRs(_ []uint) ([]tpm2pkg.PCRBank, error) {
	return m.pcrBanksOverride, m.pcrBanksErr
}

// defaultBarrierAutoUnsealMock returns a mock TPM with SHA256 PCR values
// for PCR 0 and PCR 7, matching the test policy digests.
func defaultBarrierAutoUnsealMock() *barrierAutoUnsealMockTPM {
	return &barrierAutoUnsealMockTPM{
		mockTPM: *defaultMockTPM(),
		pcrBanksOverride: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0xAA, 0xBB, 0xCC, 0xDD}},
					{ID: 7, Value: []byte{0x11, 0x22, 0x33, 0x44}},
				},
			},
		},
	}
}

// testBarrierAutoUnsealPolicy returns a PCR policy entity matching the
// default mock TPM PCR values.
func testBarrierAutoUnsealPolicy() *pcrpolicy.PCRPolicyEntity {
	return &pcrpolicy.PCRPolicyEntity{
		ID:         1,
		Name:       "boot-policy",
		Bank:       "sha256",
		AutoUnseal: true,
		PCRs: map[uint][]byte{
			0: {0xAA, 0xBB, 0xCC, 0xDD},
			7: {0x11, 0x22, 0x33, 0x44},
		},
	}
}

// newBarrierAutoUnsealSvcWithMock creates a BarrierAutoUnsealService with
// a mock policy store and TPM accessor.
func newBarrierAutoUnsealSvcWithMock(
	t *testing.T,
	store *barrierMockPolicyStore,
	mock *barrierAutoUnsealMockTPM,
) *BarrierAutoUnsealService {
	t.Helper()
	accessor := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock })
	barrier := newTestBarrierService(t)

	return NewBarrierAutoUnsealService(
		store,
		WithBarrierAutoUnsealTPMAccessor(accessor),
		WithBarrierAutoUnsealBarrier(barrier),
		WithBarrierAutoUnsealLogger(slog.Default()),
	)
}

// ---------------------------------------------------------------------------
// TryAutoUnseal
// ---------------------------------------------------------------------------

func TestBarrierAutoUnsealService_TryAutoUnseal_NoPolicyConfigured(t *testing.T) {
	store := newBarrierMockPolicyStore()
	// No auto-unseal policy set (default returns ErrPolicyNotFound).
	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	ok, err := svc.TryAutoUnseal(context.Background())
	assert.False(t, ok, "should return false when no auto-unseal policy is configured")
	assert.NoError(t, err, "should return nil error when no policy is configured")
}

func TestBarrierAutoUnsealService_TryAutoUnseal_PCRMatch(t *testing.T) {
	store := newBarrierMockPolicyStore()
	store.autoUnsealPolicy = testBarrierAutoUnsealPolicy()

	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	// Use TPM2 strategy with a mock sealer so the barrier can initialize
	// and unseal without a password (matching real auto-unseal behavior).
	svc.barrier.SetTPMSealerFunc(func() types.Sealer {
		return &mockSealer{canSeal: true}
	})
	svc.strategyID = "tpm2"

	// Initialize the barrier with TPM2 strategy (no password needed).
	require.NoError(t, svc.barrier.Initialize("", "tpm2"))
	require.NoError(t, svc.barrier.Seal())

	ok, err := svc.TryAutoUnseal(context.Background())
	assert.True(t, ok, "should succeed when PCR values match")
	assert.NoError(t, err)
	assert.True(t, svc.barrier.IsUnsealed(), "barrier should be unsealed after auto-unseal")
}

func TestBarrierAutoUnsealService_TryAutoUnseal_PCRMismatch(t *testing.T) {
	store := newBarrierMockPolicyStore()
	// Policy expects different PCR values than the TPM reports.
	policy := testBarrierAutoUnsealPolicy()
	policy.PCRs[0] = []byte{0xFF, 0xFF, 0xFF, 0xFF} // mismatch
	store.autoUnsealPolicy = policy

	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	ok, err := svc.TryAutoUnseal(context.Background())
	assert.False(t, ok, "should return false on PCR mismatch")
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealPCRMismatch)
}

func TestBarrierAutoUnsealService_TryAutoUnseal_NilPolicyStore(t *testing.T) {
	svc := NewBarrierAutoUnsealService(nil)
	svc.barrier = newTestBarrierService(t)

	ok, err := svc.TryAutoUnseal(context.Background())
	assert.False(t, ok)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealNoPolicyStore)
}

func TestBarrierAutoUnsealService_TryAutoUnseal_NilBarrier(t *testing.T) {
	store := newBarrierMockPolicyStore()
	svc := NewBarrierAutoUnsealService(store)
	// barrier is nil by default

	ok, err := svc.TryAutoUnseal(context.Background())
	assert.False(t, ok)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealNoBarrier)
}

func TestBarrierAutoUnsealService_TryAutoUnseal_StoreError(t *testing.T) {
	store := newBarrierMockPolicyStore()
	store.autoUnsealErr = errors.New("database connection lost")

	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	ok, err := svc.TryAutoUnseal(context.Background())
	assert.False(t, ok)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection lost")
}

func TestBarrierAutoUnsealService_TryAutoUnseal_BarrierUnsealFails(t *testing.T) {
	store := newBarrierMockPolicyStore()
	store.autoUnsealPolicy = testBarrierAutoUnsealPolicy()

	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	// Don't initialize the barrier, and use a strategy that will fail.
	// The barrier is uninitialized so it will trigger transparent init,
	// but with "tpm2" strategy which is unavailable (no sealer func).
	svc.strategyID = "tpm2"

	ok, err := svc.TryAutoUnseal(context.Background())
	assert.False(t, ok, "should fail when barrier unseal fails")
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealFailed)
}

// ---------------------------------------------------------------------------
// VerifyPCRs
// ---------------------------------------------------------------------------

func TestBarrierAutoUnsealService_VerifyPCRs_Match(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	policy := testBarrierAutoUnsealPolicy()
	match, err := svc.VerifyPCRs(context.Background(), policy)
	assert.True(t, match, "PCR values should match")
	assert.NoError(t, err)
}

func TestBarrierAutoUnsealService_VerifyPCRs_Mismatch(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	policy := testBarrierAutoUnsealPolicy()
	policy.PCRs[7] = []byte{0xFF, 0xEE, 0xDD, 0xCC} // different from mock
	match, err := svc.VerifyPCRs(context.Background(), policy)
	assert.False(t, match, "PCR values should not match")
	assert.NoError(t, err, "mismatch is not an error, just a false result")
}

func TestBarrierAutoUnsealService_VerifyPCRs_NilPolicy(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	match, err := svc.VerifyPCRs(context.Background(), nil)
	assert.False(t, match)
	assert.NoError(t, err)
}

func TestBarrierAutoUnsealService_VerifyPCRs_EmptyPCRs(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	policy := &pcrpolicy.PCRPolicyEntity{
		Name: "empty-policy",
		Bank: "sha256",
		PCRs: map[uint][]byte{},
	}
	match, err := svc.VerifyPCRs(context.Background(), policy)
	assert.False(t, match)
	assert.NoError(t, err)
}

func TestBarrierAutoUnsealService_VerifyPCRs_InvalidBank(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	policy := testBarrierAutoUnsealPolicy()
	policy.Bank = "md5" // unsupported bank
	match, err := svc.VerifyPCRs(context.Background(), policy)
	assert.False(t, match)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealInvalidBank)
}

func TestBarrierAutoUnsealService_VerifyPCRs_TPMReadError(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := defaultBarrierAutoUnsealMock()
	mock.pcrBanksErr = errors.New("TPM device error")
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	policy := testBarrierAutoUnsealPolicy()
	match, err := svc.VerifyPCRs(context.Background(), policy)
	assert.False(t, match)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealReadPCRFailed)
}

func TestBarrierAutoUnsealService_VerifyPCRs_MissingPCRIndex(t *testing.T) {
	store := newBarrierMockPolicyStore()
	// Mock only returns PCR 0 and 7, but policy expects PCR 14.
	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	policy := &pcrpolicy.PCRPolicyEntity{
		Name: "missing-pcr",
		Bank: "sha256",
		PCRs: map[uint][]byte{
			14: {0xDE, 0xAD, 0xBE, 0xEF},
		},
	}
	match, err := svc.VerifyPCRs(context.Background(), policy)
	assert.False(t, match, "should return false when expected PCR index is not in TPM response")
	assert.NoError(t, err)
}

func TestBarrierAutoUnsealService_VerifyPCRs_DigestLengthMismatch(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	policy := testBarrierAutoUnsealPolicy()
	// Policy expects a 5-byte digest but TPM returns 4-byte.
	policy.PCRs[0] = []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	match, err := svc.VerifyPCRs(context.Background(), policy)
	assert.False(t, match)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// CaptureCurrentPCRs
// ---------------------------------------------------------------------------

func TestBarrierAutoUnsealService_CaptureCurrentPCRs_Success(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	pcrs, err := svc.CaptureCurrentPCRs(context.Background(), "sha256", []uint{0, 7})
	require.NoError(t, err)
	require.Len(t, pcrs, 2)
	assert.Equal(t, []byte{0xAA, 0xBB, 0xCC, 0xDD}, pcrs[0])
	assert.Equal(t, []byte{0x11, 0x22, 0x33, 0x44}, pcrs[7])
}

func TestBarrierAutoUnsealService_CaptureCurrentPCRs_EmptyIndices(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	pcrs, err := svc.CaptureCurrentPCRs(context.Background(), "sha256", []uint{})
	assert.Nil(t, pcrs)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealNoPCRIndices)
}

func TestBarrierAutoUnsealService_CaptureCurrentPCRs_InvalidBank(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := defaultBarrierAutoUnsealMock()
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	pcrs, err := svc.CaptureCurrentPCRs(context.Background(), "md5", []uint{0})
	assert.Nil(t, pcrs)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealInvalidBank)
}

func TestBarrierAutoUnsealService_CaptureCurrentPCRs_TPMUnavailable(t *testing.T) {
	store := newBarrierMockPolicyStore()
	svc := NewBarrierAutoUnsealService(store)
	// No TPM accessor set.

	pcrs, err := svc.CaptureCurrentPCRs(context.Background(), "sha256", []uint{0})
	assert.Nil(t, pcrs)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealTPMUnavailable)
}

func TestBarrierAutoUnsealService_CaptureCurrentPCRs_TPMReadError(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := defaultBarrierAutoUnsealMock()
	mock.pcrBanksErr = errors.New("hardware failure")
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	pcrs, err := svc.CaptureCurrentPCRs(context.Background(), "sha256", []uint{0})
	assert.Nil(t, pcrs)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealReadPCRFailed)
}

func TestBarrierAutoUnsealService_CaptureCurrentPCRs_BankFiltering(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := &barrierAutoUnsealMockTPM{
		mockTPM: *defaultMockTPM(),
		pcrBanksOverride: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA1",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0x01}},
				},
			},
			{
				Algorithm: "SHA256",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0x02}},
				},
			},
		},
	}
	svc := newBarrierAutoUnsealSvcWithMock(t, store, mock)

	// Request SHA256 bank; should not get SHA1 values.
	pcrs, err := svc.CaptureCurrentPCRs(context.Background(), "sha256", []uint{0})
	require.NoError(t, err)
	assert.Equal(t, []byte{0x02}, pcrs[0], "should return SHA256 bank value, not SHA1")
}

// ---------------------------------------------------------------------------
// Functional options
// ---------------------------------------------------------------------------

func TestBarrierAutoUnsealService_FunctionalOptions(t *testing.T) {
	store := newBarrierMockPolicyStore()
	mock := defaultBarrierAutoUnsealMock()
	accessor := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock })
	barrier := newTestBarrierService(t)
	logger := slog.Default().With("test", "options")

	svc := NewBarrierAutoUnsealService(
		store,
		WithBarrierAutoUnsealTPMAccessor(accessor),
		WithBarrierAutoUnsealBarrier(barrier),
		WithBarrierAutoUnsealLogger(logger),
		WithBarrierAutoUnsealStrategyID("software"),
	)

	assert.Equal(t, store, svc.policyStore)
	assert.Equal(t, accessor, svc.tpmAccessor)
	assert.Equal(t, barrier, svc.barrier)
	assert.Equal(t, "software", svc.strategyID)
}

func TestBarrierAutoUnsealService_SetTPMAccessor(t *testing.T) {
	svc := NewBarrierAutoUnsealService(newBarrierMockPolicyStore())
	assert.Nil(t, svc.tpmAccessor)

	mock := defaultBarrierAutoUnsealMock()
	accessor := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock })
	svc.SetTPMAccessor(accessor)
	assert.Equal(t, accessor, svc.tpmAccessor)
}

func TestBarrierAutoUnsealService_SetBarrier(t *testing.T) {
	svc := NewBarrierAutoUnsealService(newBarrierMockPolicyStore())
	assert.Nil(t, svc.barrier)

	barrier := newTestBarrierService(t)
	svc.SetBarrier(barrier)
	assert.Equal(t, barrier, svc.barrier)
}

// ---------------------------------------------------------------------------
// Default strategy ID
// ---------------------------------------------------------------------------

func TestBarrierAutoUnsealService_DefaultStrategyID(t *testing.T) {
	svc := NewBarrierAutoUnsealService(newBarrierMockPolicyStore())
	assert.Equal(t, "tpm2", svc.strategyID, "default strategy should be tpm2")
}
