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
	"crypto/subtle"
	"errors"
	"log/slog"
	"sync/atomic"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	pcrpolicy "github.com/jeremyhahn/go-xkms/xkey/pkg/pcr_policy"
)

// Barrier auto-unseal typed errors.
var (
	// ErrBarrierAutoUnsealPCRMismatch indicates the current TPM PCR values do
	// not match the expected digests stored in the auto-unseal policy.
	ErrBarrierAutoUnsealPCRMismatch = errors.New("barrier_auto_unseal: PCR values do not match policy")

	// ErrBarrierAutoUnsealTPMUnavailable indicates the TPM is not available for
	// barrier auto-unseal operations.
	ErrBarrierAutoUnsealTPMUnavailable = errors.New("barrier_auto_unseal: TPM not available")

	// ErrBarrierAutoUnsealNoPolicyStore indicates the policy store is nil.
	ErrBarrierAutoUnsealNoPolicyStore = errors.New("barrier_auto_unseal: policy store not configured")

	// ErrBarrierAutoUnsealNoBarrier indicates the barrier service is nil.
	ErrBarrierAutoUnsealNoBarrier = errors.New("barrier_auto_unseal: barrier service not configured")

	// ErrBarrierAutoUnsealFailed indicates the barrier unseal operation failed.
	ErrBarrierAutoUnsealFailed = errors.New("barrier_auto_unseal: barrier unseal failed")

	// ErrBarrierAutoUnsealInvalidBank indicates the policy specifies an
	// unsupported PCR bank.
	ErrBarrierAutoUnsealInvalidBank = errors.New("barrier_auto_unseal: invalid PCR bank in policy")

	// ErrBarrierAutoUnsealReadPCRFailed indicates the TPM PCR read failed.
	ErrBarrierAutoUnsealReadPCRFailed = errors.New("barrier_auto_unseal: failed to read PCR values from TPM")

	// ErrBarrierAutoUnsealNoPCRIndices indicates the request contains no PCR
	// indices.
	ErrBarrierAutoUnsealNoPCRIndices = errors.New("barrier_auto_unseal: no PCR indices specified")

	// ErrBarrierAutoUnsealEmptyPolicyName indicates an empty policy name was
	// provided to SetAutoUnsealPolicy.
	ErrBarrierAutoUnsealEmptyPolicyName = errors.New("barrier_auto_unseal: policy name cannot be empty")
)

// BarrierAutoUnsealOption is a functional option for configuring
// BarrierAutoUnsealService.
type BarrierAutoUnsealOption func(*BarrierAutoUnsealService)

// WithBarrierAutoUnsealTPMAccessor sets the TPM accessor for PCR reads.
func WithBarrierAutoUnsealTPMAccessor(a *TPMAccessor) BarrierAutoUnsealOption {
	return func(s *BarrierAutoUnsealService) {
		s.tpmAccessor.Store(a)
	}
}

// WithBarrierAutoUnsealBarrier sets the barrier service used for unsealing.
func WithBarrierAutoUnsealBarrier(b *BarrierService) BarrierAutoUnsealOption {
	return func(s *BarrierAutoUnsealService) {
		s.barrier.Store(b)
	}
}

// WithBarrierAutoUnsealLogger sets a custom logger.
func WithBarrierAutoUnsealLogger(l *slog.Logger) BarrierAutoUnsealOption {
	return func(s *BarrierAutoUnsealService) {
		s.logger = l
	}
}

// WithBarrierAutoUnsealStrategyID sets the barrier strategy ID to use
// during unseal.
func WithBarrierAutoUnsealStrategyID(id string) BarrierAutoUnsealOption {
	return func(s *BarrierAutoUnsealService) {
		s.strategyID = id
	}
}

// BarrierAutoUnsealService handles barrier auto-unseal at boot by verifying
// TPM PCR values against a stored PCR policy. When the current platform
// state matches the policy, the barrier is unsealed via the TPM's PCR
// policy branch (PlatformPolicySession with nil auth), which requires
// no user-provided PIN.
//
// This is distinct from AutoUnsealService, which handles LUKS volume
// auto-unseal. BarrierAutoUnsealService operates at the barrier layer,
// unlocking the encrypted key management storage.
//
// policyStore, tpmAccessor, and barrier are stored behind atomic.Pointer so
// that the composition root can wire them in after construction (once the
// data directory and barrier have been initialized) without racing against
// concurrent reads from Wails-bound frontend calls.
type BarrierAutoUnsealService struct {
	policyStore atomic.Pointer[pcrpolicy.PolicyStore]
	tpmAccessor atomic.Pointer[TPMAccessor]
	barrier     atomic.Pointer[BarrierService]
	logger      *slog.Logger
	strategyID  string
}

// NewBarrierAutoUnsealService creates a new BarrierAutoUnsealService with
// the given policy store and options. policyStore may be nil; in that case
// GetAutoUnsealStatus reports the feature as unavailable until
// SetPolicyStore is called with a non-nil store.
func NewBarrierAutoUnsealService(policyStore pcrpolicy.PolicyStore, opts ...BarrierAutoUnsealOption) *BarrierAutoUnsealService {
	s := &BarrierAutoUnsealService{
		logger:     slog.Default().With("component", "barrier_auto_unseal_service"),
		strategyID: "tpm2",
	}
	s.policyStore.Store(&policyStore)
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// getPolicyStore returns the currently configured PCR policy store, or nil
// if none has been set.
func (s *BarrierAutoUnsealService) getPolicyStore() pcrpolicy.PolicyStore {
	if p := s.policyStore.Load(); p != nil {
		return *p
	}
	return nil
}

// SetPolicyStore injects (or replaces) the PCR policy store used to look up
// the auto-unseal policy. This is called by the composition root once the
// data directory and canonical pcr_policy store are available.
func (s *BarrierAutoUnsealService) SetPolicyStore(store pcrpolicy.PolicyStore) {
	s.policyStore.Store(&store)
}

// SetTPMAccessor sets the shared TPMAccessor used for serialized TPM access.
func (s *BarrierAutoUnsealService) SetTPMAccessor(a *TPMAccessor) {
	s.tpmAccessor.Store(a)
}

// SetBarrier sets the barrier service used for unsealing.
func (s *BarrierAutoUnsealService) SetBarrier(b *BarrierService) {
	s.barrier.Store(b)
}

// TryAutoUnseal attempts to unseal the barrier using the configured
// auto-unseal PCR policy.
//
// Returns (true, nil) if auto-unseal succeeded.
// Returns (false, nil) if no auto-unseal policy is configured.
// Returns (false, err) if auto-unseal failed (PCR mismatch, TPM error, etc.).
func (s *BarrierAutoUnsealService) TryAutoUnseal(ctx context.Context) (bool, error) {
	store := s.getPolicyStore()
	if store == nil {
		return false, ErrBarrierAutoUnsealNoPolicyStore
	}
	barrier := s.barrier.Load()
	if barrier == nil {
		return false, ErrBarrierAutoUnsealNoBarrier
	}

	// 1. Get auto-unseal policy from store.
	policy, err := store.GetAutoUnsealPolicy(ctx)
	if err != nil {
		if errors.Is(err, pcrpolicy.ErrPolicyNotFound) {
			s.logger.Debug("barrier-auto-unseal: no auto-unseal policy configured")
			return false, nil
		}
		s.logger.Error("barrier-auto-unseal: failed to retrieve policy", "error", err)
		return false, err
	}

	// 2. Verify current PCR values match the policy.
	match, verifyErr := s.verifyPCRs(ctx, policy)
	if verifyErr != nil {
		s.logger.Error("barrier-auto-unseal: PCR verification failed", "error", verifyErr)
		return false, verifyErr
	}

	if !match {
		s.logger.Warn("barrier-auto-unseal: PCR mismatch, falling back to manual unseal",
			slog.String("policy", policy.Name),
			slog.String("bank", policy.Bank))
		return false, ErrBarrierAutoUnsealPCRMismatch
	}

	// 3. PCRs match: unseal the barrier using the TPM strategy.
	// For TPM2 strategy with PCR branch, an empty password is used because
	// the PlatformPolicySession(nil) path relies solely on PCR state.
	s.logger.Info("barrier-auto-unseal: PCR values match policy, unsealing barrier",
		slog.String("policy", policy.Name))

	if unsealErr := barrier.Unseal("", s.strategyID); unsealErr != nil {
		s.logger.Error("barrier-auto-unseal: barrier unseal failed", "error", unsealErr)
		return false, ErrBarrierAutoUnsealFailed
	}

	s.logger.Info("barrier-auto-unseal: barrier successfully unsealed via PCR policy",
		slog.String("policy", policy.Name))
	return true, nil
}

// verifyPCRs checks if current TPM PCR values match the given policy.
// Returns (true, nil) on match, (false, nil) on mismatch, or (false, err)
// on TPM or validation errors.
//
// Unexported on purpose: it takes a *pcrpolicy.PCRPolicyEntity, and pcr_policy
// transitively imports the go-qrdb/sdk/go generic DAO types. If this method were
// exported, the wails v2 binding generator would try to type-load that generics
// package and abort with "package go-qrdb/sdk/go without types", preventing the
// GUI from launching. It is only used internally (by TryAutoUnseal); the frontend
// never calls it.
func (s *BarrierAutoUnsealService) verifyPCRs(ctx context.Context, policy *pcrpolicy.PCRPolicyEntity) (bool, error) {
	if policy == nil {
		return false, nil
	}

	if len(policy.PCRs) == 0 {
		return false, nil
	}

	// Policies created through the GUI store the bank in its display form
	// (e.g. "SHA256"); normalize before validating and reading.
	bank := normalizeBankAlg(policy.Bank)
	if _, ok := validPCRBanks[bank]; !ok {
		return false, ErrBarrierAutoUnsealInvalidBank
	}

	// Extract PCR indices from the policy.
	indices := make([]uint, 0, len(policy.PCRs))
	for idx := range policy.PCRs {
		indices = append(indices, idx)
	}

	// Read current PCR values from TPM.
	currentPCRs, err := s.CaptureCurrentPCRs(ctx, bank, indices)
	if err != nil {
		return false, err
	}

	// Compare each PCR value using constant-time comparison.
	for idx, expectedDigest := range policy.PCRs {
		currentDigest, ok := currentPCRs[idx]
		if !ok {
			s.logger.Debug("barrier-auto-unseal: PCR index not found in current values",
				slog.Uint64("pcr_index", uint64(idx)))
			return false, nil
		}

		if len(expectedDigest) != len(currentDigest) {
			return false, nil
		}

		if subtle.ConstantTimeCompare(expectedDigest, currentDigest) != 1 {
			s.logger.Debug("barrier-auto-unseal: PCR value mismatch",
				slog.Uint64("pcr_index", uint64(idx)))
			return false, nil
		}
	}

	return true, nil
}

// CaptureCurrentPCRs reads the current PCR values from the TPM for the
// given bank and PCR indices. Returns a map of PCR index to raw digest bytes.
func (s *BarrierAutoUnsealService) CaptureCurrentPCRs(_ context.Context, bank string, pcrIndices []uint) (map[uint][]byte, error) {
	if len(pcrIndices) == 0 {
		return nil, ErrBarrierAutoUnsealNoPCRIndices
	}

	// Accept both normalized ("sha256") and display-form ("SHA256") banks.
	bank = normalizeBankAlg(bank)
	if _, ok := validPCRBanks[bank]; !ok {
		return nil, ErrBarrierAutoUnsealInvalidBank
	}

	tpm, err := s.acquireTPM()
	if err != nil {
		return nil, err
	}
	defer s.tpmAccessor.Load().Release()

	banks, err := tpm.ReadPCRs(pcrIndices)
	if err != nil {
		s.logger.Error("barrier-auto-unseal: TPM ReadPCRs failed", "error", err)
		return nil, ErrBarrierAutoUnsealReadPCRFailed
	}

	normalizedBank := normalizeBankAlg(bank)
	result := make(map[uint][]byte, len(pcrIndices))

	for _, b := range banks {
		bankAlg := normalizeBankAlg(b.Algorithm)
		if bankAlg != normalizedBank {
			continue
		}
		for _, pcr := range b.PCRs {
			for _, requested := range pcrIndices {
				if uint(pcr.ID) == requested {
					result[requested] = pcr.Value
				}
			}
		}
	}

	return result, nil
}

// BarrierAutoUnsealStatus is the frontend-facing representation of barrier
// auto-unseal configuration and runtime state.
type BarrierAutoUnsealStatus struct {
	// Available reports whether the barrier auto-unseal feature is usable
	// at all. It is false only when no PCR policy store has been wired
	// (e.g. during early startup before initializeDataDir runs). When
	// false, Reason explains why and the remaining fields are zero values.
	Available        bool   `json:"available"`
	Reason           string `json:"reason,omitempty"`
	TPMAvailable     bool   `json:"tpm_available"`
	BarrierSealed    bool   `json:"barrier_sealed"`
	PolicyConfigured bool   `json:"policy_configured"`
	PolicyName       string `json:"policy_name"`
	PCRsMatch        bool   `json:"pcrs_match"`
}

// GetAutoUnsealStatus returns the current barrier auto-unseal configuration
// and runtime state. This method is bound to the Wails frontend.
//
// If no policy store has been configured yet, this returns a status with
// Available=false and a nil error rather than an error, so the frontend can
// render a graceful "unavailable" panel instead of retrying indefinitely.
func (s *BarrierAutoUnsealService) GetAutoUnsealStatus() (*BarrierAutoUnsealStatus, error) {
	store := s.getPolicyStore()
	if store == nil {
		return &BarrierAutoUnsealStatus{
			Available: false,
			Reason:    "PCR policy store is not configured",
		}, nil
	}

	status := &BarrierAutoUnsealStatus{Available: true}

	// Check TPM availability.
	status.TPMAvailable = s.tpmAccessor.Load() != nil

	// Check barrier state.
	if barrier := s.barrier.Load(); barrier != nil {
		info := barrier.GetSealInfo()
		status.BarrierSealed = info.Sealed
	}

	// Check whether an auto-unseal policy is configured.
	policy, err := store.GetAutoUnsealPolicy(context.Background())
	if err != nil {
		if errors.Is(err, pcrpolicy.ErrPolicyNotFound) {
			// No policy configured — not an error, just unconfigured.
			return status, nil
		}
		return nil, err
	}

	status.PolicyConfigured = true
	status.PolicyName = policy.Name

	// If the TPM is available, check whether current PCR values match.
	if status.TPMAvailable {
		match, verifyErr := s.verifyPCRs(context.Background(), policy)
		if verifyErr == nil {
			status.PCRsMatch = match
		}
		// Verification errors are non-fatal here: PCRsMatch stays false.
	}

	return status, nil
}

// SetAutoUnsealPolicy configures barrier auto-unseal to use the named
// PCR policy. This method is bound to the Wails frontend.
func (s *BarrierAutoUnsealService) SetAutoUnsealPolicy(policyName string) error {
	store := s.getPolicyStore()
	if store == nil {
		return ErrBarrierAutoUnsealNoPolicyStore
	}
	if policyName == "" {
		return ErrBarrierAutoUnsealEmptyPolicyName
	}
	return store.SetAutoUnseal(context.Background(), policyName)
}

// ClearAutoUnsealPolicy removes the barrier auto-unseal policy designation.
// This method is bound to the Wails frontend.
func (s *BarrierAutoUnsealService) ClearAutoUnsealPolicy() error {
	store := s.getPolicyStore()
	if store == nil {
		return ErrBarrierAutoUnsealNoPolicyStore
	}
	return store.ClearAutoUnseal(context.Background())
}

// acquireTPM obtains the TPM instance via the shared accessor.
// The caller MUST call s.tpmAccessor.Load().Release() after a successful call.
func (s *BarrierAutoUnsealService) acquireTPM() (xkms.TrustedPlatformModule, error) {
	accessor := s.tpmAccessor.Load()
	if accessor == nil {
		return nil, ErrBarrierAutoUnsealTPMUnavailable
	}
	tpm, err := accessor.Acquire()
	if err != nil {
		return nil, ErrBarrierAutoUnsealTPMUnavailable
	}
	return tpm, nil
}
