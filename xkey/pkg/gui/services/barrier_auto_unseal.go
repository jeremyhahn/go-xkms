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
	"fmt"
	"log/slog"
	"sync/atomic"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/localtpm"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// BarrierAutoUnsealObject names the TPM sealed object, in the system scope of
// xKey's TPM, that holds the barrier credential for auto-unseal. It is bound
// to the scope's auto-unseal policy and to nothing else, so the TPM releases
// it only in the platform state that policy approves.
const BarrierAutoUnsealObject = "xkey-barrier-auto-unseal"

// Barrier auto-unseal typed errors.
var (
	// ErrBarrierAutoUnsealNoPolicyService indicates the local TPM policy
	// service is not available (no TPM, or no data directory).
	ErrBarrierAutoUnsealNoPolicyService = errors.New("barrier_auto_unseal: the local TPM policy service is not available")

	// ErrBarrierAutoUnsealNoBarrier indicates the barrier service is nil.
	ErrBarrierAutoUnsealNoBarrier = errors.New("barrier_auto_unseal: barrier service not configured")

	// ErrBarrierAutoUnsealFailed indicates the TPM released the credential
	// but the barrier refused it.
	ErrBarrierAutoUnsealFailed = errors.New("barrier_auto_unseal: barrier unseal failed")

	// ErrBarrierAutoUnsealRefused indicates the TPM refused to release the
	// barrier credential: the PCRs no longer hold the values the
	// auto-unseal policy approves, or its approval was revoked.
	ErrBarrierAutoUnsealRefused = errors.New("barrier_auto_unseal: the TPM refused to release the barrier credential under the auto-unseal policy")

	// ErrBarrierAutoUnsealNotEnrolled indicates a policy carries the
	// auto-unseal mark but no barrier credential is sealed under it.
	ErrBarrierAutoUnsealNotEnrolled = errors.New("barrier_auto_unseal: no barrier credential is sealed under the auto-unseal policy; enable auto-unseal again")

	// ErrBarrierAutoUnsealPolicyMoved indicates the barrier credential is
	// sealed under another policy than the one carrying the auto-unseal
	// mark.
	ErrBarrierAutoUnsealPolicyMoved = errors.New("barrier_auto_unseal: the barrier credential is sealed under another policy than the auto-unseal policy; enable auto-unseal again")

	// ErrBarrierAutoUnsealEmptyPolicyName indicates an empty policy name.
	ErrBarrierAutoUnsealEmptyPolicyName = errors.New("barrier_auto_unseal: policy name cannot be empty")

	// ErrBarrierAutoUnsealBuiltinPolicy indicates the built-in platform
	// policy was named: auto-unseal needs a named policy of its own.
	ErrBarrierAutoUnsealBuiltinPolicy = errors.New("barrier_auto_unseal: the built-in platform policy cannot carry auto-unseal; create a named policy")

	// ErrBarrierAutoUnsealCredentialRequired indicates an empty barrier
	// credential. A barrier with no credential needs no auto-unseal: the
	// TPM releases it on its own.
	ErrBarrierAutoUnsealCredentialRequired = errors.New("barrier_auto_unseal: the barrier password is required")
)

// BarrierAutoUnsealOption is a functional option for configuring
// BarrierAutoUnsealService.
type BarrierAutoUnsealOption func(*BarrierAutoUnsealService)

// WithBarrierAutoUnsealLocal sets the local TPM policy service over xKey's
// TPM.
func WithBarrierAutoUnsealLocal(l *localtpm.Policies) BarrierAutoUnsealOption {
	return func(s *BarrierAutoUnsealService) {
		s.local.Store(l)
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

// BarrierAutoUnsealService unseals xKey's barrier at boot without a password
// when the platform is in the state a named TPM policy approves.
//
// Auto-unseal is an attribute of a named policy (at most one per scope, set
// with the TPM policy service). Enabling it seals the barrier credential in
// the TPM as BarrierAutoUnsealObject, bound to that policy alone; TryAutoUnseal
// has the TPM unseal it through a policy session, so it is the TPM that
// checks the PCRs and the policy's approval. After a PCR change, a revoke or
// an authority problem the TPM refuses, and the caller falls back to a
// manual unseal.
//
// This is distinct from AutoUnsealService, which handles LUKS volume
// auto-unseal. The local policy service and barrier are stored behind
// atomic pointers so the composition root can wire them after construction
// without racing Wails-bound frontend calls.
type BarrierAutoUnsealService struct {
	local   atomic.Pointer[localtpm.Policies]
	barrier atomic.Pointer[BarrierService]
	logger  *slog.Logger
}

// NewBarrierAutoUnsealService returns a BarrierAutoUnsealService configured
// by opts.
func NewBarrierAutoUnsealService(opts ...BarrierAutoUnsealOption) *BarrierAutoUnsealService {
	s := &BarrierAutoUnsealService{
		logger: slog.Default().With("component", "barrier_auto_unseal_service"),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// SetLocal sets (or replaces) the local TPM policy service.
func (s *BarrierAutoUnsealService) SetLocal(l *localtpm.Policies) {
	s.local.Store(l)
}

// SetBarrier sets the barrier service used for unsealing.
func (s *BarrierAutoUnsealService) SetBarrier(b *BarrierService) {
	s.barrier.Store(b)
}

// requireLocal returns the local TPM policy service or
// ErrBarrierAutoUnsealNoPolicyService.
func (s *BarrierAutoUnsealService) requireLocal() (*localtpm.Policies, error) {
	l := s.local.Load()
	if l == nil {
		return nil, ErrBarrierAutoUnsealNoPolicyService
	}
	return l, nil
}

// TryAutoUnseal unseals the barrier with the credential the TPM releases
// under the scope's auto-unseal policy. strategyID is the barrier's sealing
// strategy.
//
// Returns (true, nil) when the barrier was unsealed, (false, nil) when no
// policy carries the auto-unseal mark, and (false, err) otherwise -- notably
// ErrBarrierAutoUnsealRefused when the TPM refuses the policy session. The
// caller then falls back to a manual unseal.
func (s *BarrierAutoUnsealService) TryAutoUnseal(ctx context.Context, strategyID string) (bool, error) {
	l, err := s.requireLocal()
	if err != nil {
		return false, err
	}
	barrier := s.barrier.Load()
	if barrier == nil {
		return false, ErrBarrierAutoUnsealNoBarrier
	}

	policy, err := l.AutoUnsealPolicy(ctx)
	if errors.Is(err, xkms.ErrTPMPolicyNotFound) {
		s.logger.Debug("barrier-auto-unseal: no auto-unseal policy configured")
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := s.checkEnrolled(ctx, l, policy); err != nil {
		return false, err
	}

	credential, err := l.UnsealObject(ctx, BarrierAutoUnsealObject)
	if err != nil {
		s.logger.Warn("barrier-auto-unseal: the TPM refused the auto-unseal policy, falling back to manual unseal",
			slog.String("policy", policy), slog.String("error", err.Error()))
		return false, &SentinelCauseError{Sentinel: ErrBarrierAutoUnsealRefused, Cause: err}
	}
	defer clear(credential)

	if err := barrier.Unseal(string(credential), strategyID); err != nil {
		s.logger.Error("barrier-auto-unseal: barrier unseal failed", "error", err)
		return false, &SentinelCauseError{Sentinel: ErrBarrierAutoUnsealFailed, Cause: err}
	}
	s.logger.Info("barrier-auto-unseal: barrier unsealed through the TPM policy", slog.String("policy", policy))
	return true, nil
}

// checkEnrolled confirms the barrier credential is sealed under policy.
func (s *BarrierAutoUnsealService) checkEnrolled(ctx context.Context, l *localtpm.Policies, policy string) error {
	assigned, err := l.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{
		KeyID: BarrierAutoUnsealObject,
		Kind:  xkms.TPMObjectKindSealed,
	})
	if errors.Is(err, xkms.ErrTPMPolicyNotAssigned) {
		return ErrBarrierAutoUnsealNotEnrolled
	}
	if err != nil {
		return err
	}
	if assigned.Policy != policy {
		return &DetailError{
			Err:    ErrBarrierAutoUnsealPolicyMoved,
			Detail: fmt.Sprintf(" (sealed under %q, auto-unseal policy is %q)", assigned.Policy, policy),
		}
	}
	return nil
}

// BarrierAutoUnsealStatus is the frontend-facing representation of barrier
// auto-unseal configuration and runtime state.
type BarrierAutoUnsealStatus struct {
	// Available reports whether barrier auto-unseal can be used at all. It
	// is false when there is no local TPM policy service (no TPM, or the
	// data directory is not open yet); Reason then says why and the
	// remaining fields are zero.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`

	BarrierSealed bool `json:"barrier_sealed"`

	// PolicyConfigured reports whether a policy carries the auto-unseal
	// mark, and PolicyName names it.
	PolicyConfigured bool   `json:"policy_configured"`
	PolicyName       string `json:"policy_name"`

	// CredentialSealed reports whether the barrier credential is sealed
	// under that policy, so auto-unseal can run.
	CredentialSealed bool `json:"credential_sealed"`

	// PCRsMatch reports whether the live PCRs match the policy and its
	// approval is current (advisory: the TPM decides at unseal time).
	PCRsMatch bool `json:"pcrs_match"`
}

// GetAutoUnsealStatus returns the current barrier auto-unseal configuration
// and runtime state. Without a local TPM policy service it reports
// Available=false and a nil error, so the frontend can render an
// "unavailable" panel instead of retrying.
func (s *BarrierAutoUnsealService) GetAutoUnsealStatus() (*BarrierAutoUnsealStatus, error) {
	l := s.local.Load()
	if l == nil {
		return &BarrierAutoUnsealStatus{Reason: ErrBarrierAutoUnsealNoPolicyService.Error()}, nil
	}
	status := &BarrierAutoUnsealStatus{Available: true}
	if barrier := s.barrier.Load(); barrier != nil {
		status.BarrierSealed = barrier.GetSealInfo().Sealed
	}

	ctx := context.Background()
	policy, err := l.AutoUnsealPolicy(ctx)
	if errors.Is(err, xkms.ErrTPMPolicyNotFound) {
		return status, nil
	}
	if err != nil {
		return nil, err
	}
	status.PolicyConfigured = true
	status.PolicyName = policy

	switch err := s.checkEnrolled(ctx, l, policy); {
	case err == nil:
		status.CredentialSealed = true
	case errors.Is(err, ErrBarrierAutoUnsealNotEnrolled), errors.Is(err, ErrBarrierAutoUnsealPolicyMoved):
	default:
		return nil, err
	}

	v, err := l.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{Name: policy})
	if err != nil {
		return nil, err
	}
	status.PCRsMatch = v.Match && v.Approved
	return status, nil
}

// EnableAutoUnseal makes policyName the scope's auto-unseal policy and seals
// credential -- the barrier's password -- in the TPM under it, replacing any
// credential sealed before.
func (s *BarrierAutoUnsealService) EnableAutoUnseal(policyName, credential string) error {
	l, err := s.requireLocal()
	if err != nil {
		return err
	}
	switch policyName {
	case "":
		return ErrBarrierAutoUnsealEmptyPolicyName
	case xkms.TPMPolicyPlatform:
		return ErrBarrierAutoUnsealBuiltinPolicy
	}
	if credential == "" {
		return ErrBarrierAutoUnsealCredentialRequired
	}

	ctx := context.Background()
	if err := l.SealObject(ctx, BarrierAutoUnsealObject, policyName, []byte(credential)); err != nil {
		return err
	}
	if _, err := l.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{Name: policyName, Enabled: true}); err != nil {
		return err
	}
	s.logger.Info("barrier-auto-unseal: enabled", slog.String("policy", policyName))
	return nil
}

// DisableAutoUnseal clears the auto-unseal mark and deletes the sealed
// barrier credential. Disabling when nothing is enabled is not an error.
func (s *BarrierAutoUnsealService) DisableAutoUnseal() error {
	l, err := s.requireLocal()
	if err != nil {
		return err
	}
	ctx := context.Background()
	policy, err := l.AutoUnsealPolicy(ctx)
	switch {
	case err == nil:
		if _, err := l.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{Name: policy, Enabled: false}); err != nil {
			return err
		}
	case !errors.Is(err, xkms.ErrTPMPolicyNotFound):
		return err
	}
	if err := l.DeleteObject(ctx, BarrierAutoUnsealObject); err != nil {
		return err
	}
	s.logger.Info("barrier-auto-unseal: disabled")
	return nil
}
