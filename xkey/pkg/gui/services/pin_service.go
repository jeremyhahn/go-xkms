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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// PINStatusInfo describes the current PIN state for the frontend.
type PINStatusInfo struct {
	SOPINSet       bool   `json:"so_pin_set"`
	UserPINSet     bool   `json:"user_pin_set"`
	Initialized    bool   `json:"initialized"`
	Strategy       string `json:"strategy"`
	SOPINSupported bool   `json:"so_pin_supported"`
}

// sopinCapableStrategies is the single, authoritative map of which PIN
// strategies persist an independent Security Officer PIN, separate from
// the string comparisons that used to be scattered across the setup
// wizard and Settings UI. The tpm2 strategy binds all authorization to
// the PlatformSRK auth value (see pkg/pintpm2.TPM2Backend); its
// SetSOPIN/ChangeSOPIN/VerifySOPIN methods always return
// qrdbsdk.ErrPINNotSet by design, so it is listed as unsupported here.
var sopinCapableStrategies = map[qrdbsdk.PINStrategyID]bool{
	qrdbsdk.PINStrategySoftware: true,
	qrdbsdk.PINStrategyTPM2:     false,
	qrdbsdk.PINStrategyPKCS11:   true,
}

// sopinSupported reports whether the given PIN strategy supports a
// separate Security Officer PIN. Strategies not present in
// sopinCapableStrategies default to true (fail open) so that a future
// strategy added without updating this map behaves like the historical
// default rather than silently disabling SO PIN management.
func sopinSupported(strategy qrdbsdk.PINStrategyID) bool {
	supported, known := sopinCapableStrategies[strategy]
	if !known {
		return true
	}
	return supported
}

// mapSOPINUnsupportedErr rewrites qrdbsdk.ErrPINNotSet into the clearer
// ErrSOPINNotSupported when the given strategy does not support a
// separate SO PIN. Errors unrelated to that condition (invalid PIN,
// wrong length, storage failures, etc.) pass through unchanged.
func mapSOPINUnsupportedErr(err error, strategy qrdbsdk.PINStrategyID) error {
	if errors.Is(err, qrdbsdk.ErrPINNotSet) && !sopinSupported(strategy) {
		return ErrSOPINNotSupported
	}
	return err
}

// appLockAttemptsResetter is the subset of AppLockService PINService needs
// to clear the app lock's own unlock-attempt budget (#272) whenever a
// Security Officer successfully authorizes an operation that already
// implies the equivalent of a lockout reset. Using an interface here avoids
// a direct dependency from PINService onto AppLockService.
type appLockAttemptsResetter interface {
	ResetAttempts() error
}

// PINService exposes PIN management to the frontend. It is a thin wrapper
// over the unified qrdbsdk.PINService that adds Wails context and audit logging.
// It is bound to the Wails runtime so every exported method is callable
// from the Svelte frontend.
type PINService struct {
	ctx        context.Context
	log        *slog.Logger
	auditLog   atomic.Pointer[audit.Logger]
	pinSvc     atomic.Pointer[qrdbsdk.PINService]
	barrierSvc atomic.Pointer[BarrierService]
	appLockSvc atomic.Pointer[appLockAttemptsResetter]

	// policy is the enterprise policy section whose UserCanChangeOwnPIN
	// field gates ChangeUserPIN. nil in personal mode. See SetPolicy.
	policy atomic.Pointer[config.PolicySection]
}

// NewPINService creates a new PINService. The underlying qrdbsdk.PINService must
// be wired via SetPINService before PIN operations are available.
func NewPINService() *PINService {
	return &PINService{
		log: slog.Default().With("component", "pin_service"),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *PINService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetAuditLogger sets the audit logger for security event logging.
func (s *PINService) SetAuditLogger(logger audit.Logger) {
	s.auditLog.Store(&logger)
}

// SetPolicy installs the enterprise policy section that gates ChangeUserPIN.
// The GUI calls this with config.DefaultPolicy() before SO login and the
// verified section afterward; see startupEnterprisePolicy and
// applyVerifiedEnterprisePolicy in pkg/gui/enterprise_policy.go.
func (s *PINService) SetPolicy(pol *config.PolicySection) {
	s.policy.Store(pol)
}

// SetPINService wires the underlying qrdbsdk.PINService that handles all PIN
// operations through the selected backend.
func (s *PINService) SetPINService(svc *qrdbsdk.PINService) {
	s.pinSvc.Store(svc)
}

// SetBarrierService wires the barrier service so that PIN changes
// automatically re-seal the barrier root key with the new password.
func (s *PINService) SetBarrierService(svc *BarrierService) {
	if svc == nil {
		return
	}
	s.barrierSvc.Store(svc)
}

// SetAppLockService wires an AppLockService so a successful SO-PIN
// verification here (SetUserPIN, ResetLockout) also clears the app lock's
// own unlock-attempt budget: an operator who has just proven they hold the
// SO PIN should not also be stuck behind a separate, unrelated counter.
func (s *PINService) SetAppLockService(svc appLockAttemptsResetter) {
	if svc == nil {
		return
	}
	s.appLockSvc.Store(&svc)
}

// getAppLockService returns the wired AppLockService, or nil if none was
// set (a headless CLI invocation, or a GUI/daemon composition that has not
// wired one).
func (s *PINService) getAppLockService() appLockAttemptsResetter {
	ptr := s.appLockSvc.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// resetAppLockAttempts clears the wired AppLockService's own unlock-attempt
// budget, when one is wired. A failure here is logged but never fails the
// PIN operation that triggered it: the SO PIN was still verified, and the
// operation it authorized still happened.
func (s *PINService) resetAppLockAttempts(reason string) {
	appLock := s.getAppLockService()
	if appLock == nil {
		return
	}
	if err := appLock.ResetAttempts(); err != nil {
		s.log.Warn("failed to reset app lock unlock-attempt counter",
			"reason", reason, "error", err)
	}
}

// getPINService returns the underlying qrdbsdk.PINService or ErrPINServiceNotConfigured.
func (s *PINService) getPINService() (*qrdbsdk.PINService, error) {
	svc := s.pinSvc.Load()
	if svc == nil {
		return nil, ErrPINServiceNotConfigured
	}
	return svc, nil
}

// Strategy returns the identifier of the active PIN backend strategy, or
// the empty string if no PIN service has been wired yet.
func (s *PINService) Strategy() string {
	svc := s.pinSvc.Load()
	if svc == nil {
		return ""
	}
	return string(svc.Strategy())
}

// SOPINSupported reports whether the active PIN backend supports a
// separate Security Officer PIN, independent from the User PIN. It is
// false for the tpm2 strategy, whose PlatformSRK auth model has no SO
// PIN concept. Callers (the setup wizard, Settings PIN Management) use
// this to skip SO PIN provisioning UI/flows entirely rather than
// surfacing a raw "PIN not set" failure. When no PIN service has been
// wired yet, it defaults to true so callers behave as they did before
// this capability existed.
func (s *PINService) SOPINSupported() bool {
	svc := s.pinSvc.Load()
	if svc == nil {
		return true
	}
	return sopinSupported(svc.Strategy())
}

// getAuditLogger returns the audit logger, or nil if not configured.
func (s *PINService) getAuditLogger() audit.Logger {
	ptr := s.auditLog.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// GetPINStatus returns the current PIN configuration status.
func (s *PINService) GetPINStatus() (result *PINStatusInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetPINStatus", "recover", r)
			result = nil
			retErr = &MessageError{Msg: fmt.Sprintf("pin_service: panic in GetPINStatus: %v", r)}
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return nil, err
	}

	return &PINStatusInfo{
		SOPINSet:       svc.SOPINSet(),
		UserPINSet:     svc.UserPINSet(),
		Initialized:    svc.IsInitialized(),
		Strategy:       string(svc.Strategy()),
		SOPINSupported: sopinSupported(svc.Strategy()),
	}, nil
}

// SetSOPIN sets the Security Officer PIN.
func (s *PINService) SetSOPIN(currentSOPIN, newSOPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in SetSOPIN", "recover", r)
			retErr = &MessageError{Msg: fmt.Sprintf("pin_service: panic in SetSOPIN: %v", r)}
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return err
	}

	if err := svc.SetSOPIN(currentSOPIN, newSOPIN); err != nil {
		err = mapSOPINUnsupportedErr(err, svc.Strategy())
		if auditErr := s.logPINOperation(audit.OpSOPINFailed, false, err, map[string]any{
			"operation": "set",
		}); auditErr != nil {
			return auditErr
		}
		return err
	}

	return s.logPINOperation(audit.OpSOPINChanged, true, nil, map[string]any{
		"operation": "set",
	})
}

// SetUserPIN sets the user PIN. Requires SO PIN authorization.
// The FIDO2 PIN hash is pushed to the authenticator automatically
// by the underlying qrdbsdk.PINService.
func (s *PINService) SetUserPIN(soPIN, newUserPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in SetUserPIN", "recover", r)
			retErr = &MessageError{Msg: fmt.Sprintf("pin_service: panic in SetUserPIN: %v", r)}
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return err
	}

	if err := svc.SetUserPIN(soPIN, newUserPIN); err != nil {
		if auditErr := s.logPINOperation(audit.OpPINFailed, false, err, map[string]any{
			"operation": "set",
			"type":      "user_pin",
		}); auditErr != nil {
			return auditErr
		}
		return err
	}

	if auditErr := s.logPINOperation(audit.OpPINChanged, true, nil, map[string]any{
		"operation": "set",
		"type":      "user_pin",
	}); auditErr != nil {
		return auditErr
	}

	// Setting the user PIN requires and just verified the SO PIN, so this
	// carries the same authority as an explicit lockout reset (#272): an
	// operator who has proven they hold the SO PIN should not also be
	// stuck behind the app lock's own unlock-attempt budget.
	s.resetAppLockAttempts("set_user_pin")
	return nil
}

// ChangeSOPIN changes the Security Officer PIN.
func (s *PINService) ChangeSOPIN(currentSOPIN, newSOPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ChangeSOPIN", "recover", r)
			retErr = &MessageError{Msg: fmt.Sprintf("pin_service: panic in ChangeSOPIN: %v", r)}
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return err
	}

	if err := svc.ChangeSOPIN(currentSOPIN, newSOPIN); err != nil {
		err = mapSOPINUnsupportedErr(err, svc.Strategy())
		if auditErr := s.logPINOperation(audit.OpSOPINFailed, false, err, map[string]any{
			"operation": "change",
		}); auditErr != nil {
			return auditErr
		}
		return err
	}

	return s.logPINOperation(audit.OpSOPINChanged, true, nil, map[string]any{
		"operation": "change",
	})
}

// ChangeUserPIN changes the user PIN. The FIDO2 PIN hash is updated
// automatically by the underlying qrdbsdk.PINService.
//
// Returns a *PolicyDeniedError if enterprise policy's UserCanChangeOwnPIN
// is false: the user may not change their own PIN even when it is set.
// An SO resetting the PIN goes through SetUserPIN instead, which this
// field does not gate.
//
// When a barrier service is wired, the change commits only when the current
// user PIN verifiably seals the barrier; the barrier is then rewrapped from
// the current to the new PIN. Otherwise ChangeUserPIN returns an error
// wrapping ErrBarrierNotPINSealed and the cause, before the PIN backend is
// called: a barrier sealed with its own password must have its credential
// changed separately (pending go-xkms #2098).
func (s *PINService) ChangeUserPIN(currentUserPIN, newUserPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ChangeUserPIN", "recover", r)
			retErr = &MessageError{Msg: fmt.Sprintf("pin_service: panic in ChangeUserPIN: %v", r)}
		}
	}()

	if pol := s.policy.Load(); pol != nil && !pol.UserCanChangeOwnPIN {
		err := &PolicyDeniedError{Field: "user_can_change_own_pin"}
		if auditErr := s.logPINOperation(audit.OpPolicyDenied, false, err, map[string]any{
			"operation": "change",
			"type":      "user_pin",
		}); auditErr != nil {
			return errors.Join(err, auditErr)
		}
		return err
	}

	svc, err := s.getPINService()
	if err != nil {
		return err
	}

	// Order matters (Codex P1 pin_service.go:393): the barrier check below
	// tests the current PIN in software, outside any retry counter, so it
	// must never see a PIN the backend has not authenticated. First refuse
	// an invalid replacement PIN, so the answer cannot depend on the
	// current PIN; then authenticate the current PIN through the backend's
	// retry-enforced verification (TPM2 dictionary-attack protection,
	// PKCS#11 token lockout), which counts a wrong guess and honours
	// lockout, returning its error unchanged.
	if err := validateReplacementUserPIN(newUserPIN); err != nil {
		s.log.Warn("ChangeUserPIN: replacement PIN rejected", "error", err)
		if auditErr := s.logPINOperation(audit.OpPINFailed, false, err, map[string]any{
			"operation": "change",
			"type":      "user_pin",
			"reason":    "invalid_new_pin",
		}); auditErr != nil {
			return errors.Join(err, auditErr)
		}
		return err
	}
	if err := svc.VerifyUserPIN(currentUserPIN); err != nil {
		s.log.Warn("ChangeUserPIN: current PIN not authenticated", "strategy", svc.Strategy(), "error", err)
		// A locked backend is audited as the login path audits it (the
		// lockout event security monitoring keys on), not as a failed
		// attempt; a plain wrong PIN keeps the failed-attempt audit.
		locked, auditErr := s.auditUserPINLockout(svc)
		if auditErr != nil {
			return errors.Join(err, auditErr)
		}
		if locked {
			return err
		}
		if auditErr := s.logPINOperation(audit.OpPINFailed, false, err, map[string]any{
			"operation": "change",
			"type":      "user_pin",
			"reason":    "current_pin_rejected",
		}); auditErr != nil {
			return errors.Join(err, auditErr)
		}
		return err
	}

	// Confirm BEFORE the PIN backend commits that the current user PIN
	// seals the barrier. Any other outcome (credential mismatch, strategy or
	// enclave failure, storage error, uninitialized barrier) refuses the
	// change while nothing has changed yet: a barrier sealed with its own
	// password cannot be told apart from a failing PIN-bound one until
	// go-qrdb reports distinct operational errors (go-xkms #2098).
	//
	// Only a passphrase barrier can be sealed by the user PIN. A hardware or
	// external strategy (TPM2, PKCS#11, cloud KMS) is not, so it is neither
	// probed here nor rewrapped below: its PIN change rests on the backend's
	// retry-enforced verify above. An unknown strategy (nothing initialized
	// or recorded) stays on the passphrase path and is refused there.
	bsvc := s.barrierSvc.Load()
	if bsvc != nil {
		if strategy := bsvc.sealStrategy(); strategy != "" && strategy != xkms.StrategyPassphrase {
			s.log.Debug("ChangeUserPIN: barrier not PIN-sealed by strategy; skipping barrier check", "barrier_strategy", strategy)
			bsvc = nil
		}
	}
	if bsvc != nil {
		if err := verifyBarrierSealedWithPIN(bsvc, currentUserPIN); err != nil {
			s.log.Error("ChangeUserPIN: barrier not confirmed sealed by the user PIN", "error", err)
			refused := &SentinelCauseError{Sentinel: ErrBarrierNotPINSealed, Cause: err}
			if auditErr := s.logPINOperation(audit.OpPINFailed, false, refused, map[string]any{
				"operation": "barrier_check",
				"type":      "user_pin",
				"reason":    "not_confirmed",
			}); auditErr != nil {
				return errors.Join(refused, auditErr)
			}
			return refused
		}
	}

	s.log.Debug("ChangeUserPIN: attempting PIN change", "strategy", svc.Strategy())

	if err := svc.ChangeUserPIN(currentUserPIN, newUserPIN); err != nil {
		s.log.Warn("ChangeUserPIN: failed", "strategy", svc.Strategy(), "error", err)
		if auditErr := s.logPINOperation(audit.OpPINFailed, false, err, map[string]any{
			"operation": "change",
			"type":      "user_pin",
		}); auditErr != nil {
			return auditErr
		}
		return err
	}

	s.log.Info("ChangeUserPIN: PIN changed successfully", "strategy", svc.Strategy())
	if auditErr := s.logPINOperation(audit.OpPINChanged, true, nil, map[string]any{
		"operation": "change",
		"type":      "user_pin",
	}); auditErr != nil {
		return auditErr
	}

	// Re-seal the PIN-sealed barrier root key with the new PIN so that the
	// next unseal after restart uses the updated credential.
	if bsvc != nil {
		if err := bsvc.ChangePassword(currentUserPIN, newUserPIN); err != nil {
			s.log.Error("ChangeUserPIN: barrier re-seal failed", "error", err)
			if auditErr := s.logPINOperation(audit.OpPINFailed, false, err, map[string]any{
				"operation": "barrier_reseal",
				"type":      "user_pin",
			}); auditErr != nil {
				return auditErr
			}
			return ErrBarrierResealFailed
		}
		s.log.Info("ChangeUserPIN: barrier re-sealed with new PIN")
	}
	return nil
}

// verifyBarrierSealedWithPIN returns nil only when bsvc's barrier root key
// is confirmed sealed under pin, without changing the barrier: go-qrdb's
// VerifyCredentials unseals a candidate root key from the persisted blob and
// compares it with the live one. Every other outcome is an error: no
// barrier, a sealed barrier, an unreadable blob, or a credential mismatch.
// go-qrdb v0.58.4 turns every UnsealRootKey failure (a strategy or enclave
// failure included) into its credential-mismatch error, so a mismatch does
// not prove the barrier is sealed by some other credential; the caller
// refuses on every error and logs the cause unchanged.
func verifyBarrierSealedWithPIN(bsvc *BarrierService, pin string) (err error) {
	bsvc.mu.Lock()
	defer bsvc.mu.Unlock()

	if bsvc.barrier == nil {
		return ErrBarrierNotInitialized
	}
	ctx := bsvc.context()
	// CredentialsFor: a hardware-backed barrier may be checked with an
	// empty PIN; NewCredentials would refuse that input.
	creds, err := xkms.CredentialsFor(ctx, []byte(pin))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, xkms.DestroySealCredentials(creds)) }()

	return bsvc.barrier.VerifyCredentials(ctx, creds)
}

// errReplacementPINAccepted is what replacementPINProbe returns once
// go-qrdb's PIN service has accepted the replacement PIN.
var errReplacementPINAccepted = errors.New("pin_service: replacement PIN accepted")

// replacementPINProbe is a PIN backend that commits nothing: go-qrdb's
// Service.ChangeUserPIN validates the replacement PIN before it calls the
// backend, so reaching ChangeUserPIN here means the PIN passed. No other
// method is ever called; the embedded interface is nil.
type replacementPINProbe struct{ qrdbsdk.PINBackend }

func (replacementPINProbe) ChangeUserPIN(_, _ string) error { return errReplacementPINAccepted }

// validateReplacementUserPIN applies go-qrdb's own replacement-PIN rules
// (its unexported length validator, reached through Service.ChangeUserPIN
// on a probe backend) without touching the real backend, so the rules are
// never copied here and cannot drift from the commit path.
func validateReplacementUserPIN(newUserPIN string) error {
	err := qrdbsdk.NewPINService(replacementPINProbe{}, slog.Default()).ChangeUserPIN("", newUserPIN)
	if errors.Is(err, errReplacementPINAccepted) {
		return nil
	}
	return err
}

// VerifyUserPIN verifies the provided user PIN.
func (s *PINService) VerifyUserPIN(userPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in VerifyUserPIN", "recover", r)
			retErr = &MessageError{Msg: fmt.Sprintf("pin_service: panic in VerifyUserPIN: %v", r)}
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		s.log.Warn("VerifyUserPIN: no PIN service configured", "error", err)
		if auditErr := s.logPINOperation(audit.OpPINFailed, false, err, nil); auditErr != nil {
			return auditErr
		}
		return err
	}

	s.log.Debug("VerifyUserPIN: attempting verification",
		"strategy", svc.Strategy(),
		"user_pin_set", svc.UserPINSet())

	if err := svc.VerifyUserPIN(userPIN); err != nil {
		s.log.Warn("VerifyUserPIN: verification failed",
			"error", err,
			"strategy", svc.Strategy())
		if auditErr := s.logPINOperation(audit.OpPINFailed, false, err, map[string]any{
			"type": "user_pin",
		}); auditErr != nil {
			return auditErr
		}
		// Check if this verification failure resulted in lockout.
		if _, auditErr := s.auditUserPINLockout(svc); auditErr != nil {
			return auditErr
		}
		return err
	}

	s.log.Debug("VerifyUserPIN: verification succeeded")
	return s.logPINOperation(audit.OpPINVerified, true, nil, map[string]any{
		"type": "user_pin",
	})
}

// VerifySOPIN verifies the provided SO PIN.
func (s *PINService) VerifySOPIN(soPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in VerifySOPIN", "recover", r)
			retErr = &MessageError{Msg: fmt.Sprintf("pin_service: panic in VerifySOPIN: %v", r)}
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		if auditErr := s.logPINOperation(audit.OpSOPINFailed, false, err, nil); auditErr != nil {
			return auditErr
		}
		return err
	}

	if err := svc.VerifySOPIN(soPIN); err != nil {
		err = mapSOPINUnsupportedErr(err, svc.Strategy())
		if auditErr := s.logPINOperation(audit.OpSOPINFailed, false, err, map[string]any{
			"type": "so_pin",
		}); auditErr != nil {
			return auditErr
		}
		return err
	}

	return s.logPINOperation(audit.OpSOPINVerified, true, nil, map[string]any{
		"type": "so_pin",
	})
}

// GetLockoutStatus returns the current lockout status from the backend.
func (s *PINService) GetLockoutStatus() (result *qrdbsdk.PINLockoutStatus, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in GetLockoutStatus", "recover", r)
			result = nil
			retErr = &MessageError{Msg: fmt.Sprintf("pin_service: panic in GetLockoutStatus: %v", r)}
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return nil, err
	}

	status := svc.GetLockoutStatus()
	if status == nil {
		// Software backend returns nil (no native lockout). Return a zero-value
		// struct so the frontend always receives a defined object instead of null.
		status = &qrdbsdk.PINLockoutStatus{}
	}
	return status, nil
}

// ResetLockout resets the lockout counter using SO PIN authorization.
func (s *PINService) ResetLockout(soPIN string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ResetLockout", "recover", r)
			retErr = &MessageError{Msg: fmt.Sprintf("pin_service: panic in ResetLockout: %v", r)}
		}
	}()

	svc, err := s.getPINService()
	if err != nil {
		return err
	}

	if err := svc.ResetLockout(soPIN); err != nil {
		return err
	}

	// The PIN backend's own lockout is reset; the app lock's independent
	// unlock-attempt budget (#272) is reset alongside it, so an operator
	// who has just proven they hold the SO PIN is not left blocked by a
	// counter this call does not otherwise touch.
	s.resetAppLockAttempts("reset_lockout")
	return nil
}

// IsPINSet returns true if the user PIN has been configured. Implements
// the PINVerifier pattern for the FIDO2 authenticator.
func (s *PINService) IsPINSet() bool {
	svc := s.pinSvc.Load()
	if svc == nil {
		return false
	}
	return svc.IsPINSet()
}

// VerifyFIDO2Hash compares the provided FIDO2 PIN hash against the backend's
// cached hash. Implements the FIDO2HashVerifier pattern.
func (s *PINService) VerifyFIDO2Hash(hash []byte) bool {
	svc := s.pinSvc.Load()
	if svc == nil {
		return false
	}
	return svc.VerifyFIDO2Hash(hash)
}

// logPINOperation logs a PIN operation to the audit log. Every PIN
// operation is SeveritySecurity, so the caller must propagate a non-nil
// return and fail the request rather than proceed unaudited.
// auditUserPINLockout records the OpPINLocked event when the backend reports
// the user PIN locked after a refused verification, and reports whether it
// was locked. VerifyUserPIN and ChangeUserPIN share it so a lockout reached
// through either is audited the same way.
func (s *PINService) auditUserPINLockout(svc *qrdbsdk.PINService) (bool, error) {
	status := svc.GetLockoutStatus()
	if status == nil || !status.IsLocked {
		return false, nil
	}
	return true, s.logPINOperation(audit.OpPINLocked, false, nil, map[string]any{
		"type":            "user_pin",
		"failed_attempts": status.FailedAttempts,
	})
}

func (s *PINService) logPINOperation(op audit.OperationType, success bool, err error, details map[string]any) error {
	logger := s.getAuditLogger()
	if logger == nil {
		return nil
	}
	backend := "unknown"
	if svc := s.pinSvc.Load(); svc != nil {
		backend = string(svc.Strategy())
	}
	return logger.LogPINOperation(op, backend, success, err, details)
}
