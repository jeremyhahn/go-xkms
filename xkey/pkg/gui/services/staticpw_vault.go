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
	"errors"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// This file is the personal password vault half of StaticPasswordService:
// the caller's own unlock factors on the connected xkmsd server. The server
// seals the caller's personal entries with a key only these factors unwrap;
// the GUI never holds that key, only forwards the factor the user supplies.

// vaultFactorPassphrase is the wire name of the passphrase vault factor.
const vaultFactorPassphrase = "passphrase"

// Personal password vault errors.
var (
	// ErrStaticPWPassphraseRequired indicates an empty vault passphrase.
	ErrStaticPWPassphraseRequired = errors.New("staticpw_service: vault passphrase is required")

	// ErrStaticPWFactorIDRequired indicates an empty vault factor ID.
	ErrStaticPWFactorIDRequired = errors.New("staticpw_service: vault factor ID is required")

	// ErrStaticPWRecoveryCodeRequired indicates an empty recovery code.
	ErrStaticPWRecoveryCodeRequired = errors.New("staticpw_service: recovery code is required")
)

// PasswordVaultFactor is the frontend-facing description of one enrolled
// vault factor. It never carries key material.
type PasswordVaultFactor struct {
	ID        string `json:"id"`
	Factor    string `json:"factor"`
	Label     string `json:"label"`
	CreatedAt string `json:"created_at"`
}

// PasswordVaultStatus is the frontend-facing state of the caller's vault.
type PasswordVaultStatus struct {
	Initialized bool                  `json:"initialized"`
	Unlocked    bool                  `json:"unlocked"`
	Factors     []PasswordVaultFactor `json:"factors"`
}

// PasswordVaultEnrollResult is an enrolled factor and, on the first
// enrollment or a recovery, the recovery code the server shows exactly once.
type PasswordVaultEnrollResult struct {
	Factor       PasswordVaultFactor `json:"factor"`
	RecoveryCode string              `json:"recovery_code,omitempty"`
}

// Unlock opens the caller's personal password session with their vault
// passphrase.
func (s *StaticPasswordService) Unlock(passphrase string) error {
	if passphrase == "" {
		return ErrStaticPWPassphraseRequired
	}
	client, err := s.getClient()
	if err != nil {
		return err
	}
	unlockErr := client.PasswordStoreUnlock(s.getContext(), &transport.PasswordStoreUnlockRequest{
		PasswordVaultCredential: passphraseCredential(passphrase, ""),
	})
	if auditErr := s.logPasswordEvent(audit.OpPasswordStoreUnlocked, "", unlockErr == nil, unlockErr, nil); auditErr != nil {
		return auditErr
	}
	return unlockErr
}

// VaultStatus reports whether the caller's vault is initialized and
// unlocked, and lists its enrolled factors.
func (s *StaticPasswordService) VaultStatus() (*PasswordVaultStatus, error) {
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.PasswordVaultStatus(s.getContext())
	if err != nil {
		return nil, err
	}
	factors := make([]PasswordVaultFactor, 0, len(resp.Factors))
	for _, f := range resp.Factors {
		factors = append(factors, toVaultFactor(f))
	}
	return &PasswordVaultStatus{
		Initialized: resp.Initialized,
		Unlocked:    resp.Unlocked,
		Factors:     factors,
	}, nil
}

// EnrollPassphrase enrolls a passphrase factor. The first enrollment
// initializes the vault, opens the session and returns the recovery code;
// later enrollments need the session open.
func (s *StaticPasswordService) EnrollPassphrase(passphrase, label string) (*PasswordVaultEnrollResult, error) {
	if passphrase == "" {
		return nil, ErrStaticPWPassphraseRequired
	}
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}
	resp, enrollErr := client.PasswordVaultEnroll(s.getContext(), &transport.PasswordVaultEnrollRequest{
		PasswordVaultCredential: passphraseCredential(passphrase, label),
	})
	return s.auditVaultResult(audit.OpPasswordVaultFactorEnrolled, resp, enrollErr)
}

// RotatePassphrase replaces the passphrase of factor factorID. The rotated
// factor gets a new ID; label names it (pass the current label to keep it).
func (s *StaticPasswordService) RotatePassphrase(factorID, passphrase, label string) (*PasswordVaultEnrollResult, error) {
	if factorID == "" {
		return nil, ErrStaticPWFactorIDRequired
	}
	if passphrase == "" {
		return nil, ErrStaticPWPassphraseRequired
	}
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}
	resp, rotateErr := client.PasswordVaultRotate(s.getContext(), &transport.PasswordVaultRotateRequest{
		FactorID:                factorID,
		PasswordVaultCredential: passphraseCredential(passphrase, label),
	})
	return s.auditVaultResult(audit.OpPasswordVaultFactorRotated, resp, rotateErr)
}

// RemoveVaultFactor removes factor factorID. The session must be open and the
// last passphrase or passkey cannot be removed.
func (s *StaticPasswordService) RemoveVaultFactor(factorID string) error {
	if factorID == "" {
		return ErrStaticPWFactorIDRequired
	}
	client, err := s.getClient()
	if err != nil {
		return err
	}
	removeErr := client.PasswordVaultRemoveFactor(s.getContext(), &transport.PasswordVaultRemoveFactorRequest{
		FactorID: factorID,
	})
	details := map[string]any{"factor_id": factorID}
	if auditErr := s.logPasswordEvent(audit.OpPasswordVaultFactorRemoved, "", removeErr == nil, removeErr, details); auditErr != nil {
		return auditErr
	}
	return removeErr
}

// RecoverWithPassphrase uses the one-time recovery code to enroll a new
// passphrase factor. It opens the session and returns the replacement
// recovery code.
func (s *StaticPasswordService) RecoverWithPassphrase(recoveryCode, passphrase, label string) (*PasswordVaultEnrollResult, error) {
	if recoveryCode == "" {
		return nil, ErrStaticPWRecoveryCodeRequired
	}
	if passphrase == "" {
		return nil, ErrStaticPWPassphraseRequired
	}
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}
	resp, recoverErr := client.PasswordVaultRecover(s.getContext(), &transport.PasswordVaultRecoverRequest{
		RecoveryCode:            recoveryCode,
		PasswordVaultCredential: passphraseCredential(passphrase, label),
	})
	return s.auditVaultResult(audit.OpPasswordVaultRecovered, resp, recoverErr)
}

// auditVaultResult records a factor-changing vault operation and converts
// its response for the frontend. A failed audit write fails the operation.
func (s *StaticPasswordService) auditVaultResult(op audit.OperationType, resp *transport.PasswordVaultEnrollResponse, opErr error) (*PasswordVaultEnrollResult, error) {
	var details map[string]any
	if opErr == nil {
		details = map[string]any{"factor_id": resp.Factor.ID, "factor": resp.Factor.Factor}
	}
	if auditErr := s.logPasswordEvent(op, "", opErr == nil, opErr, details); auditErr != nil {
		return nil, auditErr
	}
	if opErr != nil {
		return nil, opErr
	}
	return &PasswordVaultEnrollResult{
		Factor:       toVaultFactor(resp.Factor),
		RecoveryCode: resp.RecoveryCode,
	}, nil
}

// passphraseCredential builds the passphrase vault credential.
func passphraseCredential(passphrase, label string) transport.PasswordVaultCredential {
	return transport.PasswordVaultCredential{
		Factor:     vaultFactorPassphrase,
		Passphrase: passphrase,
		Label:      label,
	}
}

// toVaultFactor converts a transport factor to its frontend form.
func toVaultFactor(f transport.PasswordVaultFactor) PasswordVaultFactor {
	return PasswordVaultFactor{
		ID:        f.ID,
		Factor:    f.Factor,
		Label:     f.Label,
		CreatedAt: f.CreatedAt,
	}
}
