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
	"io"

	fido2 "github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/vaultpasskey"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// This file is the personal password vault half of StaticPasswordService:
// the caller's own unlock factors on the connected xkmsd server. The server
// seals the caller's personal entries with a key only these factors unwrap;
// the GUI never holds that key, only forwards the factor the user supplies.
//
// A passkey factor lives on a FIDO2 security key -- a hardware key or the
// running xKey virtual authenticator, both reached over HID. Its secret is
// the key's hmac-secret output, derived by vaultpasskey (the same package
// xkmsctl and the xkey CLI use, so a passkey enrolled here unlocks there).
// Each passkey call blocks until the user touches the key.

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

	// ErrStaticPWSecurityKeyPINRequired indicates an empty security key PIN.
	// A vault passkey is always verified with the key's PIN.
	ErrStaticPWSecurityKeyPINRequired = errors.New("staticpw_service: security key PIN is required")

	// ErrStaticPWSecurityKeyUnavailable indicates no FIDO2 security key
	// could be opened for a vault passkey.
	ErrStaticPWSecurityKeyUnavailable = errors.New("staticpw_service: no FIDO2 security key is available; " +
		"attach one or start the xKey authenticator")

	// ErrStaticPWSecurityKeyPINSealFailed indicates the security key PIN
	// could not be sealed into protected memory.
	ErrStaticPWSecurityKeyPINSealFailed = errors.New("staticpw_service: failed to seal the security key PIN")
)

// vaultAuthenticator is the FIDO2 authenticator a vault passkey runs on.
// *fido2.FIDO2Handler satisfies it.
type vaultAuthenticator interface {
	vaultpasskey.Authenticator
	io.Closer
}

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

// EnrollPasskey creates a vault passkey on the attached security key,
// verified with its PIN, and enrolls it. The first enrollment initializes the
// vault, opens the session and returns the recovery code; later enrollments
// need the session open. The key is touched twice: once to create the
// passkey and once to derive its secret.
func (s *StaticPasswordService) EnrollPasskey(label, pin string) (*PasswordVaultEnrollResult, error) {
	client, pinSecret, err := s.passkeyCall(pin)
	if err != nil {
		return nil, err
	}
	defer pinSecret.Destroy()

	cred, err := s.enrollPasskey(client, pinSecret, label)
	if err != nil {
		return s.auditVaultResult(audit.OpPasswordVaultFactorEnrolled, nil, err)
	}
	defer clear(cred.Secret)
	resp, enrollErr := client.PasswordVaultEnroll(s.getContext(), &transport.PasswordVaultEnrollRequest{
		PasswordVaultCredential: cred,
	})
	return s.auditVaultResult(audit.OpPasswordVaultFactorEnrolled, resp, enrollErr)
}

// enrollPasskey creates a vault passkey on the security key for the relying
// party the server advertises in its vault status.
func (s *StaticPasswordService) enrollPasskey(client transport.Client, pin *secure.Secret, label string) (transport.PasswordVaultCredential, error) {
	status, err := client.PasswordVaultStatus(s.getContext())
	if err != nil {
		return transport.PasswordVaultCredential{}, err
	}
	if status.PasskeyRPID == "" {
		return transport.PasswordVaultCredential{}, vaultpasskey.ErrNoRelyingParty
	}
	return s.withVaultAuthenticator(func(a vaultpasskey.Authenticator) (transport.PasswordVaultCredential, error) {
		return vaultpasskey.Enroll(a, vaultpasskey.Options{PIN: pin, Label: label, RelyingPartyID: status.PasskeyRPID})
	})
}

// UnlockWithPasskey opens the caller's personal password session with a
// vault passkey on the attached security key, verified with its PIN.
func (s *StaticPasswordService) UnlockWithPasskey(pin string) error {
	client, pinSecret, err := s.passkeyCall(pin)
	if err != nil {
		return err
	}
	defer pinSecret.Destroy()

	unlockErr := s.unlockWithPasskey(client, pinSecret)
	details := map[string]any{"factor": vaultpasskey.Factor}
	if auditErr := s.logPasswordEvent(audit.OpPasswordStoreUnlocked, "", unlockErr == nil, unlockErr, details); auditErr != nil {
		return auditErr
	}
	return unlockErr
}

// unlockWithPasskey evaluates the vault's passkeys on the security key and
// sends the unlock credential.
func (s *StaticPasswordService) unlockWithPasskey(client transport.Client, pin *secure.Secret) error {
	ctx := s.getContext()
	status, err := client.PasswordVaultStatus(ctx)
	if err != nil {
		return err
	}
	cred, err := s.withVaultAuthenticator(func(a vaultpasskey.Authenticator) (transport.PasswordVaultCredential, error) {
		return vaultpasskey.Unlock(a, status.Factors, vaultpasskey.Options{PIN: pin})
	})
	if err != nil {
		return err
	}
	defer clear(cred.Secret)
	return client.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: cred})
}

// RecoverWithPasskey uses the one-time recovery code to enroll a new vault
// passkey on the attached security key. It opens the session and returns the
// replacement recovery code.
func (s *StaticPasswordService) RecoverWithPasskey(recoveryCode, label, pin string) (*PasswordVaultEnrollResult, error) {
	if recoveryCode == "" {
		return nil, ErrStaticPWRecoveryCodeRequired
	}
	client, pinSecret, err := s.passkeyCall(pin)
	if err != nil {
		return nil, err
	}
	defer pinSecret.Destroy()

	cred, err := s.enrollPasskey(client, pinSecret, label)
	if err != nil {
		return s.auditVaultResult(audit.OpPasswordVaultRecovered, nil, err)
	}
	defer clear(cred.Secret)
	resp, recoverErr := client.PasswordVaultRecover(s.getContext(), &transport.PasswordVaultRecoverRequest{
		RecoveryCode:            recoveryCode,
		PasswordVaultCredential: cred,
	})
	return s.auditVaultResult(audit.OpPasswordVaultRecovered, resp, recoverErr)
}

// passkeyCall validates the inputs every passkey call shares: a non-empty
// security key PIN, sealed for the authenticator, and a connected client.
// The caller destroys the returned PIN.
func (s *StaticPasswordService) passkeyCall(pin string) (transport.Client, *secure.Secret, error) {
	if pin == "" {
		return nil, nil, ErrStaticPWSecurityKeyPINRequired
	}
	client, err := s.getClient()
	if err != nil {
		return nil, nil, err
	}
	pinSecret, err := secure.NewSecret([]byte(pin))
	if err != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrStaticPWSecurityKeyPINSealFailed, Cause: err}
	}
	return client, pinSecret, nil
}

// withVaultAuthenticator opens the security key, runs fn on it and closes
// it. A close failure fails the call and discards the derived secret.
func (s *StaticPasswordService) withVaultAuthenticator(fn func(vaultpasskey.Authenticator) (transport.PasswordVaultCredential, error)) (cred transport.PasswordVaultCredential, err error) {
	open := s.vaultAuthenticatorOpener
	if open == nil {
		open = openVaultAuthenticator
	}
	authenticator, err := open()
	if err != nil {
		return transport.PasswordVaultCredential{}, &SentinelCauseError{Sentinel: ErrStaticPWSecurityKeyUnavailable, Cause: err}
	}
	defer func() {
		if closeErr := authenticator.Close(); closeErr != nil {
			clear(cred.Secret)
			cred = transport.PasswordVaultCredential{}
			err = errors.Join(err, closeErr)
		}
	}()
	return fn(authenticator)
}

// openVaultAuthenticator opens the attached FIDO2 security key over HID.
func openVaultAuthenticator() (vaultAuthenticator, error) {
	cfg := fido2.DefaultConfig
	handler, err := fido2.NewHandler(&cfg, fido2.NewDefaultEnumerator())
	if err != nil {
		return nil, err
	}
	return handler, nil
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
