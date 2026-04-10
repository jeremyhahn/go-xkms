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

package tpm2

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// authMockTPM wraps mockTPM to add controllable auth operation behavior.
type authMockTPM struct {
	mockTPM
	verifyAuthErr    error
	changeAuthErr    error
	fixedPropsErr    error
	fixedPropsResult *pkgtpm2.PropertiesFixed
	lockoutResetErr  error
}

func (m *authMockTPM) VerifyAuth(handle tpm2.TPMHandle, authValue []byte) error {
	return m.verifyAuthErr
}

func (m *authMockTPM) ChangeAuth(handle tpm2.TPMHandle, currentAuth, newAuth []byte) error {
	return m.changeAuthErr
}

func (m *authMockTPM) FixedProperties() (*pkgtpm2.PropertiesFixed, error) {
	if m.fixedPropsErr != nil {
		return nil, m.fixedPropsErr
	}
	if m.fixedPropsResult != nil {
		return m.fixedPropsResult, nil
	}
	return &pkgtpm2.PropertiesFixed{}, nil
}

func (m *authMockTPM) DictionaryAttackLockoutReset(lockoutAuth []byte) error {
	return m.lockoutResetErr
}

// newAuthTestBackend creates a Backend with an authMockTPM for auth tests.
func newAuthTestBackend(mock *authMockTPM) *Backend {
	return &Backend{
		tpm:     mock,
		logger:  slog.Default(),
		tracker: backend.NewMemoryAEADTracker(),
		srkAttrs: &types.KeyAttributes{
			CN: "ssrk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
	}
}

// ---------- VerifyAuth ----------

func TestBackend_VerifyAuth_Success(t *testing.T) {
	mock := &authMockTPM{}
	b := newAuthTestBackend(mock)

	if err := b.VerifyAuth("123456"); err != nil {
		t.Fatalf("VerifyAuth should succeed, got: %v", err)
	}
}

func TestBackend_VerifyAuth_BackendClosed(t *testing.T) {
	mock := &authMockTPM{}
	b := newAuthTestBackend(mock)
	b.closed = true

	err := b.VerifyAuth("123456")
	if err == nil {
		t.Fatal("VerifyAuth should fail when backend is closed")
	}
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("expected ErrNotInitialized, got: %v", err)
	}
}

func TestBackend_VerifyAuth_TPMError(t *testing.T) {
	tpmErr := errors.New("tpm2: auth verification failed")
	mock := &authMockTPM{verifyAuthErr: tpmErr}
	b := newAuthTestBackend(mock)

	err := b.VerifyAuth("wrong-pin")
	if err == nil {
		t.Fatal("VerifyAuth should fail when TPM returns error")
	}
	if !errors.Is(err, ErrAuthVerifyFailed) {
		t.Fatalf("expected ErrAuthVerifyFailed, got: %v", err)
	}
	if !errors.Is(err, tpmErr) {
		t.Fatalf("expected wrapped tpm error, got: %v", err)
	}
}

// ---------- ChangeAuth ----------

func TestBackend_ChangeAuth_Success(t *testing.T) {
	mock := &authMockTPM{}
	b := newAuthTestBackend(mock)

	if err := b.ChangeAuth("old-pin", "new-pin"); err != nil {
		t.Fatalf("ChangeAuth should succeed, got: %v", err)
	}
}

func TestBackend_ChangeAuth_BackendClosed(t *testing.T) {
	mock := &authMockTPM{}
	b := newAuthTestBackend(mock)
	b.closed = true

	err := b.ChangeAuth("old-pin", "new-pin")
	if err == nil {
		t.Fatal("ChangeAuth should fail when backend is closed")
	}
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("expected ErrNotInitialized, got: %v", err)
	}
}

func TestBackend_ChangeAuth_TPMError(t *testing.T) {
	tpmErr := errors.New("tpm2: auth change recreate failed")
	mock := &authMockTPM{changeAuthErr: tpmErr}
	b := newAuthTestBackend(mock)

	err := b.ChangeAuth("old-pin", "new-pin")
	if err == nil {
		t.Fatal("ChangeAuth should fail when TPM returns error")
	}
	if !errors.Is(err, ErrAuthChangeFailed) {
		t.Fatalf("expected ErrAuthChangeFailed, got: %v", err)
	}
	if !errors.Is(err, tpmErr) {
		t.Fatalf("expected wrapped tpm error, got: %v", err)
	}
}

// ---------- LockoutStatus ----------

func TestBackend_LockoutStatus_NoFailures(t *testing.T) {
	mock := &authMockTPM{
		fixedPropsResult: &pkgtpm2.PropertiesFixed{
			LockoutCounter:  0,
			MaxAuthFail:     32,
			LockoutRecovery: 7200,
		},
	}
	b := newAuthTestBackend(mock)

	status, err := b.LockoutStatus()
	if err != nil {
		t.Fatalf("LockoutStatus should succeed, got: %v", err)
	}
	if status.FailedAttempts != 0 {
		t.Fatalf("expected 0 failed attempts, got: %d", status.FailedAttempts)
	}
	if status.MaxAttempts != 32 {
		t.Fatalf("expected 32 max attempts, got: %d", status.MaxAttempts)
	}
	if status.IsLocked {
		t.Fatal("expected IsLocked to be false")
	}
	if status.RecoverySeconds != 7200 {
		t.Fatalf("expected 7200 recovery seconds, got: %d", status.RecoverySeconds)
	}
}

func TestBackend_LockoutStatus_Locked(t *testing.T) {
	mock := &authMockTPM{
		fixedPropsResult: &pkgtpm2.PropertiesFixed{
			LockoutCounter:  32,
			MaxAuthFail:     32,
			LockoutRecovery: 600,
		},
	}
	b := newAuthTestBackend(mock)

	status, err := b.LockoutStatus()
	if err != nil {
		t.Fatalf("LockoutStatus should succeed, got: %v", err)
	}
	if !status.IsLocked {
		t.Fatal("expected IsLocked to be true when counter >= max")
	}
	if status.FailedAttempts != 32 {
		t.Fatalf("expected 32 failed attempts, got: %d", status.FailedAttempts)
	}
	if status.RecoverySeconds != 600 {
		t.Fatalf("expected 600 recovery seconds, got: %d", status.RecoverySeconds)
	}
}

func TestBackend_LockoutStatus_BackendClosed(t *testing.T) {
	mock := &authMockTPM{}
	b := newAuthTestBackend(mock)
	b.closed = true

	_, err := b.LockoutStatus()
	if err == nil {
		t.Fatal("LockoutStatus should fail when backend is closed")
	}
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("expected ErrNotInitialized, got: %v", err)
	}
}

func TestBackend_LockoutStatus_TPMError(t *testing.T) {
	tpmErr := errors.New("tpm2: capability query failed")
	mock := &authMockTPM{fixedPropsErr: tpmErr}
	b := newAuthTestBackend(mock)

	_, err := b.LockoutStatus()
	if err == nil {
		t.Fatal("LockoutStatus should fail when FixedProperties returns error")
	}
	if !errors.Is(err, ErrLockoutQueryFailed) {
		t.Fatalf("expected ErrLockoutQueryFailed, got: %v", err)
	}
	if !errors.Is(err, tpmErr) {
		t.Fatalf("expected wrapped tpm error, got: %v", err)
	}
}

func TestBackend_LockoutStatus_ZeroMaxAuthFail(t *testing.T) {
	// When MaxAuthFail is 0, the TPM has no DA protection. IsLocked should be false.
	mock := &authMockTPM{
		fixedPropsResult: &pkgtpm2.PropertiesFixed{
			LockoutCounter:  5,
			MaxAuthFail:     0,
			LockoutRecovery: 0,
		},
	}
	b := newAuthTestBackend(mock)

	status, err := b.LockoutStatus()
	if err != nil {
		t.Fatalf("LockoutStatus should succeed, got: %v", err)
	}
	if status.IsLocked {
		t.Fatal("expected IsLocked to be false when MaxAuthFail is 0")
	}
}

// ---------- ResetLockout ----------

func TestBackend_ResetLockout_Success(t *testing.T) {
	mock := &authMockTPM{}
	b := newAuthTestBackend(mock)

	if err := b.ResetLockout([]byte("lockout-auth")); err != nil {
		t.Fatalf("ResetLockout should succeed, got: %v", err)
	}
}

func TestBackend_ResetLockout_EmptyAuth(t *testing.T) {
	// Empty lockout auth is valid for TPMs with no lockout hierarchy auth set.
	mock := &authMockTPM{}
	b := newAuthTestBackend(mock)

	if err := b.ResetLockout(nil); err != nil {
		t.Fatalf("ResetLockout with nil auth should succeed, got: %v", err)
	}
}

func TestBackend_ResetLockout_BackendClosed(t *testing.T) {
	mock := &authMockTPM{}
	b := newAuthTestBackend(mock)
	b.closed = true

	err := b.ResetLockout([]byte("lockout-auth"))
	if err == nil {
		t.Fatal("ResetLockout should fail when backend is closed")
	}
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("expected ErrNotInitialized, got: %v", err)
	}
}

func TestBackend_ResetLockout_TPMError(t *testing.T) {
	tpmErr := errors.New("tpm2: lockout reset send failed")
	mock := &authMockTPM{lockoutResetErr: tpmErr}
	b := newAuthTestBackend(mock)

	err := b.ResetLockout([]byte("wrong-auth"))
	if err == nil {
		t.Fatal("ResetLockout should fail when TPM returns error")
	}
	if !errors.Is(err, ErrLockoutResetFailed) {
		t.Fatalf("expected ErrLockoutResetFailed, got: %v", err)
	}
	if !errors.Is(err, tpmErr) {
		t.Fatalf("expected wrapped tpm error, got: %v", err)
	}
}
