// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package xkms

import (
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// fakePlatformAuthProvider is a minimal TPMPlatformAuthProvider for
// exercising the PIN SDK aliases without a real TPM.
type fakePlatformAuthProvider struct {
	provisioned bool
	authReady   bool
}

func (f *fakePlatformAuthProvider) VerifyAuth(string) error         { return nil }
func (f *fakePlatformAuthProvider) ChangeAuth(string, string) error { return nil }
func (f *fakePlatformAuthProvider) GetLockoutInfo() (int, int, int, int, error) {
	return 0, 0, 0, 0, nil
}
func (f *fakePlatformAuthProvider) DictionaryAttackLockoutReset([]byte) error { return nil }
func (f *fakePlatformAuthProvider) IsProvisioned() bool                       { return f.provisioned }
func (f *fakePlatformAuthProvider) IsAuthReady() bool                         { return f.authReady }

var _ TPMPlatformAuthProvider = (*fakePlatformAuthProvider)(nil)

// TestPINSelectAliases_Resolve proves the pinselect re-exports name usable
// values: PINSelectConfig accepts a software provider, and
// ErrPINSelectNoSoftwareProvider is the sentinel SelectPINBackend returns
// without one.
func TestPINSelectAliases_Resolve(t *testing.T) {
	_, err := SelectPINBackend(PINSelectConfig{})
	if !errors.Is(err, ErrPINSelectNoSoftwareProvider) {
		t.Fatalf("SelectPINBackend with no Software provider: got %v, want ErrPINSelectNoSoftwareProvider", err)
	}
}

// TestPINSelectSoftwareStorageError_Resolves proves the alias names a
// usable, wrappable error type.
func TestPINSelectSoftwareStorageError_Resolves(t *testing.T) {
	cause := errors.New("disk gone")
	e := &PINSelectSoftwareStorageError{Cause: cause}
	if !errors.Is(e, cause) {
		t.Fatal("errors.Is(e, cause) = false, want true via Unwrap")
	}
}

// TestNewPINTPMBackend_Resolves proves NewPINTPMBackend and PINTPMBackend
// construct a usable PINBackend over a TPMPlatformAuthProvider.
func TestNewPINTPMBackend_Resolves(t *testing.T) {
	backend := NewPINTPMBackend(&fakePlatformAuthProvider{provisioned: true, authReady: true})
	if backend == nil {
		t.Fatal("NewPINTPMBackend returned nil")
	}
	if backend.Strategy() != qrdbsdk.PINStrategyTPM2 {
		t.Fatalf("Strategy() = %q, want %q", backend.Strategy(), qrdbsdk.PINStrategyTPM2)
	}
	if !backend.UserPINSet() {
		t.Fatal("UserPINSet() = false for a provisioned, auth-ready provider")
	}
}
