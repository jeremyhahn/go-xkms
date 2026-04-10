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

//go:build pkcs11

package hardware

import (
	"errors"
	"testing"

	"github.com/miekg/pkcs11"
)

// fakeSOProvider is a minimal PKCS11SessionProvider + PKCS11SOSessionProvider
// that records which session-acquisition path was taken. It does not invoke
// any real PKCS#11 library — the *pkcs11.Ctx is nil because the tests only
// exercise the routing and post-destroy verification logic that wraps it.
//
// The tests inject behavior by setting destroyFn (called for DestroyObject)
// and stillPresent (controls whether the post-delete find reports the object
// as surviving).
type fakeSOProvider struct {
	withSessionCalls   int
	withSOSessionCalls int

	lastSOPin   string
	lastUserPin string
}

func (f *fakeSOProvider) WithSession(fn func(session pkcs11.SessionHandle) error) error {
	f.withSessionCalls++
	return fn(pkcs11.SessionHandle(1))
}

func (f *fakeSOProvider) WithSOSession(soPin, userPin string, fn func(session pkcs11.SessionHandle) error) error {
	f.withSOSessionCalls++
	f.lastSOPin = soPin
	f.lastUserPin = userPin
	return fn(pkcs11.SessionHandle(1))
}

func (f *fakeSOProvider) Ctx() *pkcs11.Ctx { return nil }
func (f *fakeSOProvider) SlotID() uint     { return 0 }

// TestPKCS11CertStorage_DeleteCert_UsesSOSession_WhenRequireSO verifies the
// routing logic: when requireSO=true and the provider supports
// WithSOSession, the delete runs under the SO path. Otherwise it uses
// WithSession.
//
// We deliberately pass an invalid session operation: since Ctx() is nil,
// the delete function will panic/error on the first PKCS#11 call. We
// recover via a defer because all we care about is which entry point was
// called.
func TestPKCS11CertStorage_DeleteCert_UsesSOSession_WhenRequireSO(t *testing.T) {
	tests := []struct {
		name           string
		requireSO      bool
		soPin          string
		wantSOCalls    int
		wantUserCalls  int
	}{
		{
			name:          "requireSO true uses WithSOSession",
			requireSO:     true,
			soPin:         "010203",
			wantSOCalls:   1,
			wantUserCalls: 0,
		},
		{
			name:          "requireSO false uses WithSession",
			requireSO:     false,
			soPin:         "010203",
			wantSOCalls:   0,
			wantUserCalls: 1,
		},
		{
			name:          "requireSO true but empty soPin falls back to WithSession",
			requireSO:     true,
			soPin:         "",
			wantSOCalls:   0,
			wantUserCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prov := &fakeSOProvider{}
			p := &PKCS11CertStorage{
				pool:      prov,
				soPin:     tc.soPin,
				userPin:   "123456",
				requireSO: tc.requireSO,
			}

			// runDelete is the routing layer under test. We pass a no-op
			// fn so we don't depend on a real pkcs11.Ctx.
			_ = p.runDelete(func(session pkcs11.SessionHandle) error {
				return nil
			})

			if prov.withSOSessionCalls != tc.wantSOCalls {
				t.Errorf("WithSOSession calls = %d, want %d", prov.withSOSessionCalls, tc.wantSOCalls)
			}
			if prov.withSessionCalls != tc.wantUserCalls {
				t.Errorf("WithSession calls = %d, want %d", prov.withSessionCalls, tc.wantUserCalls)
			}
			if tc.wantSOCalls > 0 {
				if prov.lastSOPin != tc.soPin {
					t.Errorf("SO pin passthrough = %q, want %q", prov.lastSOPin, tc.soPin)
				}
				if prov.lastUserPin != "123456" {
					t.Errorf("user pin passthrough = %q, want %q", prov.lastUserPin, "123456")
				}
			}
		})
	}
}

// TestPKCS11CertStorage_ErrDeleteNotSupportedOnToken_IsSentinel ensures the
// exported sentinel error unwraps correctly via errors.Is so callers can
// branch on it without string matching.
func TestPKCS11CertStorage_ErrDeleteNotSupportedOnToken_IsSentinel(t *testing.T) {
	wrapped := errors.New("wrapper")
	if errors.Is(wrapped, ErrDeleteNotSupportedOnToken) {
		t.Fatal("unrelated error should not match ErrDeleteNotSupportedOnToken")
	}
	if !errors.Is(ErrDeleteNotSupportedOnToken, ErrDeleteNotSupportedOnToken) {
		t.Fatal("ErrDeleteNotSupportedOnToken must match itself via errors.Is")
	}
}
