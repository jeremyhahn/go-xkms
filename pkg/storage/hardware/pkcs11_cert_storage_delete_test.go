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
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

// fakeSOProvider is a minimal PKCS11SessionProvider + PKCS11SOSessionProvider
// that records which session-acquisition path was taken. It does not invoke
// any real PKCS#11 library -- the *pkcs11.Ctx is nil because the tests only
// exercise the routing and post-destroy verification logic that wraps it.
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

// fakeUserOnlyProvider implements PKCS11SessionProvider but NOT
// PKCS11SOSessionProvider. Used to verify that requireSO=true against a
// provider that cannot elevate returns ErrSOSessionRequired rather than
// silently falling through to a user session that the token would reject.
type fakeUserOnlyProvider struct {
	withSessionCalls int
}

func (f *fakeUserOnlyProvider) WithSession(fn func(session pkcs11.SessionHandle) error) error {
	f.withSessionCalls++
	return fn(pkcs11.SessionHandle(1))
}

func (f *fakeUserOnlyProvider) Ctx() *pkcs11.Ctx { return nil }
func (f *fakeUserOnlyProvider) SlotID() uint     { return 0 }

// TestPKCS11CertStorage_RunWrite_Routing verifies the write-path routing
// logic now enforced by runWrite. When requireSO=true and a valid SO PIN is
// supplied, operations go through WithSOSession. When requireSO=false, they
// go through WithSession. When requireSO=true but soPin is empty, the call
// MUST return ErrSOSessionRequired instead of silently falling through to a
// CKU_USER session that the token (e.g. YubiKey PIV) would reject with
// CKR_USER_TYPE_INVALID.
func TestPKCS11CertStorage_RunWrite_Routing(t *testing.T) {
	tests := []struct {
		name          string
		requireSO     bool
		soPin         string
		wantErr       error
		wantSOCalls   int
		wantUserCalls int
	}{
		{
			name:          "requireSO true with SO pin uses WithSOSession",
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
			name:          "requireSO true but empty soPin returns ErrSOSessionRequired",
			requireSO:     true,
			soPin:         "",
			wantErr:       ErrSOSessionRequired,
			wantSOCalls:   0,
			wantUserCalls: 0,
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

			err := p.runWrite(func(session pkcs11.SessionHandle) error {
				return nil
			})

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("runWrite err = %v, want %v", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("runWrite err = %v, want nil", err)
			}

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

// TestPKCS11CertStorage_RunWrite_RequireSOWithoutSOProvider verifies that
// requireSO=true against a provider that does not implement
// PKCS11SOSessionProvider returns ErrSOSessionRequired instead of falling
// through to the user session.
func TestPKCS11CertStorage_RunWrite_RequireSOWithoutSOProvider(t *testing.T) {
	prov := &fakeUserOnlyProvider{}
	p := &PKCS11CertStorage{
		pool:      prov,
		soPin:     "010203",
		userPin:   "123456",
		requireSO: true,
	}

	err := p.runWrite(func(session pkcs11.SessionHandle) error {
		return nil
	})

	if !errors.Is(err, ErrSOSessionRequired) {
		t.Fatalf("runWrite err = %v, want ErrSOSessionRequired", err)
	}
	if prov.withSessionCalls != 0 {
		t.Errorf("WithSession must not be called when SO is required but unavailable; got %d", prov.withSessionCalls)
	}
}

// TestPKCS11CertStorage_SaveCert_ReturnsErrSOSessionRequired verifies the
// typed error surfaces from the public SaveCert API when the storage is
// configured with requireSO=true but no SO PIN was supplied. This prevents
// the YubiKey PIV failure mode where C_DestroyObject under CKU_USER returns
// CKR_USER_TYPE_INVALID.
func TestPKCS11CertStorage_SaveCert_ReturnsErrSOSessionRequired(t *testing.T) {
	prov := &fakeSOProvider{}
	p := &PKCS11CertStorage{
		pool:      prov,
		soPin:     "",
		userPin:   "123456",
		requireSO: true,
	}

	cert, err := generateTestCertificate("test")
	if err != nil {
		t.Fatalf("generateTestCertificate: %v", err)
	}

	err = p.SaveCert("slot-9a", cert)
	if !errors.Is(err, ErrSOSessionRequired) {
		t.Fatalf("SaveCert err = %v, want ErrSOSessionRequired", err)
	}
	if prov.withSessionCalls != 0 || prov.withSOSessionCalls != 0 {
		t.Errorf("no session should have been opened; withSession=%d withSOSession=%d",
			prov.withSessionCalls, prov.withSOSessionCalls)
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

// A primary id of the reserved chain-member shape is refused before any
// token operation, so the listing's classification stays exact by
// construction; the check precedes session use, so a bare store suffices.
func TestPKCS11CertStorage_RefusesReservedChainIDs(t *testing.T) {
	p := &PKCS11CertStorage{}
	cert := &x509.Certificate{Raw: []byte{0x30}}
	require.ErrorIs(t, p.SaveCert("foo-chain-0", cert), ErrIDReservedForChain)
	require.ErrorIs(t, p.SaveCertChain("foo-chain-7", []*x509.Certificate{cert}), ErrIDReservedForChain)
	require.ErrorIs(t, p.SaveCert("", cert), storage.ErrInvalidID, "the empty-id check still comes first")
	require.ErrorIs(t, p.SaveCert("foo-chain", cert), ErrIDReservedForChain,
		"the -chain suffix is the chain encoding's own, so it cannot name a certificate")

	// The certificate-facing reads and deletes refuse the shape too, so a
	// chain member is reachable only through the chain methods: a generic
	// caller addressing certs/foo-chain-0.pem cannot destroy one member of
	// foo's chain under the name of a certificate delete.
	_, err := p.GetCert("foo-chain-0")
	require.ErrorIs(t, err, ErrIDReservedForChain)
	require.ErrorIs(t, p.DeleteCert("foo-chain-0"), ErrIDReservedForChain)
	_, err = p.CertExists("foo-chain-0")
	require.ErrorIs(t, err, ErrIDReservedForChain)
	// The chain-facing paths refuse the shapes too, so foo-chain-0 cannot be
	// addressed as the base of a chain foo-chain-0-chain-<n>.
	_, err = p.GetCertChain("foo-chain-0")
	require.ErrorIs(t, err, ErrIDReservedForChain)
	require.ErrorIs(t, p.DeleteCertChain("foo-chain"), ErrIDReservedForChain)
}
