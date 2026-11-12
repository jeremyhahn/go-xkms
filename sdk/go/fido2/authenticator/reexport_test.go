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

package authenticator_test

import (
	"reflect"
	"testing"

	pkgauth "github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator"
)

func TestReexport_Constants(t *testing.T) {
	ints := []struct {
		name      string
		got, want int64
	}{
		{"ClientDataHashSize", int64(authenticator.ClientDataHashSize), int64(pkgauth.ClientDataHashSize)},
		{"CmdGetAssertion", int64(authenticator.CmdGetAssertion), int64(pkgauth.CmdGetAssertion)},
		{"CmdMakeCredential", int64(authenticator.CmdMakeCredential), int64(pkgauth.CmdMakeCredential)},
		{"COSEAlgES384", int64(authenticator.COSEAlgES384), int64(pkgauth.COSEAlgES384)},
		{"VendorCmdSetSOPIN", int64(authenticator.VendorCmdSetSOPIN), int64(pkgauth.VendorCmdSetSOPIN)},
	}
	for _, c := range ints {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestReexport_Types passes a pointer to each SDK type where a pointer to
// the pkg type is expected: it compiles only if the two are identical.
func TestReexport_Types(t *testing.T) {
	takesAuditLogger := func(*pkgauth.AuditLogger) {}
	takesAuditLogger((*authenticator.AuditLogger)(nil))
	takesState := func(*pkgauth.AuthenticatorState) {}
	takesState((*authenticator.AuthenticatorState)(nil))
	takesAutoGrant := func(*pkgauth.AutoGrantHandler) {}
	takesAutoGrant((*authenticator.AutoGrantHandler)(nil))
	takesInteractive := func(*pkgauth.InteractiveHandler) {}
	takesInteractive((*authenticator.InteractiveHandler)(nil))
	takesMemory := func(*pkgauth.MemoryStorage) {}
	takesMemory((*authenticator.MemoryStorage)(nil))
}

func TestReexport_Functions(t *testing.T) {
	funcs := []struct {
		name      string
		got, want any
	}{
		{"DefaultConfig", authenticator.DefaultConfig, pkgauth.DefaultConfig},
		{"NewAuthenticatorState", authenticator.NewAuthenticatorState, pkgauth.NewAuthenticatorState},
	}
	for _, c := range funcs {
		if reflect.ValueOf(c.got).Pointer() != reflect.ValueOf(c.want).Pointer() {
			t.Errorf("%s is not the pkg/fido2/authenticator function", c.name)
		}
	}
}

func TestReexport_Errors(t *testing.T) {
	errs := []struct {
		name      string
		got, want error
	}{
		{"ErrAttestationCertNotIssuedForKey", authenticator.ErrAttestationCertNotIssuedForKey, pkgauth.ErrAttestationCertNotIssuedForKey},
		{"ErrConfigInvalidVendorCmd", authenticator.ErrConfigInvalidVendorCmd, pkgauth.ErrConfigInvalidVendorCmd},
		{"ErrInvalidParameter", authenticator.ErrInvalidParameter, pkgauth.ErrInvalidParameter},
		{"ErrKeyManagerLocked", authenticator.ErrKeyManagerLocked, pkgauth.ErrKeyManagerLocked},
		{"ErrKeyManagerNoAttestKey", authenticator.ErrKeyManagerNoAttestKey, pkgauth.ErrKeyManagerNoAttestKey},
		{"ErrNilStorage", authenticator.ErrNilStorage, pkgauth.ErrNilStorage},
		{"ErrPINPolicyViolation", authenticator.ErrPINPolicyViolation, pkgauth.ErrPINPolicyViolation},
		{"ErrRPPolicyInvalidRPID", authenticator.ErrRPPolicyInvalidRPID, pkgauth.ErrRPPolicyInvalidRPID},
		{"ErrRPPolicyNotFound", authenticator.ErrRPPolicyNotFound, pkgauth.ErrRPPolicyNotFound},
		{"ErrSOPINInvalid", authenticator.ErrSOPINInvalid, pkgauth.ErrSOPINInvalid},
		{"ErrSOPINPolicyViolation", authenticator.ErrSOPINPolicyViolation, pkgauth.ErrSOPINPolicyViolation},
		{"ErrUserVerificationDenied", authenticator.ErrUserVerificationDenied, pkgauth.ErrUserVerificationDenied},
	}
	for _, c := range errs {
		if c.got != c.want {
			t.Errorf("%s is not the pkg/fido2/authenticator sentinel", c.name)
		}
	}
}
