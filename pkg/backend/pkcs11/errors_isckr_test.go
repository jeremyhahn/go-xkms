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

//go:build pkcs11

package pkcs11

import (
	"fmt"
	"testing"

	"github.com/miekg/pkcs11"
)

// TestIsCKR_WrappedError is go-xkms#894's regression case for isCKR: call
// sites compare a Cryptoki return code with errors.As rather than a bare
// == against the raw pkcs11.Error, so a session/pool layer that adds
// call-site context to the Cryptoki error (fmt.Errorf's %w, the shape
// session_pool.go and pkcs11_importexport.go's own wrapping helpers
// produce) must still classify correctly.
func TestIsCKR_WrappedError(t *testing.T) {
	wrapped := fmt.Errorf("C_Login: %w", pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN))

	if !isCKR(wrapped, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		t.Fatal("isCKR must match a wrapped pkcs11.Error carrying the given code")
	}
	if isCKR(wrapped, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		t.Fatal("isCKR must not match a wrapped pkcs11.Error carrying a different code")
	}
}

// TestIsCKR_NotAPKCS11Error proves isCKR reports false, not a panic or a
// false positive, for an error that carries no pkcs11.Error at all.
func TestIsCKR_NotAPKCS11Error(t *testing.T) {
	if isCKR(fmt.Errorf("unrelated failure"), pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		t.Fatal("isCKR must not match an error that is not a pkcs11.Error")
	}
	if isCKR(nil, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		t.Fatal("isCKR must not match a nil error")
	}
}
