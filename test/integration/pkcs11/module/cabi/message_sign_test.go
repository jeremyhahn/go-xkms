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

//go:build integration && pkcs11_cabi

package cabi

import (
	"testing"
)

// TestSignMessageRejectsUnsupportedParameter proves the message-based signing
// entry points do not silently ignore a per-message parameter.
//
// No signature mechanism this module implements takes one: RSA, ECDSA and
// EdDSA message signing are parameterless, and ML-DSA's optional
// CK_SIGN_ADDITIONAL_CONTEXT is not implemented. A module that accepted a
// non-NULL parameter and dropped it would return a signature made under a
// different context than the caller asked for, so the call must be refused with
// CKR_MECHANISM_PARAM_INVALID. The parameterless (NULL) form must still work.
func TestSignMessageRejectsUnsupportedParameter(t *testing.T) {
	f := NewFixture(t)
	if !f.Module.HasV3() {
		t.Fatalf("the module at %s returned a v2.40 function list, which has no message-based functions", f.Module.Path())
	}

	_, priv := generateRSAKeyPair(t, f, 2048)
	data := []byte("message-based signing rejects an unsupported parameter")

	// A non-NULL per-message parameter must be refused: this module honours none.
	if err := f.Session.MessageSignInit(CKM_RSA_PKCS, nil, priv); err != nil {
		t.Fatalf("C_MessageSignInit: %v", err)
	}
	err := f.Session.SignMessageProbe([]byte("unexpected-context"), data)
	if err == nil {
		t.Fatal("C_SignMessage accepted a per-message parameter this module cannot honour")
	}
	if got := RV(err); got != CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("C_SignMessage with a non-NULL parameter returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID",
			rvName(got), got)
	}

	// The parameterless form is the supported case and must not be refused for
	// the same reason.
	if err := f.Session.MessageSignInit(CKM_RSA_PKCS, nil, priv); err != nil {
		t.Fatalf("C_MessageSignInit (second): %v", err)
	}
	if err := f.Session.SignMessageProbe(nil, data); err != nil {
		if got := RV(err); got == CKR_MECHANISM_PARAM_INVALID {
			t.Fatalf("C_SignMessage refused the parameterless form with CKR_MECHANISM_PARAM_INVALID; only a non-NULL parameter should be refused")
		}
	}
}
