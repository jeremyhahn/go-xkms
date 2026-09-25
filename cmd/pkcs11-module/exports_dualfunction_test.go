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

package main

// Tests for the dual-function cryptographic entry points in exports.go
// (C_DigestEncryptUpdate, C_DecryptDigestUpdate, C_SignEncryptUpdate,
// C_DecryptVerifyUpdate). All four share the same argument-marshalling
// shape: a NULL output length pointer, a NULL input buffer with a nonzero
// declared length, and (with well-formed arguments but no active operation
// pair) CKR_OPERATION_NOT_INITIALIZED -- reachable without a hand-built
// CK_MECHANISM, unlike the mechanism-parameter decode paths (see
// exports_keymgmt_test.go's file doc comment on why those are out of
// reach from a _test.go file).

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

func TestDualFunctionUpdates_NullLengthPointerIsRefused(t *testing.T) {
	f := newTestFixture(t)

	cases := []struct {
		name string
		fn   any
	}{
		{"C_DigestEncryptUpdate", C_DigestEncryptUpdate},
		{"C_DecryptDigestUpdate", C_DecryptDigestUpdate},
		{"C_SignEncryptUpdate", C_SignEncryptUpdate},
		{"C_DecryptVerifyUpdate", C_DecryptVerifyUpdate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv, _ := callC(t, tc.fn, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cNull())
			if rv != module.CKR_ARGUMENTS_BAD {
				t.Fatalf("%s(pulOutLen=NULL) = %s, want CKR_ARGUMENTS_BAD", tc.name, rv)
			}
		})
	}
}

func TestDualFunctionUpdates_NullInputWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	cases := []struct {
		name string
		fn   any
	}{
		{"C_DigestEncryptUpdate", C_DigestEncryptUpdate},
		{"C_DecryptDigestUpdate", C_DecryptDigestUpdate},
		{"C_SignEncryptUpdate", C_SignEncryptUpdate},
		{"C_DecryptVerifyUpdate", C_DecryptVerifyUpdate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv, _ := callC(t, tc.fn, cScalar(uint64(f.session)), cNull(), cScalar(16), cNull(), cAlloc())
			if rv != module.CKR_ARGUMENTS_BAD {
				t.Fatalf("%s(pIn=NULL, ulInLen=16) = %s, want CKR_ARGUMENTS_BAD", tc.name, rv)
			}
		})
	}
}

// TestDualFunctionUpdates_NoActiveOperation proves each verb refuses to run
// without both halves of its operation pair active (digest+encrypt,
// decrypt+digest, sign+encrypt, decrypt+verify), using the length-query
// shape (NULL output buffer, non-NULL output length pointer) that also
// proves a query against an idle session reports the real error rather
// than a spurious CKR_OK.
func TestDualFunctionUpdates_NoActiveOperation(t *testing.T) {
	f := newTestFixture(t)

	cases := []struct {
		name string
		fn   any
	}{
		{"C_DigestEncryptUpdate", C_DigestEncryptUpdate},
		{"C_DecryptDigestUpdate", C_DecryptDigestUpdate},
		{"C_SignEncryptUpdate", C_SignEncryptUpdate},
		{"C_DecryptVerifyUpdate", C_DecryptVerifyUpdate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv, _ := callC(t, tc.fn, cScalar(uint64(f.session)), cNull(), cScalar(0), cNull(), cAlloc())
			if rv != module.CKR_OPERATION_NOT_INITIALIZED {
				t.Fatalf("%s with nothing initialized = %s, want CKR_OPERATION_NOT_INITIALIZED", tc.name, rv)
			}
		})
	}
}
