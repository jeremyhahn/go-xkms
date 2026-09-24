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

// Tests for the key-management entry points in exports.go
// (C_GenerateKey/C_GenerateKeyPair/C_WrapKey/C_UnwrapKey/C_DeriveKey) and
// C_InitToken/C_InitPIN/C_SetPIN.
//
// A well-formed CK_ATTRIBUTE template carries actual key material through a
// pointer this module reads as a whole C struct (type, pValue, ulValueLen);
// building one requires setting those fields, and cgo names them with
// unexported Go identifiers (a C field named "type" becomes "_type" to dodge
// the keyword, but stays unexported regardless of the leading underscore).
// reflect cannot Set an unexported struct field, and Go 1.26 forbids
// `import "C"` in a _test.go file (see exports_test.go's file doc comment),
// so there is no way to construct one from here. These tests are therefore
// scoped to the argument-marshalling branches every key-management entry
// point checks before it ever looks at the template: a NULL pMechanism or
// NULL output handle. The template-decoding helpers themselves
// (convertCTemplateToGo, readCAttributeArray, writeCAttributeArray,
// requestedAttributes, copyGoTemplateToCTemplate) are exercised indirectly
// through C_GetAttributeValue/C_SetAttributeValue's empty-template path in
// exports_session_object_test.go, which is the one shape reachable without a
// hand-built CK_ATTRIBUTE.

import (
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

func TestKeyManagement_NullMechanismIsRefused(t *testing.T) {
	f := newTestFixture(t)

	cases := []struct {
		name string
		fn   any
		args []cArg
	}{
		{"C_GenerateKey", C_GenerateKey,
			[]cArg{cScalar(uint64(f.session)), cNull(), cNull(), cScalar(0), cAlloc()}},
		{"C_GenerateKeyPair", C_GenerateKeyPair,
			[]cArg{cScalar(uint64(f.session)), cNull(), cNull(), cScalar(0), cNull(), cScalar(0), cAlloc(), cAlloc()}},
		{"C_WrapKey", C_WrapKey,
			[]cArg{cScalar(uint64(f.session)), cNull(), cScalar(uint64(f.privKey)), cScalar(uint64(f.pubKey)), cNull(), cAlloc()}},
		{"C_UnwrapKey", C_UnwrapKey,
			[]cArg{cScalar(uint64(f.session)), cNull(), cScalar(uint64(f.privKey)), cNull(), cScalar(0), cNull(), cScalar(0), cAlloc()}},
		{"C_DeriveKey", C_DeriveKey,
			[]cArg{cScalar(uint64(f.session)), cNull(), cScalar(uint64(f.privKey)), cNull(), cScalar(0), cAlloc()}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv, _ := callC(t, tc.fn, tc.args...)
			if rv != module.CKR_ARGUMENTS_BAD {
				t.Fatalf("%s(pMechanism=NULL) = %s, want CKR_ARGUMENTS_BAD", tc.name, rv)
			}
		})
	}
}

func TestCGenerateKey_NullOutputHandleIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_GenerateKey,
		cScalar(uint64(f.session)), cAlloc(), cNull(), cScalar(0), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GenerateKey(phKey=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCGenerateKeyPair_NullOutputHandlesAreRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_GenerateKeyPair,
		cScalar(uint64(f.session)), cAlloc(), cNull(), cScalar(0), cNull(), cScalar(0), cNull(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_GenerateKeyPair(phPublicKey=NULL, phPrivateKey=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCWrapKey_NullLengthPointerIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_WrapKey,
		cScalar(uint64(f.session)), cAlloc(), cScalar(uint64(f.privKey)), cScalar(uint64(f.pubKey)), cNull(), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_WrapKey(pulWrappedKeyLen=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCUnwrapKey_NullOutputHandleIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_UnwrapKey,
		cScalar(uint64(f.session)), cAlloc(), cScalar(uint64(f.privKey)), cNull(), cScalar(0), cNull(), cScalar(0), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_UnwrapKey(phKey=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCUnwrapKey_NullWrappedKeyWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_UnwrapKey,
		cScalar(uint64(f.session)), cAlloc(), cScalar(uint64(f.privKey)), cNull(), cScalar(16), cNull(), cScalar(0), cAlloc())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_UnwrapKey(pWrappedKey=NULL, ulWrappedKeyLen=16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCDeriveKey_NullOutputHandleIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_DeriveKey,
		cScalar(uint64(f.session)), cAlloc(), cScalar(uint64(f.privKey)), cNull(), cScalar(0), cNull())
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_DeriveKey(phKey=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

// ============================================================================
// C_InitToken / C_InitPIN / C_SetPIN: argument marshalling.
// ============================================================================

func TestCInitToken_NullLabelIsRefused(t *testing.T) {
	newTestFixture(t)

	pin := []byte(testSOPIN)
	rv := callExport(t, C_InitToken, map[int]func(reflect.Value){
		1: setBufferArg(pin),
		2: func(v reflect.Value) { v.SetUint(uint64(len(pin))) },
	})
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_InitToken(pLabel=NULL) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCInitToken_NullPinWithNonzeroLengthIsRefused(t *testing.T) {
	newTestFixture(t)

	label := make([]byte, 32)
	copy(label, "test token")
	rv := callExport(t, C_InitToken, map[int]func(reflect.Value){
		2: func(v reflect.Value) { v.SetUint(16) },
		3: setBufferArg(label),
	})
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_InitToken(pPin=NULL, ulPinLen=16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCInitPIN_NullPinWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_InitPIN, cScalar(uint64(f.session)), cNull(), cScalar(16))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_InitPIN(pPin=NULL, ulPinLen=16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCSetPIN_NullOldPinWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	rv, _ := callC(t, C_SetPIN, cScalar(uint64(f.session)), cNull(), cScalar(16), cNull(), cScalar(0))
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_SetPIN(pOldPin=NULL, ulOldLen=16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}

func TestCSetPIN_NullNewPinWithNonzeroLengthIsRefused(t *testing.T) {
	f := newTestFixture(t)

	oldPin := []byte(testUserPIN)
	rv := callExport(t, C_SetPIN, map[int]func(reflect.Value){
		0: func(v reflect.Value) { v.SetUint(uint64(f.session)) },
		1: setBufferArg(oldPin),
		2: func(v reflect.Value) { v.SetUint(uint64(len(oldPin))) },
		4: func(v reflect.Value) { v.SetUint(16) },
	})
	if rv != module.CKR_ARGUMENTS_BAD {
		t.Fatalf("C_SetPIN(pNewPin=NULL, ulNewLen=16) = %s, want CKR_ARGUMENTS_BAD", rv)
	}
}
