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

import (
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// TestInputBuffer_NullWithLengthIsArgumentsBad pins the input-buffer check
// every data-taking export shares: a NULL input pointer paired with a non-zero
// length names memory that does not exist, so the call answers
// CKR_ARGUMENTS_BAD before the module is consulted. Every output argument is a
// valid pointer, so the refusal can only come from the input pair.
func TestInputBuffer_NullWithLengthIsArgumentsBad(t *testing.T) {
	tests := []struct {
		name string
		fn   any
	}{
		{"C_Encrypt", C_Encrypt},
		{"C_EncryptUpdate", C_EncryptUpdate},
		{"C_Decrypt", C_Decrypt},
		{"C_DecryptUpdate", C_DecryptUpdate},
		{"C_Digest", C_Digest},
		{"C_Sign", C_Sign},
		{"C_SignRecover", C_SignRecover},
		{"C_Verify", C_Verify},
		{"C_VerifyRecover", C_VerifyRecover},
		{"C_DigestEncryptUpdate", C_DigestEncryptUpdate},
		{"C_DecryptDigestUpdate", C_DecryptDigestUpdate},
		{"C_SignEncryptUpdate", C_SignEncryptUpdate},
		{"C_DecryptVerifyUpdate", C_DecryptVerifyUpdate},
		{"C_SeedRandom", C_SeedRandom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv := reflect.ValueOf(tt.fn)
			ft := fv.Type()
			args := []reflect.Value{
				scalarOf(ft, 0, 0),
				setBufferPtr(nil, ft, 1),
				scalarOf(ft, 2, 16),
			}
			for i := 3; i < ft.NumIn(); i++ {
				if ft.In(i).Kind() == reflect.Pointer {
					args = append(args, reflect.New(ft.In(i).Elem()))
					continue
				}
				args = append(args, reflect.Zero(ft.In(i)))
			}
			if rv := module.CK_RV(fv.Call(args)[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
				t.Fatalf("%s(NULL input, length 16) = %s, want CKR_ARGUMENTS_BAD", tt.name, rv)
			}
		})
	}
}
