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

package truststore_test

import (
	"reflect"
	"testing"

	pkgtruststore "github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/sdk/go/truststore"
)

func TestReexportedTypesAreThePkgTypes(t *testing.T) {
	cases := map[string][2]reflect.Type{
		"CertMetadata": {
			reflect.TypeOf((*truststore.CertMetadata)(nil)).Elem(),
			reflect.TypeOf((*pkgtruststore.CertMetadata)(nil)).Elem(),
		},
		"OSCertStore": {
			reflect.TypeOf((*truststore.OSCertStore)(nil)).Elem(),
			reflect.TypeOf((*pkgtruststore.OSCertStore)(nil)).Elem(),
		},
	}
	for name, c := range cases {
		if c[0] != c[1] {
			t.Errorf("%s: sdk type %v is not pkg type %v", name, c[0], c[1])
		}
	}
}

func TestReexportedFuncsAreThePkgFuncs(t *testing.T) {
	sdk := reflect.ValueOf(truststore.ClassifyCertificate).Pointer()
	pkg := reflect.ValueOf(pkgtruststore.ClassifyCertificate).Pointer()
	if sdk != pkg {
		t.Errorf("ClassifyCertificate: sdk func is not the pkg func")
	}
}

func TestReexportedErrorsAreThePkgErrors(t *testing.T) {
	cases := map[string][2]error{
		"ErrInvalidCertificate": {truststore.ErrInvalidCertificate, pkgtruststore.ErrInvalidCertificate},
		"ErrPermissionDenied":   {truststore.ErrPermissionDenied, pkgtruststore.ErrPermissionDenied},
		"ErrRemoveFailed":       {truststore.ErrRemoveFailed, pkgtruststore.ErrRemoveFailed},
	}
	for name, c := range cases {
		if c[0] != c[1] {
			t.Errorf("%s: sdk error %v is not pkg error %v", name, c[0], c[1])
		}
	}
}
