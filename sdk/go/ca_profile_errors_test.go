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

	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
)

// TestReexport_ProfileErrors pins the profile sentinels sdk/go re-exports to
// the pkg/ca values, so errors.Is against the sdk/go name matches what the
// CA returns (SPEC.md:180, issue 729).
func TestReexport_ProfileErrors(t *testing.T) {
	cases := []struct {
		name string
		got  error
		want error
	}{
		{"ErrProfileNotFound", ErrProfileNotFound, pkgca.ErrProfileNotFound},
		{"ErrInvalidProfile", ErrInvalidProfile, pkgca.ErrInvalidProfile},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s does not alias pkg/ca", tc.name)
		}
	}
}

// TestDefaultProfileRegistry_UnknownNameIsErrProfileNotFound proves a caller
// holding only sdk/go can recognise an unknown profile name (#241).
func TestDefaultProfileRegistry_UnknownNameIsErrProfileNotFound(t *testing.T) {
	_, err := NewDefaultProfileRegistry().Get("idevid")
	if err == nil {
		t.Fatal("Get(\"idevid\") returned no error")
	}
	if !errors.Is(err, ErrProfileNotFound) {
		t.Errorf("Get(\"idevid\") error %v is not ErrProfileNotFound", err)
	}
}
