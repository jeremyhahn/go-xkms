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

import "testing"

// TestInterfaceIsVersion3 proves the module answers C_GetInterface for
// PKCS#11 v3.2.
//
// Everything message-based in this suite reaches the module through the v3.x
// function list. If C_GetInterface stopped working the harness would silently
// fall back to the v2.40 list obtained from C_GetFunctionList, and the
// message-based tests would report a missing function rather than the real
// cause, so the interface itself is asserted once here.
func TestInterfaceIsVersion3(t *testing.T) {
	mod, _, err := LoadShared()
	if err != nil {
		t.Fatalf("loading the module: %v", err)
	}
	if !mod.HasV3() {
		t.Fatalf("C_GetInterface(\"PKCS 11\", 3.2) did not yield a function list for %s, so the module was reached through the v2.40 C_GetFunctionList; "+
			"the message-based functions are unreachable that way", mod.Path())
	}
}

// TestMechanismListDeclaresTheParameterisedMechanisms proves that every
// mechanism this suite exercises with a parameter struct is discoverable.
//
// C_GetMechanismList is the only documented way for an application to learn
// what a token can do (PKCS#11 v3.2 section 5.5). A mechanism the module
// implements but never lists is unreachable to p11-kit, to OpenSSL's
// pkcs11-provider, and to any other caller that enumerates before it acts,
// however well the implementation behind it works.
//
// The mechanisms are checked as a group rather than one per test so that the
// failure names the whole set at once, which is what a maintainer needs in
// order to decide whether the advertised surface or the implementation is the
// thing to change.
func TestMechanismListDeclaresTheParameterisedMechanisms(t *testing.T) {
	f := NewFixture(t)

	list, err := f.Module.MechanismList(f.Slot)
	if err != nil {
		t.Fatalf("C_GetMechanismList: %v", err)
	}
	advertised := make(map[uint]bool, len(list))
	for _, m := range list {
		advertised[m] = true
	}

	required := []struct {
		mech uint
		name string
	}{
		{CKM_RSA_PKCS_PSS, "CKM_RSA_PKCS_PSS"},
		{CKM_RSA_PKCS_OAEP, "CKM_RSA_PKCS_OAEP"},
		{CKM_AES_GCM, "CKM_AES_GCM"},
		{CKM_ECDH1_DERIVE, "CKM_ECDH1_DERIVE"},
		{CKM_EDDSA, "CKM_EDDSA"},
		{CKM_HKDF_DERIVE, "CKM_HKDF_DERIVE"},
		{CKM_SP800_108_COUNTER_KDF, "CKM_SP800_108_COUNTER_KDF"},
	}

	var missing []string
	for _, r := range required {
		if !advertised[r.mech] {
			missing = append(missing, r.name)
		}
	}

	if len(missing) > 0 {
		t.Fatalf("C_GetMechanismList on slot %d does not advertise %v, although this suite drives each of them "+
			"successfully through C_DeriveKey or C_SignInit. An application that enumerates mechanisms before using "+
			"them cannot discover any of these.", f.Slot, missing)
	}
}
