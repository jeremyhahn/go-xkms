// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

//go:build pkcs11

package pkcs11

import (
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/miekg/pkcs11"
)

// TestBuildYubiKeyECDSATemplates verifies that the minimal ECDSA template
// required by YubiKey's libykcs11 contains exactly the three attributes
// (CKA_CLASS, CKA_KEY_TYPE, and CKA_EC_PARAMS for the public key;
// CKA_CLASS, CKA_KEY_TYPE, and CKA_ID for the private key) and excludes
// any of the attributes that would trigger CKR_ATTRIBUTE_VALUE_INVALID.
func TestBuildYubiKeyECDSATemplates(t *testing.T) {
	encodedOID, err := asn1.Marshal(oidP256)
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}
	id := []byte{0x04}
	pub, priv := buildYubiKeyECDSATemplates(id, encodedOID)

	if len(pub) != 3 {
		t.Fatalf("public template length: want 3, got %d", len(pub))
	}
	if len(priv) != 3 {
		t.Fatalf("private template length: want 3, got %d", len(priv))
	}

	pubTypes := attrTypeSet(pub)
	wantPub := []uint{pkcs11.CKA_CLASS, pkcs11.CKA_KEY_TYPE, pkcs11.CKA_EC_PARAMS}
	for _, a := range wantPub {
		if !pubTypes[a] {
			t.Errorf("public template missing attribute 0x%x", a)
		}
	}

	privTypes := attrTypeSet(priv)
	wantPriv := []uint{pkcs11.CKA_CLASS, pkcs11.CKA_KEY_TYPE, pkcs11.CKA_ID}
	for _, a := range wantPriv {
		if !privTypes[a] {
			t.Errorf("private template missing attribute 0x%x", a)
		}
	}

	// Forbidden: any of these triggers CKR_ATTRIBUTE_VALUE_INVALID on YubiKey.
	forbidden := []uint{
		pkcs11.CKA_TOKEN, pkcs11.CKA_LABEL, pkcs11.CKA_SIGN,
		pkcs11.CKA_SENSITIVE, pkcs11.CKA_PRIVATE, pkcs11.CKA_VERIFY,
	}
	for _, a := range forbidden {
		if pubTypes[a] {
			t.Errorf("public template must not contain attribute 0x%x", a)
		}
		if privTypes[a] {
			t.Errorf("private template must not contain attribute 0x%x", a)
		}
	}
}

// TestBuildYubiKeyRSATemplates verifies the same minimal-template invariants
// for RSA key generation on YubiKey PIV.
func TestBuildYubiKeyRSATemplates(t *testing.T) {
	pub, priv := buildYubiKeyRSATemplates([]byte{0x05}, 2048)

	pubTypes := attrTypeSet(pub)
	privTypes := attrTypeSet(priv)

	for _, a := range []uint{pkcs11.CKA_CLASS, pkcs11.CKA_KEY_TYPE, pkcs11.CKA_MODULUS_BITS, pkcs11.CKA_PUBLIC_EXPONENT} {
		if !pubTypes[a] {
			t.Errorf("public template missing attribute 0x%x", a)
		}
	}
	for _, a := range []uint{pkcs11.CKA_CLASS, pkcs11.CKA_KEY_TYPE, pkcs11.CKA_ID} {
		if !privTypes[a] {
			t.Errorf("private template missing attribute 0x%x", a)
		}
	}

	forbidden := []uint{
		pkcs11.CKA_TOKEN, pkcs11.CKA_LABEL, pkcs11.CKA_SIGN, pkcs11.CKA_SENSITIVE,
		pkcs11.CKA_PRIVATE, pkcs11.CKA_VERIFY, pkcs11.CKA_ENCRYPT, pkcs11.CKA_DECRYPT,
		pkcs11.CKA_WRAP, pkcs11.CKA_UNWRAP,
	}
	for _, a := range forbidden {
		if pubTypes[a] || privTypes[a] {
			t.Errorf("YubiKey RSA template must not contain attribute 0x%x", a)
		}
	}
}

// TestYubiKeyPIV_Ed25519_Unsupported verifies that GenerateEd25519 returns
// an error explaining that YubiKey PIV does not support Ed25519.
func TestYubiKeyPIV_Ed25519_Unsupported(t *testing.T) {
	b := &Backend{
		config: &Config{Library: "/usr/lib/libykcs11.so"},
	}
	// Pool is nil, so without the YubiKey guard the call would return
	// ErrNotInitialized. The guard must run first and produce the
	// algorithm-not-supported error instead.
	_, err := b.GenerateEd25519(nil)
	if err == nil {
		t.Fatal("expected error from GenerateEd25519 on YubiKey PIV, got nil")
	}
	if !errors.Is(err, ErrUnsupportedKeyAlgorithm) {
		t.Errorf("error chain: want ErrUnsupportedKeyAlgorithm, got %v", err)
	}
}

// TestConfig_IsYubiKeyPIV verifies the library-path detection used to
// branch the key-generation templates.
func TestConfig_IsYubiKeyPIV(t *testing.T) {
	cases := []struct {
		lib  string
		want bool
	}{
		{"/usr/lib/libykcs11.so", true},
		{"/usr/local/lib/ykcs11.dylib", true},
		{"/usr/lib/softhsm/libsofthsm2.so", false},
		{"", false},
	}
	for _, tc := range cases {
		got := (&Config{Library: tc.lib}).IsYubiKeyPIV()
		if got != tc.want {
			t.Errorf("IsYubiKeyPIV(%q) = %v, want %v", tc.lib, got, tc.want)
		}
	}
}

// attrTypeSet returns a set of attribute Type values for assertion lookups.
func attrTypeSet(attrs []*pkcs11.Attribute) map[uint]bool {
	out := make(map[uint]bool, len(attrs))
	for _, a := range attrs {
		out[a.Type] = true
	}
	return out
}
