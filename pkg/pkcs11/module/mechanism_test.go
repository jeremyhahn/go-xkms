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

package module

import (
	"crypto/fips140"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

// TestNewMechanism tests NewMechanism constructor.
func TestNewMechanism(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
	}{
		{
			name:     "RSA PKCS",
			mechType: CKM_RSA_PKCS,
		},
		{
			name:     "AES GCM",
			mechType: CKM_AES_GCM,
		},
		{
			name:     "SHA256",
			mechType: CKM_SHA256,
		},
		{
			name:     "ECDSA",
			mechType: CKM_ECDSA,
		},
		{
			name:     "zero value mechanism",
			mechType: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mech := NewMechanism(tt.mechType)
			if mech == nil {
				t.Fatal("NewMechanism returned nil")
			}
			if mech.Type != tt.mechType {
				t.Errorf("Type = %v, want %v", mech.Type, tt.mechType)
			}
			if mech.Parameter != nil {
				t.Error("Parameter should be nil for NewMechanism")
			}
			if mech.TypedParameter != nil {
				t.Error("TypedParameter should be nil for NewMechanism")
			}
		})
	}
}

// TestNewMechanismWithParams tests NewMechanismWithParams constructor.
func TestNewMechanismWithParams(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		params   []byte
	}{
		{
			name:     "with params",
			mechType: CKM_AES_CBC,
			params:   make([]byte, 16),
		},
		{
			name:     "with nil params",
			mechType: CKM_AES_ECB,
			params:   nil,
		},
		{
			name:     "with empty params",
			mechType: CKM_RSA_PKCS,
			params:   []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mech := NewMechanismWithParams(tt.mechType, tt.params)
			if mech == nil {
				t.Fatal("NewMechanismWithParams returned nil")
			}
			if mech.Type != tt.mechType {
				t.Errorf("Type = %v, want %v", mech.Type, tt.mechType)
			}
			if tt.params == nil && mech.Parameter != nil {
				t.Error("Parameter should be nil when nil params provided")
			}
			if tt.params != nil && len(mech.Parameter) != len(tt.params) {
				t.Errorf("Parameter length = %d, want %d", len(mech.Parameter), len(tt.params))
			}
		})
	}
}

// TestNewMechanismWithTypedParams tests NewMechanismWithTypedParams constructor.
func TestNewMechanismWithTypedParams(t *testing.T) {
	hkdfParams := &HKDFParams{
		Extract:     true,
		Expand:      true,
		PRFHashMech: CKM_SHA256,
		SaltType:    CKF_HKDF_SALT_DATA,
		Salt:        []byte("salt"),
		Info:        []byte("info"),
	}

	tests := []struct {
		name     string
		mechType MechanismType
		params   interface{}
	}{
		{
			name:     "with HKDF params",
			mechType: CKM_HKDF_DERIVE,
			params:   hkdfParams,
		},
		{
			name:     "with nil params",
			mechType: CKM_AES_KEY_GEN,
			params:   nil,
		},
		{
			name:     "with string params",
			mechType: CKM_RSA_PKCS,
			params:   "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mech := NewMechanismWithTypedParams(tt.mechType, tt.params)
			if mech == nil {
				t.Fatal("NewMechanismWithTypedParams returned nil")
			}
			if mech.Type != tt.mechType {
				t.Errorf("Type = %v, want %v", mech.Type, tt.mechType)
			}
			if mech.TypedParameter != tt.params {
				t.Error("TypedParameter does not match input")
			}
		})
	}
}

// TestMechanism_GetHKDFParams tests Mechanism.GetHKDFParams method.
func TestMechanism_GetHKDFParams(t *testing.T) {
	hkdfParams := &HKDFParams{
		Extract:     true,
		Expand:      true,
		PRFHashMech: CKM_SHA256,
		SaltType:    CKF_HKDF_SALT_DATA,
		Salt:        []byte("salt"),
		Info:        []byte("info"),
	}

	tests := []struct {
		name      string
		mech      *Mechanism
		wantOK    bool
		wantMatch bool
	}{
		{
			name: "valid HKDF params",
			mech: &Mechanism{
				Type:           CKM_HKDF_DERIVE,
				TypedParameter: hkdfParams,
			},
			wantOK:    true,
			wantMatch: true,
		},
		{
			name: "nil typed parameter",
			mech: &Mechanism{
				Type:           CKM_HKDF_DERIVE,
				TypedParameter: nil,
			},
			wantOK:    false,
			wantMatch: false,
		},
		{
			name: "wrong type",
			mech: &Mechanism{
				Type:           CKM_RSA_PKCS,
				TypedParameter: "not hkdf params",
			},
			wantOK:    false,
			wantMatch: false,
		},
		{
			name: "RSA OAEP params instead",
			mech: &Mechanism{
				Type:           CKM_RSA_PKCS_OAEP,
				TypedParameter: &RSAOAEPParams{},
			},
			wantOK:    false,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, ok := tt.mech.GetHKDFParams()
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if tt.wantMatch && params != hkdfParams {
				t.Error("returned params do not match original")
			}
			if !tt.wantOK && params != nil {
				t.Error("params should be nil when ok is false")
			}
		})
	}
}

// TestIsMechanismSupported tests IsMechanismSupported function.
func TestIsMechanismSupported(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     bool
	}{
		{
			name:     "RSA PKCS supported",
			mechType: CKM_RSA_PKCS,
			want:     true,
		},
		{
			name:     "AES GCM supported",
			mechType: CKM_AES_GCM,
			want:     true,
		},
		{
			name:     "SHA256 supported",
			mechType: CKM_SHA256,
			want:     true,
		},
		{
			name:     "EC key pair gen supported",
			mechType: CKM_EC_KEY_PAIR_GEN,
			want:     true,
		},
		{
			// FIPS mode withholds HKDF over an arbitrary base key (see TestFIPSMode).
			name:     "HKDF derive supported outside FIPS mode",
			mechType: CKM_HKDF_DERIVE,
			want:     !fips140.Enabled(),
		},
		{
			name:     "unknown mechanism not supported",
			mechType: MechanismType(0xFFFFFFFF),
			want:     false,
		},
		{
			name:     "vendor defined not supported",
			mechType: CKM_VENDOR_DEFINED,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsMechanismSupported(tt.mechType)
			if got != tt.want {
				t.Errorf("IsMechanismSupported(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestGetMechanismName tests GetMechanismName function.
func TestGetMechanismName(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     string
	}{
		{
			name:     "RSA PKCS",
			mechType: CKM_RSA_PKCS,
			want:     "CKM_RSA_PKCS",
		},
		{
			name:     "AES GCM",
			mechType: CKM_AES_GCM,
			want:     "CKM_AES_GCM",
		},
		{
			name:     "SHA256",
			mechType: CKM_SHA256,
			want:     "CKM_SHA256",
		},
		{
			name:     "ECDSA SHA256",
			mechType: CKM_ECDSA_SHA256,
			want:     "CKM_ECDSA_SHA256",
		},
		{
			name:     "HKDF derive",
			mechType: CKM_HKDF_DERIVE,
			want:     "CKM_HKDF_DERIVE",
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0x12345678),
			want:     "CKM_UNKNOWN(0x12345678)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetMechanismName(tt.mechType)
			if got != tt.want {
				t.Errorf("GetMechanismName(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestGetMechanismInfo tests GetMechanismInfo function.
func TestMechanismGetMechanismInfo(t *testing.T) {
	tests := []struct {
		name       string
		mechType   MechanismType
		wantErr    bool
		wantMinKey uint32
		wantMaxKey uint32
	}{
		{
			name:     "RSA PKCS",
			mechType: CKM_RSA_PKCS,
			wantErr:  false,
			// 2048 is the floor the module enforces and advertises. PKCS#11
			// v3.2 §6.1.21 permits only 1024, 2048 and 3072 for CKM_RSA_PKCS in
			// FIPS mode -- 512 is not a permitted modulus length at all -- and
			// NIST SP 800-131A has disallowed RSA below 2048 since 2014.
			wantMinKey: rsaModulusBitsMin,
			// The ceiling is a size the module actually generates. It read
			// 16384 until generating a key at that advertised maximum
			// exhausted the daemon's memory; see rsaModulusBitsMax. FIPS mode
			// narrows it to 3072 (TestRSAModulusCeilingNarrowsUnderFIPS).
			wantMaxKey: rsaModulusCeilingForProcess(),
		},
		{
			// CKM_AES_GCM's MinKeySize/MaxKeySize are in bytes (PKCS#11
			// v3.2 §6.13.7), so AES-128/256 are expressed here as 16/32,
			// not their bit lengths 128/256.
			name:       "AES GCM",
			mechType:   CKM_AES_GCM,
			wantErr:    false,
			wantMinKey: 16,
			wantMaxKey: 32,
		},
		{
			name:       "SHA256 digest",
			mechType:   CKM_SHA256,
			wantErr:    false,
			wantMinKey: 0,
			wantMaxKey: 0,
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := GetMechanismInfo(tt.mechType)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				if info != nil {
					t.Error("info should be nil when error returned")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info == nil {
				t.Fatal("info is nil")
			}
			if info.MinKeySize != tt.wantMinKey {
				t.Errorf("MinKeySize = %d, want %d", info.MinKeySize, tt.wantMinKey)
			}
			if info.MaxKeySize != tt.wantMaxKey {
				t.Errorf("MaxKeySize = %d, want %d", info.MaxKeySize, tt.wantMaxKey)
			}
		})
	}
}

// TestCanSign tests CanSign function.
func TestCanSign(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     bool
	}{
		{
			name:     "RSA PKCS can sign",
			mechType: CKM_RSA_PKCS,
			want:     true,
		},
		{
			name:     "ECDSA can sign",
			mechType: CKM_ECDSA,
			want:     true,
		},
		{
			name:     "SHA256 HMAC can sign",
			mechType: CKM_SHA256_HMAC,
			want:     true,
		},
		{
			name:     "AES GCM cannot sign",
			mechType: CKM_AES_GCM,
			want:     false,
		},
		{
			name:     "SHA256 cannot sign",
			mechType: CKM_SHA256,
			want:     false,
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanSign(tt.mechType)
			if got != tt.want {
				t.Errorf("CanSign(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestCanVerify tests CanVerify function.
func TestCanVerify(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     bool
	}{
		{
			name:     "RSA PKCS can verify",
			mechType: CKM_RSA_PKCS,
			want:     true,
		},
		{
			name:     "ECDSA can verify",
			mechType: CKM_ECDSA,
			want:     true,
		},
		{
			name:     "SHA256 HMAC can verify",
			mechType: CKM_SHA256_HMAC,
			want:     true,
		},
		{
			name:     "AES GCM cannot verify",
			mechType: CKM_AES_GCM,
			want:     false,
		},
		{
			name:     "SHA256 cannot verify",
			mechType: CKM_SHA256,
			want:     false,
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanVerify(tt.mechType)
			if got != tt.want {
				t.Errorf("CanVerify(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestCanEncrypt tests CanEncrypt function.
func TestCanEncrypt(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     bool
	}{
		{
			name:     "AES GCM can encrypt",
			mechType: CKM_AES_GCM,
			want:     true,
		},
		{
			name:     "AES CBC can encrypt",
			mechType: CKM_AES_CBC,
			want:     true,
		},
		{
			name:     "RSA PKCS can encrypt",
			mechType: CKM_RSA_PKCS,
			want:     true,
		},
		{
			name:     "RSA OAEP can encrypt",
			mechType: CKM_RSA_PKCS_OAEP,
			want:     true,
		},
		{
			name:     "SHA256 cannot encrypt",
			mechType: CKM_SHA256,
			want:     false,
		},
		{
			name:     "ECDSA cannot encrypt",
			mechType: CKM_ECDSA,
			want:     false,
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanEncrypt(tt.mechType)
			if got != tt.want {
				t.Errorf("CanEncrypt(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestCanDecrypt tests CanDecrypt function.
func TestCanDecrypt(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     bool
	}{
		{
			name:     "AES GCM can decrypt",
			mechType: CKM_AES_GCM,
			want:     true,
		},
		{
			name:     "AES CBC can decrypt",
			mechType: CKM_AES_CBC,
			want:     true,
		},
		{
			name:     "RSA PKCS can decrypt",
			mechType: CKM_RSA_PKCS,
			want:     true,
		},
		{
			name:     "RSA OAEP can decrypt",
			mechType: CKM_RSA_PKCS_OAEP,
			want:     true,
		},
		{
			name:     "SHA256 cannot decrypt",
			mechType: CKM_SHA256,
			want:     false,
		},
		{
			name:     "ECDSA cannot decrypt",
			mechType: CKM_ECDSA,
			want:     false,
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanDecrypt(tt.mechType)
			if got != tt.want {
				t.Errorf("CanDecrypt(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestCanGenerateKey tests CanGenerateKey function.
func TestCanGenerateKey(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     bool
	}{
		{
			name:     "AES key gen",
			mechType: CKM_AES_KEY_GEN,
			want:     true,
		},
		// CKM_HKDF_KEY_GEN carried CKF_GENERATE with no entry in the
		// mechanism-to-key-type mapping, so C_GenerateKey could not build a
		// request for it and failed with CKR_GENERAL_ERROR. Its descriptor has
		// been removed, so CanGenerateKey must now say so.
		{
			name:     "HKDF key gen is not implemented and must not claim to generate",
			mechType: CKM_HKDF_KEY_GEN,
			want:     false,
		},
		{
			name:     "generic secret key gen",
			mechType: CKM_GENERIC_SECRET_KEY_GEN,
			want:     true,
		},
		{
			name:     "RSA key pair gen is not single key gen",
			mechType: CKM_RSA_PKCS_KEY_PAIR_GEN,
			want:     false,
		},
		{
			name:     "EC key pair gen is not single key gen",
			mechType: CKM_EC_KEY_PAIR_GEN,
			want:     false,
		},
		{
			name:     "SHA256 cannot generate key",
			mechType: CKM_SHA256,
			want:     false,
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanGenerateKey(tt.mechType)
			if got != tt.want {
				t.Errorf("CanGenerateKey(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestCanGenerateKeyPair tests CanGenerateKeyPair function.
func TestCanGenerateKeyPair(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     bool
	}{
		{
			name:     "RSA key pair gen",
			mechType: CKM_RSA_PKCS_KEY_PAIR_GEN,
			want:     true,
		},
		{
			name:     "EC key pair gen",
			mechType: CKM_EC_KEY_PAIR_GEN,
			want:     true,
		},
		{
			name:     "Edwards key pair gen",
			mechType: CKM_EC_EDWARDS_KEY_PAIR_GEN,
			want:     true,
		},
		{
			name:     "AES key gen is not key pair gen",
			mechType: CKM_AES_KEY_GEN,
			want:     false,
		},
		{
			name:     "SHA256 cannot generate key pair",
			mechType: CKM_SHA256,
			want:     false,
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanGenerateKeyPair(tt.mechType)
			if got != tt.want {
				t.Errorf("CanGenerateKeyPair(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestCanWrap tests CanWrap function.
func TestCanWrap(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     bool
	}{
		{
			name:     "AES key wrap",
			mechType: CKM_AES_KEY_WRAP,
			want:     true,
		},
		{
			name:     "AES key wrap pad",
			mechType: CKM_AES_KEY_WRAP_PAD,
			want:     true,
		},
		{
			name:     "RSA PKCS can wrap",
			mechType: CKM_RSA_PKCS,
			want:     true,
		},
		{
			name:     "RSA OAEP can wrap",
			mechType: CKM_RSA_PKCS_OAEP,
			want:     true,
		},
		// This asserted that CKM_AES_GCM cannot wrap while module.go routed it
		// through C_WrapKey, so C_GetMechanismInfo and the module disagreed.
		// PKCS#11 v3.2 §6.10 lists AES-GCM among the wrapping mechanisms and
		// the descriptor now carries CKF_WRAP.
		{
			name:     "AES GCM can wrap",
			mechType: CKM_AES_GCM,
			want:     true,
		},
		{
			name:     "SHA256 cannot wrap",
			mechType: CKM_SHA256,
			want:     false,
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanWrap(tt.mechType)
			if got != tt.want {
				t.Errorf("CanWrap(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestCanUnwrap tests CanUnwrap function.
func TestCanUnwrap(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     bool
	}{
		{
			name:     "AES key wrap",
			mechType: CKM_AES_KEY_WRAP,
			want:     true,
		},
		{
			name:     "AES key wrap pad",
			mechType: CKM_AES_KEY_WRAP_PAD,
			want:     true,
		},
		{
			name:     "RSA PKCS can unwrap",
			mechType: CKM_RSA_PKCS,
			want:     true,
		},
		{
			name:     "RSA OAEP can unwrap",
			mechType: CKM_RSA_PKCS_OAEP,
			want:     true,
		},
		// The CKF_UNWRAP half of the same disagreement; see TestCanWrap.
		{
			name:     "AES GCM can unwrap",
			mechType: CKM_AES_GCM,
			want:     true,
		},
		{
			name:     "SHA256 cannot unwrap",
			mechType: CKM_SHA256,
			want:     false,
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanUnwrap(tt.mechType)
			if got != tt.want {
				t.Errorf("CanUnwrap(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestCanDerive tests CanDerive function.
func TestCanDerive(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     bool
	}{
		{
			// FIPS mode withholds HKDF over an arbitrary base key (see TestFIPSMode).
			name:     "HKDF derive outside FIPS mode",
			mechType: CKM_HKDF_DERIVE,
			want:     !fips140.Enabled(),
		},
		{
			name:     "ECDH derive",
			mechType: CKM_ECDH1_DERIVE,
			want:     true,
		},
		{
			name:     "SP800-108 counter KDF",
			mechType: CKM_SP800_108_COUNTER_KDF,
			want:     true,
		},
		{
			name:     "AES GCM cannot derive",
			mechType: CKM_AES_GCM,
			want:     false,
		},
		{
			name:     "SHA256 cannot derive",
			mechType: CKM_SHA256,
			want:     false,
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanDerive(tt.mechType)
			if got != tt.want {
				t.Errorf("CanDerive(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestCanDigest tests CanDigest function.
func TestCanDigest(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     bool
	}{
		{
			name:     "SHA1",
			mechType: CKM_SHA_1,
			want:     true,
		},
		{
			name:     "SHA256",
			mechType: CKM_SHA256,
			want:     true,
		},
		{
			name:     "SHA384",
			mechType: CKM_SHA384,
			want:     true,
		},
		{
			name:     "SHA512",
			mechType: CKM_SHA512,
			want:     true,
		},
		{
			name:     "SHA512/224",
			mechType: CKM_SHA512_224,
			want:     true,
		},
		{
			name:     "SHA512/256",
			mechType: CKM_SHA512_256,
			want:     true,
		},
		// This case asserted CanDigest(CKM_SHA3_256) == true, which was the
		// defect stated as a test: the registry carried CKF_DIGEST for the
		// SHA-3 mechanisms while newDigestOperation has no SHA-3 case, so
		// C_DigestInit accepted the mechanism and C_Digest then failed with
		// CKR_MECHANISM_INVALID. The registry no longer claims a SHA-3 digest,
		// so CanDigest must now say so.
		{
			name:     "SHA3-256 is not implemented and must not claim to digest",
			mechType: CKM_SHA3_256,
			want:     false,
		},
		{
			name:     "AES GCM cannot digest",
			mechType: CKM_AES_GCM,
			want:     false,
		},
		{
			name:     "RSA PKCS cannot digest",
			mechType: CKM_RSA_PKCS,
			want:     false,
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanDigest(tt.mechType)
			if got != tt.want {
				t.Errorf("CanDigest(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestIsValidKeySize tests IsValidKeySize function.
func TestIsValidKeySize(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		keySize  uint32
		want     bool
	}{
		{
			// CKM_AES_KEY_GEN's MinKeySize/MaxKeySize are in bytes (PKCS#11
			// v3.2 §6.10.3), so AES-128's 128-bit key is expressed as 16
			// bytes here, not 128.
			name:     "AES-128 (16 bytes) valid",
			mechType: CKM_AES_KEY_GEN,
			keySize:  16,
			want:     true,
		},
		{
			name:     "AES-256 (32 bytes) valid",
			mechType: CKM_AES_KEY_GEN,
			keySize:  32,
			want:     true,
		},
		{
			name:     "AES-192 (24 bytes) valid",
			mechType: CKM_AES_KEY_GEN,
			keySize:  24,
			want:     true,
		},
		{
			name:     "AES 8 bytes (64 bits) too small",
			mechType: CKM_AES_KEY_GEN,
			keySize:  8,
			want:     false,
		},
		{
			name:     "AES 64 bytes (512 bits) too large",
			mechType: CKM_AES_KEY_GEN,
			keySize:  64,
			want:     false,
		},
		{
			name:     "RSA 2048 valid",
			mechType: CKM_RSA_PKCS_KEY_PAIR_GEN,
			keySize:  2048,
			want:     true,
		},
		{
			// PKCS#11 v3.2 §6.1.21 caps the modulus at 3072 bits in FIPS mode.
			name:     "RSA 4096 valid outside FIPS mode",
			mechType: CKM_RSA_PKCS_KEY_PAIR_GEN,
			keySize:  4096,
			want:     !fips140.Enabled(),
		},
		{
			name:     "RSA 256 too small",
			mechType: CKM_RSA_PKCS_KEY_PAIR_GEN,
			keySize:  256,
			want:     false,
		},
		{
			name:     "SHA256 any key size valid (no key size)",
			mechType: CKM_SHA256,
			keySize:  0,
			want:     true,
		},
		{
			name:     "SHA256 any non-zero key size valid",
			mechType: CKM_SHA256,
			keySize:  1000,
			want:     true,
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			keySize:  256,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidKeySize(tt.mechType, tt.keySize)
			if got != tt.want {
				t.Errorf("IsValidKeySize(%v, %d) = %v, want %v", tt.mechType, tt.keySize, got, tt.want)
			}
		})
	}
}

// TestListSupportedMechanisms tests ListSupportedMechanisms function.
func TestListSupportedMechanisms(t *testing.T) {
	mechanisms := ListSupportedMechanisms()

	if len(mechanisms) == 0 {
		t.Fatal("ListSupportedMechanisms returned empty slice")
	}

	// Check that known mechanisms are in the list
	knownMechanisms := []MechanismType{
		CKM_RSA_PKCS,
		CKM_AES_GCM,
		CKM_SHA256,
		CKM_EC_KEY_PAIR_GEN,
		CKM_ECDSA,
	}

	for _, known := range knownMechanisms {
		found := false
		for _, mech := range mechanisms {
			if mech == known {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected mechanism %v not found in list", known)
		}
	}

	// Verify all returned mechanisms are actually supported
	for _, mech := range mechanisms {
		if !IsMechanismSupported(mech) {
			t.Errorf("mechanism %v in list but IsMechanismSupported returns false", mech)
		}
	}
}

// TestListMechanismsByCategory tests ListMechanismsByCategory function.
func TestListMechanismsByCategory(t *testing.T) {
	tests := []struct {
		name          string
		category      MechanismCategory
		shouldHave    []MechanismType
		shouldNotHave []MechanismType
	}{
		{
			name:          "digest category",
			category:      CategoryDigest,
			shouldHave:    []MechanismType{CKM_SHA256, CKM_SHA384, CKM_SHA512},
			shouldNotHave: []MechanismType{CKM_RSA_PKCS, CKM_AES_GCM},
		},
		{
			name:          "sign category",
			category:      CategorySign,
			shouldHave:    []MechanismType{CKM_RSA_PKCS, CKM_ECDSA},
			shouldNotHave: []MechanismType{CKM_SHA256, CKM_AES_KEY_GEN},
		},
		{
			name:          "key pair gen category",
			category:      CategoryKeyPairGen,
			shouldHave:    []MechanismType{CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN},
			shouldNotHave: []MechanismType{CKM_SHA256, CKM_AES_GCM},
		},
		{
			name:          "derive category",
			category:      CategoryDerive,
			shouldHave:    []MechanismType{CKM_HKDF_DERIVE, CKM_ECDH1_DERIVE},
			shouldNotHave: []MechanismType{CKM_SHA256, CKM_RSA_PKCS},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mechanisms := ListMechanismsByCategory(tt.category)

			for _, should := range tt.shouldHave {
				found := false
				for _, mech := range mechanisms {
					if mech == should {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected mechanism %v not found in category %v", should, tt.category)
				}
			}

			for _, shouldNot := range tt.shouldNotHave {
				for _, mech := range mechanisms {
					if mech == shouldNot {
						t.Errorf("mechanism %v should not be in category %v", shouldNot, tt.category)
						break
					}
				}
			}
		})
	}
}

// TestGetDigestMechanismForHash tests GetDigestMechanismForHash function.
func TestGetDigestMechanismForHash(t *testing.T) {
	tests := []struct {
		name     string
		hashSize int
		want     MechanismType
	}{
		{
			name:     "SHA-1 (20 bytes)",
			hashSize: 20,
			want:     CKM_SHA_1,
		},
		{
			name:     "SHA-224 (28 bytes)",
			hashSize: 28,
			want:     CKM_SHA224,
		},
		{
			name:     "SHA-256 (32 bytes)",
			hashSize: 32,
			want:     CKM_SHA256,
		},
		{
			name:     "SHA-384 (48 bytes)",
			hashSize: 48,
			want:     CKM_SHA384,
		},
		{
			name:     "SHA-512 (64 bytes)",
			hashSize: 64,
			want:     CKM_SHA512,
		},
		{
			name:     "unknown hash size 16",
			hashSize: 16,
			want:     0,
		},
		{
			name:     "unknown hash size 0",
			hashSize: 0,
			want:     0,
		},
		{
			name:     "unknown hash size 100",
			hashSize: 100,
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetDigestMechanismForHash(tt.hashSize)
			if got != tt.want {
				t.Errorf("GetDigestMechanismForHash(%d) = %v, want %v", tt.hashSize, got, tt.want)
			}
		})
	}
}

// TestGetMGFForHash tests GetMGFForHash function.
func TestGetMGFForHash(t *testing.T) {
	tests := []struct {
		name     string
		hashMech MechanismType
		want     MGFType
	}{
		{
			name:     "SHA-1",
			hashMech: CKM_SHA_1,
			want:     CKG_MGF1_SHA1,
		},
		{
			name:     "SHA-224",
			hashMech: CKM_SHA224,
			want:     CKG_MGF1_SHA224,
		},
		{
			name:     "SHA-256",
			hashMech: CKM_SHA256,
			want:     CKG_MGF1_SHA256,
		},
		{
			name:     "SHA-384",
			hashMech: CKM_SHA384,
			want:     CKG_MGF1_SHA384,
		},
		{
			name:     "SHA-512",
			hashMech: CKM_SHA512,
			want:     CKG_MGF1_SHA512,
		},
		{
			name:     "SHA3-224",
			hashMech: CKM_SHA3_224,
			want:     CKG_MGF1_SHA3_224,
		},
		{
			name:     "SHA3-256",
			hashMech: CKM_SHA3_256,
			want:     CKG_MGF1_SHA3_256,
		},
		{
			name:     "SHA3-384",
			hashMech: CKM_SHA3_384,
			want:     CKG_MGF1_SHA3_384,
		},
		{
			name:     "SHA3-512",
			hashMech: CKM_SHA3_512,
			want:     CKG_MGF1_SHA3_512,
		},
		{
			name:     "unknown mechanism",
			hashMech: CKM_AES_GCM,
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetMGFForHash(tt.hashMech)
			if got != tt.want {
				t.Errorf("GetMGFForHash(%v) = %v, want %v", tt.hashMech, got, tt.want)
			}
		})
	}
}

// TestNewRSAOAEPParams tests NewRSAOAEPParams function.
func TestNewRSAOAEPParams(t *testing.T) {
	tests := []struct {
		name    string
		hashAlg MechanismType
		wantMGF MGFType
	}{
		{
			name:    "SHA-256",
			hashAlg: CKM_SHA256,
			wantMGF: CKG_MGF1_SHA256,
		},
		{
			name:    "SHA-384",
			hashAlg: CKM_SHA384,
			wantMGF: CKG_MGF1_SHA384,
		},
		{
			name:    "SHA-512",
			hashAlg: CKM_SHA512,
			wantMGF: CKG_MGF1_SHA512,
		},
		{
			name:    "SHA-1",
			hashAlg: CKM_SHA_1,
			wantMGF: CKG_MGF1_SHA1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewRSAOAEPParams(tt.hashAlg)
			if params == nil {
				t.Fatal("NewRSAOAEPParams returned nil")
			}
			if params.HashAlg != tt.hashAlg {
				t.Errorf("HashAlg = %v, want %v", params.HashAlg, tt.hashAlg)
			}
			if params.MGF != tt.wantMGF {
				t.Errorf("MGF = %v, want %v", params.MGF, tt.wantMGF)
			}
			if params.Source != CKZ_DATA_SPECIFIED {
				t.Errorf("Source = %v, want %v", params.Source, CKZ_DATA_SPECIFIED)
			}
			if params.SourceData != nil {
				t.Error("SourceData should be nil")
			}
		})
	}
}

// TestNewRSAOAEPParamsWithLabel tests NewRSAOAEPParamsWithLabel function.
func TestNewRSAOAEPParamsWithLabel(t *testing.T) {
	tests := []struct {
		name    string
		hashAlg MechanismType
		label   []byte
	}{
		{
			name:    "with label",
			hashAlg: CKM_SHA256,
			label:   []byte("test label"),
		},
		{
			name:    "with empty label",
			hashAlg: CKM_SHA384,
			label:   []byte{},
		},
		{
			name:    "with nil label",
			hashAlg: CKM_SHA512,
			label:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewRSAOAEPParamsWithLabel(tt.hashAlg, tt.label)
			if params == nil {
				t.Fatal("NewRSAOAEPParamsWithLabel returned nil")
			}
			if params.HashAlg != tt.hashAlg {
				t.Errorf("HashAlg = %v, want %v", params.HashAlg, tt.hashAlg)
			}
			if params.Source != CKZ_DATA_SPECIFIED {
				t.Errorf("Source = %v, want %v", params.Source, CKZ_DATA_SPECIFIED)
			}
			if tt.label == nil && params.SourceData != nil {
				t.Error("SourceData should be nil when label is nil")
			}
			if tt.label != nil && len(params.SourceData) != len(tt.label) {
				t.Errorf("SourceData length = %d, want %d", len(params.SourceData), len(tt.label))
			}
		})
	}
}

// TestNewRSAPSSParams tests NewRSAPSSParams function.
func TestNewRSAPSSParams(t *testing.T) {
	tests := []struct {
		name        string
		hashAlg     MechanismType
		wantMGF     MGFType
		wantSaltLen uint32
	}{
		{
			name:        "SHA-1",
			hashAlg:     CKM_SHA_1,
			wantMGF:     CKG_MGF1_SHA1,
			wantSaltLen: 20,
		},
		{
			name:        "SHA-224",
			hashAlg:     CKM_SHA224,
			wantMGF:     CKG_MGF1_SHA224,
			wantSaltLen: 28,
		},
		{
			name:        "SHA-256",
			hashAlg:     CKM_SHA256,
			wantMGF:     CKG_MGF1_SHA256,
			wantSaltLen: 32,
		},
		{
			name:        "SHA-384",
			hashAlg:     CKM_SHA384,
			wantMGF:     CKG_MGF1_SHA384,
			wantSaltLen: 48,
		},
		{
			name:        "SHA-512",
			hashAlg:     CKM_SHA512,
			wantMGF:     CKG_MGF1_SHA512,
			wantSaltLen: 64,
		},
		{
			name:        "unknown hash defaults to 32",
			hashAlg:     CKM_AES_GCM,
			wantMGF:     0,
			wantSaltLen: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewRSAPSSParams(tt.hashAlg)
			if params == nil {
				t.Fatal("NewRSAPSSParams returned nil")
			}
			if params.HashAlg != tt.hashAlg {
				t.Errorf("HashAlg = %v, want %v", params.HashAlg, tt.hashAlg)
			}
			if params.MGF != tt.wantMGF {
				t.Errorf("MGF = %v, want %v", params.MGF, tt.wantMGF)
			}
			if params.SaltLen != tt.wantSaltLen {
				t.Errorf("SaltLen = %d, want %d", params.SaltLen, tt.wantSaltLen)
			}
		})
	}
}

// TestNewRSAPSSParamsWithSaltLen tests NewRSAPSSParamsWithSaltLen function.
func TestNewRSAPSSParamsWithSaltLen(t *testing.T) {
	tests := []struct {
		name    string
		hashAlg MechanismType
		saltLen uint32
	}{
		{
			name:    "SHA-256 with custom salt",
			hashAlg: CKM_SHA256,
			saltLen: 0,
		},
		{
			name:    "SHA-384 with salt 20",
			hashAlg: CKM_SHA384,
			saltLen: 20,
		},
		{
			name:    "SHA-512 with salt 64",
			hashAlg: CKM_SHA512,
			saltLen: 64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewRSAPSSParamsWithSaltLen(tt.hashAlg, tt.saltLen)
			if params == nil {
				t.Fatal("NewRSAPSSParamsWithSaltLen returned nil")
			}
			if params.HashAlg != tt.hashAlg {
				t.Errorf("HashAlg = %v, want %v", params.HashAlg, tt.hashAlg)
			}
			if params.SaltLen != tt.saltLen {
				t.Errorf("SaltLen = %d, want %d", params.SaltLen, tt.saltLen)
			}
		})
	}
}

// TestNewAESGCMParams tests NewAESGCMParams function.
func TestNewAESGCMParams(t *testing.T) {
	tests := []struct {
		name    string
		iv      []byte
		tagBits uint32
	}{
		{
			name:    "standard 12-byte IV 128-bit tag",
			iv:      make([]byte, 12),
			tagBits: 128,
		},
		{
			name:    "16-byte IV 96-bit tag",
			iv:      make([]byte, 16),
			tagBits: 96,
		},
		{
			name:    "nil IV",
			iv:      nil,
			tagBits: 128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewAESGCMParams(tt.iv, tt.tagBits)
			if params == nil {
				t.Fatal("NewAESGCMParams returned nil")
			}
			if tt.iv == nil && params.IV != nil {
				t.Error("IV should be nil when nil passed")
			}
			if tt.iv != nil && len(params.IV) != len(tt.iv) {
				t.Errorf("IV length = %d, want %d", len(params.IV), len(tt.iv))
			}
			if params.TagBits != tt.tagBits {
				t.Errorf("TagBits = %d, want %d", params.TagBits, tt.tagBits)
			}
			if params.AAD != nil {
				t.Error("AAD should be nil")
			}
		})
	}
}

// TestNewAESGCMParamsWithAAD tests NewAESGCMParamsWithAAD function.
func TestNewAESGCMParamsWithAAD(t *testing.T) {
	tests := []struct {
		name    string
		iv      []byte
		aad     []byte
		tagBits uint32
	}{
		{
			name:    "with AAD",
			iv:      make([]byte, 12),
			aad:     []byte("additional data"),
			tagBits: 128,
		},
		{
			name:    "with empty AAD",
			iv:      make([]byte, 12),
			aad:     []byte{},
			tagBits: 128,
		},
		{
			name:    "with nil AAD",
			iv:      make([]byte, 12),
			aad:     nil,
			tagBits: 128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewAESGCMParamsWithAAD(tt.iv, tt.aad, tt.tagBits)
			if params == nil {
				t.Fatal("NewAESGCMParamsWithAAD returned nil")
			}
			if len(params.IV) != len(tt.iv) {
				t.Errorf("IV length = %d, want %d", len(params.IV), len(tt.iv))
			}
			if params.TagBits != tt.tagBits {
				t.Errorf("TagBits = %d, want %d", params.TagBits, tt.tagBits)
			}
			if tt.aad == nil && params.AAD != nil {
				t.Error("AAD should be nil when nil passed")
			}
			if tt.aad != nil && len(params.AAD) != len(tt.aad) {
				t.Errorf("AAD length = %d, want %d", len(params.AAD), len(tt.aad))
			}
		})
	}
}

// TestNewAESCBCParams tests NewAESCBCParams function.
func TestNewAESCBCParams(t *testing.T) {
	tests := []struct {
		name string
		iv   [16]byte
	}{
		{
			name: "zero IV",
			iv:   [16]byte{},
		},
		{
			name: "non-zero IV",
			iv:   [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewAESCBCParams(tt.iv)
			if params == nil {
				t.Fatal("NewAESCBCParams returned nil")
			}
			if params.IV != tt.iv {
				t.Errorf("IV = %v, want %v", params.IV, tt.iv)
			}
		})
	}
}

// TestNewECDHParams tests NewECDHParams function.
func TestNewECDHParams(t *testing.T) {
	tests := []struct {
		name       string
		kdf        KDFType
		publicData []byte
	}{
		{
			name:       "with NULL KDF",
			kdf:        CKD_NULL,
			publicData: []byte{0x04, 0x01, 0x02, 0x03},
		},
		{
			name:       "with SHA256 KDF",
			kdf:        CKD_SHA256_KDF,
			publicData: make([]byte, 65),
		},
		{
			name:       "with nil public data",
			kdf:        CKD_NULL,
			publicData: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewECDHParams(tt.kdf, tt.publicData)
			if params == nil {
				t.Fatal("NewECDHParams returned nil")
			}
			if params.KDF != tt.kdf {
				t.Errorf("KDF = %v, want %v", params.KDF, tt.kdf)
			}
			if params.SharedData != nil {
				t.Error("SharedData should be nil")
			}
			if tt.publicData == nil && params.PublicData != nil {
				t.Error("PublicData should be nil when nil passed")
			}
			if tt.publicData != nil && len(params.PublicData) != len(tt.publicData) {
				t.Errorf("PublicData length = %d, want %d", len(params.PublicData), len(tt.publicData))
			}
		})
	}
}

// TestNewECDHParamsWithSharedData tests NewECDHParamsWithSharedData function.
func TestNewECDHParamsWithSharedData(t *testing.T) {
	tests := []struct {
		name       string
		kdf        KDFType
		sharedData []byte
		publicData []byte
	}{
		{
			name:       "with shared data",
			kdf:        CKD_SHA256_KDF,
			sharedData: []byte("shared info"),
			publicData: []byte{0x04, 0x01, 0x02, 0x03},
		},
		{
			name:       "with nil shared data",
			kdf:        CKD_NULL,
			sharedData: nil,
			publicData: []byte{0x04, 0x01, 0x02, 0x03},
		},
		{
			name:       "with empty shared data",
			kdf:        CKD_SHA512_KDF,
			sharedData: []byte{},
			publicData: make([]byte, 65),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewECDHParamsWithSharedData(tt.kdf, tt.sharedData, tt.publicData)
			if params == nil {
				t.Fatal("NewECDHParamsWithSharedData returned nil")
			}
			if params.KDF != tt.kdf {
				t.Errorf("KDF = %v, want %v", params.KDF, tt.kdf)
			}
			if tt.sharedData == nil && params.SharedData != nil {
				t.Error("SharedData should be nil when nil passed")
			}
			if tt.sharedData != nil && len(params.SharedData) != len(tt.sharedData) {
				t.Errorf("SharedData length = %d, want %d", len(params.SharedData), len(tt.sharedData))
			}
			if len(params.PublicData) != len(tt.publicData) {
				t.Errorf("PublicData length = %d, want %d", len(params.PublicData), len(tt.publicData))
			}
		})
	}
}

// TestNewHKDFParams tests NewHKDFParams function.
func TestNewHKDFParams(t *testing.T) {
	tests := []struct {
		name     string
		hashMech MechanismType
		salt     []byte
		info     []byte
	}{
		{
			name:     "SHA256 with salt and info",
			hashMech: CKM_SHA256,
			salt:     []byte("salt"),
			info:     []byte("info"),
		},
		{
			name:     "SHA384 with nil salt",
			hashMech: CKM_SHA384,
			salt:     nil,
			info:     []byte("info"),
		},
		{
			name:     "SHA512 with nil info",
			hashMech: CKM_SHA512,
			salt:     []byte("salt"),
			info:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewHKDFParams(tt.hashMech, tt.salt, tt.info)
			if params == nil {
				t.Fatal("NewHKDFParams returned nil")
			}
			if !params.Extract {
				t.Error("Extract should be true")
			}
			if !params.Expand {
				t.Error("Expand should be true")
			}
			if params.PRFHashMech != tt.hashMech {
				t.Errorf("PRFHashMech = %v, want %v", params.PRFHashMech, tt.hashMech)
			}
			if params.SaltType != CKF_HKDF_SALT_DATA {
				t.Errorf("SaltType = %v, want %v", params.SaltType, CKF_HKDF_SALT_DATA)
			}
			if params.SaltKey != 0 {
				t.Error("SaltKey should be 0")
			}
		})
	}
}

// TestNewHKDFExpandOnlyParams tests NewHKDFExpandOnlyParams function.
func TestNewHKDFExpandOnlyParams(t *testing.T) {
	tests := []struct {
		name     string
		hashMech MechanismType
		info     []byte
	}{
		{
			name:     "SHA256 with info",
			hashMech: CKM_SHA256,
			info:     []byte("expand info"),
		},
		{
			name:     "SHA384 with nil info",
			hashMech: CKM_SHA384,
			info:     nil,
		},
		{
			name:     "SHA512 with empty info",
			hashMech: CKM_SHA512,
			info:     []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewHKDFExpandOnlyParams(tt.hashMech, tt.info)
			if params == nil {
				t.Fatal("NewHKDFExpandOnlyParams returned nil")
			}
			if params.Extract {
				t.Error("Extract should be false for expand-only")
			}
			if !params.Expand {
				t.Error("Expand should be true")
			}
			if params.PRFHashMech != tt.hashMech {
				t.Errorf("PRFHashMech = %v, want %v", params.PRFHashMech, tt.hashMech)
			}
			if params.SaltType != CKF_HKDF_SALT_NULL {
				t.Errorf("SaltType = %v, want %v", params.SaltType, CKF_HKDF_SALT_NULL)
			}
			if params.Salt != nil {
				t.Error("Salt should be nil for expand-only")
			}
		})
	}
}

// TestNewHKDFExtractOnlyParams tests NewHKDFExtractOnlyParams function.
func TestNewHKDFExtractOnlyParams(t *testing.T) {
	tests := []struct {
		name         string
		hashMech     MechanismType
		salt         []byte
		wantSaltType HKDFSaltType
	}{
		{
			name:         "SHA256 with salt",
			hashMech:     CKM_SHA256,
			salt:         []byte("extract salt"),
			wantSaltType: CKF_HKDF_SALT_DATA,
		},
		{
			name:         "SHA384 with nil salt",
			hashMech:     CKM_SHA384,
			salt:         nil,
			wantSaltType: CKF_HKDF_SALT_NULL,
		},
		{
			name:         "SHA512 with empty salt",
			hashMech:     CKM_SHA512,
			salt:         []byte{},
			wantSaltType: CKF_HKDF_SALT_NULL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewHKDFExtractOnlyParams(tt.hashMech, tt.salt)
			if params == nil {
				t.Fatal("NewHKDFExtractOnlyParams returned nil")
			}
			if !params.Extract {
				t.Error("Extract should be true")
			}
			if params.Expand {
				t.Error("Expand should be false for extract-only")
			}
			if params.PRFHashMech != tt.hashMech {
				t.Errorf("PRFHashMech = %v, want %v", params.PRFHashMech, tt.hashMech)
			}
			if params.SaltType != tt.wantSaltType {
				t.Errorf("SaltType = %v, want %v", params.SaltType, tt.wantSaltType)
			}
			if params.Info != nil {
				t.Error("Info should be nil for extract-only")
			}
		})
	}
}

// TestMechanismType_String tests MechanismType.String method.
func TestMechanismType_String(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     string
	}{
		{
			name:     "RSA PKCS",
			mechType: CKM_RSA_PKCS,
			want:     "CKM_RSA_PKCS",
		},
		{
			name:     "AES GCM",
			mechType: CKM_AES_GCM,
			want:     "CKM_AES_GCM",
		},
		{
			name:     "unknown",
			mechType: MechanismType(0x12345678),
			want:     "CKM_UNKNOWN(0x12345678)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mechType.String()
			if got != tt.want {
				t.Errorf("MechanismType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMGFType_String tests MGFType.String method.
func TestMGFType_String(t *testing.T) {
	tests := []struct {
		name string
		mgf  MGFType
		want string
	}{
		{
			name: "MGF1 SHA1",
			mgf:  CKG_MGF1_SHA1,
			want: "CKG_MGF1_SHA1",
		},
		{
			name: "MGF1 SHA256",
			mgf:  CKG_MGF1_SHA256,
			want: "CKG_MGF1_SHA256",
		},
		{
			name: "MGF1 SHA384",
			mgf:  CKG_MGF1_SHA384,
			want: "CKG_MGF1_SHA384",
		},
		{
			name: "MGF1 SHA512",
			mgf:  CKG_MGF1_SHA512,
			want: "CKG_MGF1_SHA512",
		},
		{
			name: "MGF1 SHA224",
			mgf:  CKG_MGF1_SHA224,
			want: "CKG_MGF1_SHA224",
		},
		{
			name: "MGF1 SHA3-224",
			mgf:  CKG_MGF1_SHA3_224,
			want: "CKG_MGF1_SHA3_224",
		},
		{
			name: "MGF1 SHA3-256",
			mgf:  CKG_MGF1_SHA3_256,
			want: "CKG_MGF1_SHA3_256",
		},
		{
			name: "MGF1 SHA3-384",
			mgf:  CKG_MGF1_SHA3_384,
			want: "CKG_MGF1_SHA3_384",
		},
		{
			name: "MGF1 SHA3-512",
			mgf:  CKG_MGF1_SHA3_512,
			want: "CKG_MGF1_SHA3_512",
		},
		{
			name: "unknown MGF",
			mgf:  MGFType(0x12345678),
			want: "CKG_UNKNOWN(0x12345678)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mgf.String()
			if got != tt.want {
				t.Errorf("MGFType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestKDFType_String tests KDFType.String method.
func TestKDFType_String(t *testing.T) {
	tests := []struct {
		name string
		kdf  KDFType
		want string
	}{
		{
			name: "NULL KDF",
			kdf:  CKD_NULL,
			want: "CKD_NULL",
		},
		{
			name: "SHA1 KDF",
			kdf:  CKD_SHA1_KDF,
			want: "CKD_SHA1_KDF",
		},
		{
			name: "SHA1 KDF ASN1",
			kdf:  CKD_SHA1_KDF_ASN1,
			want: "CKD_SHA1_KDF_ASN1",
		},
		{
			name: "SHA1 KDF Concatenate",
			kdf:  CKD_SHA1_KDF_CONCATENATE,
			want: "CKD_SHA1_KDF_CONCATENATE",
		},
		{
			name: "SHA224 KDF",
			kdf:  CKD_SHA224_KDF,
			want: "CKD_SHA224_KDF",
		},
		{
			name: "SHA256 KDF",
			kdf:  CKD_SHA256_KDF,
			want: "CKD_SHA256_KDF",
		},
		{
			name: "SHA384 KDF",
			kdf:  CKD_SHA384_KDF,
			want: "CKD_SHA384_KDF",
		},
		{
			name: "SHA512 KDF",
			kdf:  CKD_SHA512_KDF,
			want: "CKD_SHA512_KDF",
		},
		{
			name: "SHA3-224 KDF",
			kdf:  CKD_SHA3_224_KDF,
			want: "CKD_SHA3_224_KDF",
		},
		{
			name: "SHA3-256 KDF",
			kdf:  CKD_SHA3_256_KDF,
			want: "CKD_SHA3_256_KDF",
		},
		{
			name: "SHA3-384 KDF",
			kdf:  CKD_SHA3_384_KDF,
			want: "CKD_SHA3_384_KDF",
		},
		{
			name: "SHA3-512 KDF",
			kdf:  CKD_SHA3_512_KDF,
			want: "CKD_SHA3_512_KDF",
		},
		{
			name: "unknown KDF",
			kdf:  KDFType(0x12345678),
			want: "CKD_UNKNOWN(0x12345678)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.kdf.String()
			if got != tt.want {
				t.Errorf("KDFType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMechanismCategory_String tests MechanismCategory.String method.
func TestMechanismCategory_String(t *testing.T) {
	tests := []struct {
		name     string
		category MechanismCategory
		want     string
	}{
		{
			name:     "Digest",
			category: CategoryDigest,
			want:     "Digest",
		},
		{
			name:     "Sign",
			category: CategorySign,
			want:     "Sign",
		},
		{
			name:     "Verify",
			category: CategoryVerify,
			want:     "Verify",
		},
		{
			name:     "Encrypt",
			category: CategoryEncrypt,
			want:     "Encrypt",
		},
		{
			name:     "Decrypt",
			category: CategoryDecrypt,
			want:     "Decrypt",
		},
		{
			name:     "KeyGen",
			category: CategoryKeyGen,
			want:     "KeyGen",
		},
		{
			name:     "KeyPairGen",
			category: CategoryKeyPairGen,
			want:     "KeyPairGen",
		},
		{
			name:     "Wrap",
			category: CategoryWrap,
			want:     "Wrap",
		},
		{
			name:     "Unwrap",
			category: CategoryUnwrap,
			want:     "Unwrap",
		},
		{
			name:     "Derive",
			category: CategoryDerive,
			want:     "Derive",
		},
		{
			name:     "unknown category",
			category: MechanismCategory(255),
			want:     "Unknown(255)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.category.String()
			if got != tt.want {
				t.Errorf("MechanismCategory.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMechanismInfo_HasFlag tests MechanismInfo.HasFlag method.
func TestMechanismInfo_HasFlag(t *testing.T) {
	tests := []struct {
		name string
		info *MechanismInfo
		flag MechanismFlag
		want bool
	}{
		{
			name: "has sign flag",
			info: &MechanismInfo{
				Flags: CKF_SIGN | CKF_VERIFY,
			},
			flag: CKF_SIGN,
			want: true,
		},
		{
			name: "has verify flag",
			info: &MechanismInfo{
				Flags: CKF_SIGN | CKF_VERIFY,
			},
			flag: CKF_VERIFY,
			want: true,
		},
		{
			name: "does not have encrypt flag",
			info: &MechanismInfo{
				Flags: CKF_SIGN | CKF_VERIFY,
			},
			flag: CKF_ENCRYPT,
			want: false,
		},
		{
			name: "no flags set",
			info: &MechanismInfo{
				Flags: 0,
			},
			flag: CKF_SIGN,
			want: false,
		},
		{
			name: "all flags set",
			info: &MechanismInfo{
				Flags: 0xFFFFFFFF,
			},
			flag: CKF_HW,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.info.HasFlag(tt.flag)
			if got != tt.want {
				t.Errorf("HasFlag(%v) = %v, want %v", tt.flag, got, tt.want)
			}
		})
	}
}

// TestMechanismInfo_SupportsHardware tests MechanismInfo.SupportsHardware method.
func TestMechanismInfo_SupportsHardware(t *testing.T) {
	tests := []struct {
		name string
		info *MechanismInfo
		want bool
	}{
		{
			name: "supports hardware",
			info: &MechanismInfo{
				Flags: CKF_HW | CKF_SIGN,
			},
			want: true,
		},
		{
			name: "does not support hardware",
			info: &MechanismInfo{
				Flags: CKF_SIGN | CKF_VERIFY,
			},
			want: false,
		},
		{
			name: "only HW flag",
			info: &MechanismInfo{
				Flags: CKF_HW,
			},
			want: true,
		},
		{
			name: "no flags",
			info: &MechanismInfo{
				Flags: 0,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.info.SupportsHardware()
			if got != tt.want {
				t.Errorf("SupportsHardware() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetMechanismDescriptor tests GetMechanismDescriptor function.
func TestGetMechanismDescriptor(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		wantNil  bool
		wantName string
	}{
		{
			name:     "RSA PKCS",
			mechType: CKM_RSA_PKCS,
			wantNil:  false,
			wantName: "CKM_RSA_PKCS",
		},
		{
			name:     "AES GCM",
			mechType: CKM_AES_GCM,
			wantNil:  false,
			wantName: "CKM_AES_GCM",
		},
		{
			name:     "SHA256",
			mechType: CKM_SHA256,
			wantNil:  false,
			wantName: "CKM_SHA256",
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := GetMechanismDescriptor(tt.mechType)
			if tt.wantNil {
				if desc != nil {
					t.Error("expected nil descriptor")
				}
				return
			}
			if desc == nil {
				t.Fatal("descriptor is nil")
			}
			if desc.Name != tt.wantName {
				t.Errorf("Name = %v, want %v", desc.Name, tt.wantName)
			}
			if desc.Type != tt.mechType {
				t.Errorf("Type = %v, want %v", desc.Type, tt.mechType)
			}
		})
	}
}

// TestMechanismDescriptor_Categories tests that descriptors have correct categories.
func TestMechanismDescriptor_Categories(t *testing.T) {
	tests := []struct {
		name           string
		mechType       MechanismType
		wantCategories []MechanismCategory
	}{
		{
			name:           "RSA PKCS key pair gen",
			mechType:       CKM_RSA_PKCS_KEY_PAIR_GEN,
			wantCategories: []MechanismCategory{CategoryKeyPairGen},
		},
		{
			name:           "SHA256 digest",
			mechType:       CKM_SHA256,
			wantCategories: []MechanismCategory{CategoryDigest},
		},
		{
			name:           "AES key gen",
			mechType:       CKM_AES_KEY_GEN,
			wantCategories: []MechanismCategory{CategoryKeyGen},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := GetMechanismDescriptor(tt.mechType)
			if desc == nil {
				t.Fatal("descriptor is nil")
			}
			if len(desc.Categories) != len(tt.wantCategories) {
				t.Errorf("categories length = %d, want %d", len(desc.Categories), len(tt.wantCategories))
			}
			for i, cat := range tt.wantCategories {
				found := false
				for _, c := range desc.Categories {
					if c == cat {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("category[%d] %v not found", i, cat)
				}
			}
		})
	}
}

// TestMechanismInfo_ErrorHandling tests error handling for GetMechanismInfo.
func TestMechanismInfo_ErrorHandling(t *testing.T) {
	info, err := GetMechanismInfo(MechanismType(0xFFFFFFFF))
	if err == nil {
		t.Error("expected error for unknown mechanism")
	}
	if info != nil {
		t.Error("info should be nil when error returned")
	}
	if err != ErrMechanismInvalid {
		t.Errorf("expected ErrMechanismInvalid, got %v", err)
	}
}

// TestMechanismConstants tests that mechanism constants have correct values.
func TestMechanismConstants(t *testing.T) {
	// Verify some key constants match PKCS#11 spec
	tests := []struct {
		name     string
		constant MechanismType
		want     uint32
	}{
		{
			name:     "CKM_RSA_PKCS_KEY_PAIR_GEN",
			constant: CKM_RSA_PKCS_KEY_PAIR_GEN,
			want:     0x00000000,
		},
		{
			name:     "CKM_RSA_PKCS",
			constant: CKM_RSA_PKCS,
			want:     0x00000001,
		},
		{
			name:     "CKM_SHA256",
			constant: CKM_SHA256,
			want:     0x00000250,
		},
		{
			name:     "CKM_AES_KEY_GEN",
			constant: CKM_AES_KEY_GEN,
			want:     0x00001080,
		},
		{
			name:     "CKM_AES_GCM",
			constant: CKM_AES_GCM,
			want:     0x00001087,
		},
		{
			name:     "CKM_EC_KEY_PAIR_GEN",
			constant: CKM_EC_KEY_PAIR_GEN,
			want:     0x00001040,
		},
		{
			name:     "CKM_ECDSA",
			constant: CKM_ECDSA,
			want:     0x00001041,
		},
		{
			name:     "CKM_VENDOR_DEFINED",
			constant: CKM_VENDOR_DEFINED,
			want:     0x80000000,
		},
		// SHA-3 digest mechanism hex-pinning. OASIS allocates SHA3-256 the
		// lowest block, ahead of SHA3-224, so these are not in ascending
		// digest-size order.
		{
			name:     "CKM_SHA3_256",
			constant: CKM_SHA3_256,
			want:     0x000002B0,
		},
		{
			name:     "CKM_SHA3_224",
			constant: CKM_SHA3_224,
			want:     0x000002B5,
		},
		{
			name:     "CKM_SHA3_384",
			constant: CKM_SHA3_384,
			want:     0x000002C0,
		},
		{
			name:     "CKM_SHA3_512",
			constant: CKM_SHA3_512,
			want:     0x000002D0,
		},
		// SHA-3 HMAC hex-pinning
		{
			name:     "CKM_SHA3_256_HMAC",
			constant: CKM_SHA3_256_HMAC,
			want:     0x000002B1,
		},
		{
			name:     "CKM_SHA3_224_HMAC",
			constant: CKM_SHA3_224_HMAC,
			want:     0x000002B6,
		},
		{
			name:     "CKM_SHA3_384_HMAC",
			constant: CKM_SHA3_384_HMAC,
			want:     0x000002C1,
		},
		{
			name:     "CKM_SHA3_512_HMAC",
			constant: CKM_SHA3_512_HMAC,
			want:     0x000002D1,
		},
		// SHA-3 general-length HMAC hex-pinning
		{
			name:     "CKM_SHA3_256_HMAC_GENERAL",
			constant: CKM_SHA3_256_HMAC_GENERAL,
			want:     0x000002B2,
		},
		{
			name:     "CKM_SHA3_224_HMAC_GENERAL",
			constant: CKM_SHA3_224_HMAC_GENERAL,
			want:     0x000002B7,
		},
		{
			name:     "CKM_SHA3_384_HMAC_GENERAL",
			constant: CKM_SHA3_384_HMAC_GENERAL,
			want:     0x000002C2,
		},
		{
			name:     "CKM_SHA3_512_HMAC_GENERAL",
			constant: CKM_SHA3_512_HMAC_GENERAL,
			want:     0x000002D2,
		},
		// DES3_CMAC hex-pinning (name/value swap corrected)
		{
			name:     "CKM_DES3_CMAC_GENERAL",
			constant: CKM_DES3_CMAC_GENERAL,
			want:     0x00000137,
		},
		{
			name:     "CKM_DES3_CMAC",
			constant: CKM_DES3_CMAC,
			want:     0x00000138,
		},
		// RSA AES key wrap hex-pinning (corrected from 0x1091)
		{
			name:     "CKM_RSA_AES_KEY_WRAP",
			constant: CKM_RSA_AES_KEY_WRAP,
			want:     0x00001054,
		},
		// HKDF mechanism hex-pinning. The block starts at 0x402A; 0x402C is
		// CKM_HKDF_KEY_GEN, not CKM_HKDF_DERIVE.
		{
			name:     "CKM_HKDF_DERIVE",
			constant: CKM_HKDF_DERIVE,
			want:     0x0000402A,
		},
		{
			name:     "CKM_HKDF_DATA",
			constant: CKM_HKDF_DATA,
			want:     0x0000402B,
		},
		{
			name:     "CKM_HKDF_KEY_GEN",
			constant: CKM_HKDF_KEY_GEN,
			want:     0x0000402C,
		},
		// XEdDSA hex-pinning. OASIS places it in the 0x4000 block, not
		// alongside the Edwards mechanisms at 0x1055-0x1057.
		{
			name:     "CKM_XEDDSA",
			constant: CKM_XEDDSA,
			want:     0x00004029,
		},
		// AES-XTS hex-pinning. OASIS allocates these after
		// CKM_RSA_AES_KEY_WRAP (0x1054), not in the 0x2100 AES block.
		{
			name:     "CKM_AES_XTS",
			constant: CKM_AES_XTS,
			want:     0x00001071,
		},
		{
			name:     "CKM_AES_XTS_KEY_GEN",
			constant: CKM_AES_XTS_KEY_GEN,
			want:     0x00001072,
		},
		// ACTI hex-pinning. The operation precedes the key generator here,
		// unlike the SecurID and HOTP blocks.
		{
			name:     "CKM_ACTI",
			constant: CKM_ACTI,
			want:     0x000002A0,
		},
		{
			name:     "CKM_ACTI_KEY_GEN",
			constant: CKM_ACTI_KEY_GEN,
			want:     0x000002A1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint32(tt.constant) != tt.want {
				t.Errorf("%s = 0x%08X, want 0x%08X", tt.name, uint32(tt.constant), tt.want)
			}
		})
	}
}

// TestMGFConstants tests that MGF constants have correct values.
func TestMGFConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant MGFType
		want     uint32
	}{
		{
			name:     "CKG_MGF1_SHA1",
			constant: CKG_MGF1_SHA1,
			want:     0x00000001,
		},
		{
			name:     "CKG_MGF1_SHA256",
			constant: CKG_MGF1_SHA256,
			want:     0x00000002,
		},
		{
			name:     "CKG_MGF1_SHA384",
			constant: CKG_MGF1_SHA384,
			want:     0x00000003,
		},
		{
			name:     "CKG_MGF1_SHA512",
			constant: CKG_MGF1_SHA512,
			want:     0x00000004,
		},
		{
			name:     "CKG_MGF1_SHA224",
			constant: CKG_MGF1_SHA224,
			want:     0x00000005,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint32(tt.constant) != tt.want {
				t.Errorf("%s = 0x%08X, want 0x%08X", tt.name, uint32(tt.constant), tt.want)
			}
		})
	}
}

// TestMechanismFlagConstants tests that mechanism flag constants have correct values.
func TestMechanismFlagConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant MechanismFlag
		want     uint32
	}{
		{
			name:     "CKF_HW",
			constant: CKF_HW,
			want:     0x00000001,
		},
		{
			name:     "CKF_ENCRYPT",
			constant: CKF_ENCRYPT,
			want:     0x00000100,
		},
		{
			name:     "CKF_DECRYPT",
			constant: CKF_DECRYPT,
			want:     0x00000200,
		},
		{
			name:     "CKF_DIGEST",
			constant: CKF_DIGEST,
			want:     0x00000400,
		},
		{
			name:     "CKF_SIGN",
			constant: CKF_SIGN,
			want:     0x00000800,
		},
		{
			name:     "CKF_VERIFY",
			constant: CKF_VERIFY,
			want:     0x00002000,
		},
		{
			name:     "CKF_GENERATE",
			constant: CKF_GENERATE,
			want:     0x00008000,
		},
		{
			name:     "CKF_GENERATE_KEY_PAIR",
			constant: CKF_GENERATE_KEY_PAIR,
			want:     0x00010000,
		},
		{
			name:     "CKF_WRAP",
			constant: CKF_WRAP,
			want:     0x00020000,
		},
		{
			name:     "CKF_UNWRAP",
			constant: CKF_UNWRAP,
			want:     0x00040000,
		},
		{
			name:     "CKF_DERIVE",
			constant: CKF_DERIVE,
			want:     0x00080000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint32(tt.constant) != tt.want {
				t.Errorf("%s = 0x%08X, want 0x%08X", tt.name, uint32(tt.constant), tt.want)
			}
		})
	}
}

// TestHKDFSaltTypeConstants tests HKDF salt type constants.
func TestHKDFSaltTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant HKDFSaltType
		want     uint32
	}{
		{
			name:     "CKF_HKDF_SALT_NULL",
			constant: CKF_HKDF_SALT_NULL,
			want:     0x00000001,
		},
		{
			name:     "CKF_HKDF_SALT_DATA",
			constant: CKF_HKDF_SALT_DATA,
			want:     0x00000002,
		},
		{
			// The salt types are single-bit flags, so this is 0x4; 0x3 is
			// the union of CKF_HKDF_SALT_NULL and CKF_HKDF_SALT_DATA.
			name:     "CKF_HKDF_SALT_KEY",
			constant: CKF_HKDF_SALT_KEY,
			want:     0x00000004,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint32(tt.constant) != tt.want {
				t.Errorf("%s = 0x%08X, want 0x%08X", tt.name, uint32(tt.constant), tt.want)
			}
		})
	}
}

// TestKDFTypeConstants tests KDF type constants.
func TestKDFTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant KDFType
		want     uint32
	}{
		{
			name:     "CKD_NULL",
			constant: CKD_NULL,
			want:     0x00000001,
		},
		{
			name:     "CKD_SHA1_KDF",
			constant: CKD_SHA1_KDF,
			want:     0x00000002,
		},
		{
			name:     "CKD_SHA256_KDF",
			constant: CKD_SHA256_KDF,
			want:     0x00000006,
		},
		{
			name:     "CKD_SHA384_KDF",
			constant: CKD_SHA384_KDF,
			want:     0x00000007,
		},
		{
			name:     "CKD_SHA512_KDF",
			constant: CKD_SHA512_KDF,
			want:     0x00000008,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint32(tt.constant) != tt.want {
				t.Errorf("%s = 0x%08X, want 0x%08X", tt.name, uint32(tt.constant), tt.want)
			}
		})
	}
}

// TestListMechanismsByCategory_Empty tests edge case with potentially empty categories.
func TestListMechanismsByCategory_Empty(t *testing.T) {
	// Test that the function doesn't crash with any category value
	// Note: ListMechanismsByCategory returns nil for empty results, which is valid Go
	for i := uint8(0); i < 20; i++ {
		cat := MechanismCategory(i)
		// Should not panic for any category value
		_ = ListMechanismsByCategory(cat)
	}

	// Verify known categories return non-empty results
	validCategories := []MechanismCategory{
		CategoryDigest,
		CategorySign,
		CategoryEncrypt,
		CategoryKeyGen,
		CategoryKeyPairGen,
	}
	for _, cat := range validCategories {
		mechanisms := ListMechanismsByCategory(cat)
		if len(mechanisms) == 0 {
			t.Errorf("ListMechanismsByCategory(%v) returned empty for known category", cat)
		}
	}
}

// TestMechanismName_Consistency tests that GetMechanismName and String are consistent.
func TestMechanismName_Consistency(t *testing.T) {
	mechanisms := ListSupportedMechanisms()
	for _, mech := range mechanisms {
		name := GetMechanismName(mech)
		str := mech.String()
		if name != str {
			t.Errorf("GetMechanismName(%v) = %s, String() = %s", mech, name, str)
		}
	}
}

// TestUnknownMechanismName tests unknown mechanism name formatting.
func TestUnknownMechanismName(t *testing.T) {
	unknown := MechanismType(0xDEADBEEF)
	name := GetMechanismName(unknown)
	if !strings.HasPrefix(name, "CKM_UNKNOWN(") {
		t.Errorf("expected CKM_UNKNOWN prefix, got %s", name)
	}
	if !strings.Contains(name, "DEADBEEF") {
		t.Errorf("expected hex value in name, got %s", name)
	}
}

// TestMechanismDescriptor_Flags tests that descriptor flags match capability functions.
func TestMechanismDescriptor_Flags(t *testing.T) {
	mechanisms := ListSupportedMechanisms()
	for _, mech := range mechanisms {
		desc := GetMechanismDescriptor(mech)
		if desc == nil {
			continue
		}

		// Verify flag consistency
		if CanSign(mech) != (desc.Flags&CKF_SIGN != 0) {
			t.Errorf("CanSign inconsistent for %v", mech)
		}
		if CanVerify(mech) != (desc.Flags&CKF_VERIFY != 0) {
			t.Errorf("CanVerify inconsistent for %v", mech)
		}
		if CanEncrypt(mech) != (desc.Flags&CKF_ENCRYPT != 0) {
			t.Errorf("CanEncrypt inconsistent for %v", mech)
		}
		if CanDecrypt(mech) != (desc.Flags&CKF_DECRYPT != 0) {
			t.Errorf("CanDecrypt inconsistent for %v", mech)
		}
		if CanWrap(mech) != (desc.Flags&CKF_WRAP != 0) {
			t.Errorf("CanWrap inconsistent for %v", mech)
		}
		if CanUnwrap(mech) != (desc.Flags&CKF_UNWRAP != 0) {
			t.Errorf("CanUnwrap inconsistent for %v", mech)
		}
		if CanDerive(mech) != (desc.Flags&CKF_DERIVE != 0) {
			t.Errorf("CanDerive inconsistent for %v", mech)
		}
		if CanDigest(mech) != (desc.Flags&CKF_DIGEST != 0) {
			t.Errorf("CanDigest inconsistent for %v", mech)
		}
		if CanGenerateKey(mech) != (desc.Flags&CKF_GENERATE != 0) {
			t.Errorf("CanGenerateKey inconsistent for %v", mech)
		}
		if CanGenerateKeyPair(mech) != (desc.Flags&CKF_GENERATE_KEY_PAIR != 0) {
			t.Errorf("CanGenerateKeyPair inconsistent for %v", mech)
		}
	}
}

// TestMechanismInfo_Consistency tests MechanismInfo is consistent with descriptors.
func TestMechanismInfo_Consistency(t *testing.T) {
	// The descriptor carries the default-regime range; FIPS mode narrows the
	// advertised RSA ceiling on purpose, which
	// TestRSAModulusCeilingNarrowsUnderFIPS covers.
	withFIPSMode(t, false)

	mechanisms := ListSupportedMechanisms()
	for _, mech := range mechanisms {
		info, err := GetMechanismInfo(mech)
		if err != nil {
			t.Errorf("GetMechanismInfo(%v) error: %v", mech, err)
			continue
		}
		desc := GetMechanismDescriptor(mech)
		if desc == nil {
			t.Errorf("GetMechanismDescriptor(%v) returned nil but GetMechanismInfo succeeded", mech)
			continue
		}
		if info.MinKeySize != desc.MinKeySize {
			t.Errorf("MinKeySize mismatch for %v: info=%d, desc=%d", mech, info.MinKeySize, desc.MinKeySize)
		}
		if info.MaxKeySize != desc.MaxKeySize {
			t.Errorf("MaxKeySize mismatch for %v: info=%d, desc=%d", mech, info.MaxKeySize, desc.MaxKeySize)
		}
		if info.Flags != desc.Flags {
			t.Errorf("Flags mismatch for %v: info=%v, desc=%v", mech, info.Flags, desc.Flags)
		}
	}
}

// TestMechanismKeySizeUnits asserts the PKCS#11 v3.2-mandated unit (bits vs
// bytes) for a representative mechanism from each family in the registry.
//
// CK_MECHANISM_INFO.ulMinKeySize/ulMaxKeySize are mechanism-dependent: some
// families report bits, others bytes, and the spec states which per
// mechanism (see MechanismInfo's doc comment for the full citation list).
// This test exists to catch exactly the defect that previously shipped:
// CKM_AES_KEY_GEN reported MinKeySize/MaxKeySize as 128/256 (AES-128 and
// AES-256's BIT lengths, per PKCS#11 v3.2 §6.1's own convention for RSA)
// instead of 16/32 (their BYTE lengths, which is what §6.10.3 actually
// mandates for AES) -- a caller reading ulMinKeySize=128 for an AES
// mechanism would conclude the token's minimum key size was 1024 bits.
func TestMechanismKeySizeUnits(t *testing.T) {
	tests := []struct {
		name    string
		mech    MechanismType
		wantMin uint32
		wantMax uint32
		unit    string
	}{
		{
			name:    "RSA key pair gen reports modulus size in bits (PKCS#11 v3.2 §6.1.2)",
			mech:    CKM_RSA_PKCS_KEY_PAIR_GEN,
			wantMin: rsaModulusBitsMin,
			wantMax: rsaModulusBitsMax,
			unit:    "bits",
		},
		{
			name:    "EC key pair gen reports field size in bits (PKCS#11 v3.2 §6.3.1)",
			mech:    CKM_EC_KEY_PAIR_GEN,
			wantMin: 256,
			wantMax: 521,
			unit:    "bits",
		},
		{
			name:    "Edwards curve key pair gen reports field size in bits (PKCS#11 v3.2 §6.3.9)",
			mech:    CKM_EC_EDWARDS_KEY_PAIR_GEN,
			wantMin: 255,
			wantMax: 448,
			unit:    "bits",
		},
		{
			name:    "AES key gen reports key size in bytes, not bits (PKCS#11 v3.2 §6.10.3)",
			mech:    CKM_AES_KEY_GEN,
			wantMin: 16,
			wantMax: 32,
			unit:    "bytes",
		},
		{
			name:    "AES CBC reports key size in bytes, not bits (PKCS#11 v3.2 §6.10.5)",
			mech:    CKM_AES_CBC,
			wantMin: 16,
			wantMax: 32,
			unit:    "bytes",
		},
		{
			name:    "AES GCM reports key size in bytes, not bits (PKCS#11 v3.2 §6.13.7)",
			mech:    CKM_AES_GCM,
			wantMin: 16,
			wantMax: 32,
			unit:    "bytes",
		},
		{
			name:    "AES key wrap reports key size in bytes, consistent with the AES family",
			mech:    CKM_AES_KEY_WRAP,
			wantMin: 16,
			wantMax: 32,
			unit:    "bytes",
		},
		{
			name:    "SHA-256 HMAC reports key size in bytes (PKCS#11 v3.2 §6.22)",
			mech:    CKM_SHA256_HMAC,
			wantMin: 1,
			wantMax: 0,
			unit:    "bytes",
		},
		{
			name:    "Generic secret key gen reports key size in bits (PKCS#11 v3.2 §6.9)",
			mech:    CKM_GENERIC_SECRET_KEY_GEN,
			wantMin: 1,
			wantMax: 0,
			unit:    "bits",
		},
		{
			name:    "Pure digest mechanisms have no key size at all (PKCS#11 v3.2 §6.1 Table 10)",
			mech:    CKM_SHA256,
			wantMin: 0,
			wantMax: 0,
			unit:    "n/a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := GetMechanismDescriptor(tt.mech)
			if desc == nil {
				t.Fatalf("GetMechanismDescriptor(%v) returned nil", tt.mech)
			}
			if desc.MinKeySize != tt.wantMin {
				t.Errorf("%v MinKeySize = %d, want %d (%s)", tt.mech, desc.MinKeySize, tt.wantMin, tt.unit)
			}
			if desc.MaxKeySize != tt.wantMax {
				t.Errorf("%v MaxKeySize = %d, want %d (%s)", tt.mech, desc.MaxKeySize, tt.wantMax, tt.unit)
			}
		})
	}
}

// TestMechanismAESKeySizeRegression is a targeted regression test for the
// AES key-size unit defect described in TestMechanismKeySizeUnits above:
// CKM_AES_KEY_GEN previously reported MinKeySize/MaxKeySize as 128/256 (the
// BIT lengths of AES-128 and AES-256) instead of 16/32 (their BYTE
// lengths). Multiplying the byte-denominated field by 8 must reproduce the
// real AES key sizes in bits; multiplying the old, incorrectly
// bit-denominated field by 8 would have produced 1024/2048 instead.
func TestMechanismAESKeySizeRegression(t *testing.T) {
	info, err := GetMechanismInfo(CKM_AES_KEY_GEN)
	if err != nil {
		t.Fatalf("GetMechanismInfo(CKM_AES_KEY_GEN) error: %v", err)
	}

	minBits := info.MinKeySize * 8
	maxBits := info.MaxKeySize * 8

	if minBits != 128 {
		t.Errorf("CKM_AES_KEY_GEN MinKeySize*8 = %d bits, want 128 bits (AES-128); "+
			"MinKeySize=%d suggests the field is reporting bits instead of bytes",
			minBits, info.MinKeySize)
	}
	if maxBits != 256 {
		t.Errorf("CKM_AES_KEY_GEN MaxKeySize*8 = %d bits, want 256 bits (AES-256); "+
			"MaxKeySize=%d suggests the field is reporting bits instead of bytes",
			maxBits, info.MaxKeySize)
	}
}

// TestAdvertisedMechanismsAreDeliberate pins the exact set of mechanisms the
// token offers through C_GetMechanismList.
//
// Advertising a mechanism is a promise an application may rely on, so the set
// must change only when someone means it to. This test exists because the
// advertised set used to live in a second hardcoded table maintained by hand
// alongside mechanismRegistry: the two drifted apart on the key-size range and
// flags of nearly every RSA and EC mechanism, and the registry accumulated
// dozens of implemented mechanisms the table never listed, so applications
// could not discover them. defaultMechanismInfo now projects from the registry,
// which makes disagreement unrepresentable — but nothing stops a stray
// Advertised: true from silently widening the promise, and this catches that.
func TestAdvertisedMechanismsAreDeliberate(t *testing.T) {
	// FIPS mode withholds SHA-1 signature generation and HKDF over an
	// arbitrary base key; TestFIPSMode gives the reasons.
	outsideFIPS := !fips140.Enabled()

	want := map[MechanismType]bool{
		CKM_RSA_PKCS_KEY_PAIR_GEN: true,
		CKM_RSA_PKCS:              true,
		CKM_RSA_PKCS_OAEP:         true,
		CKM_RSA_PKCS_PSS:          true,
		CKM_SHA1_RSA_PKCS:         outsideFIPS,
		CKM_SHA256_RSA_PKCS:       true,
		CKM_SHA384_RSA_PKCS:       true,
		CKM_SHA512_RSA_PKCS:       true,
		CKM_SHA256_RSA_PKCS_PSS:   true,
		CKM_SHA384_RSA_PKCS_PSS:   true,
		CKM_SHA512_RSA_PKCS_PSS:   true,

		CKM_EC_KEY_PAIR_GEN: true,
		CKM_ECDSA:           true,
		// CKM_ECDSA_SHA1 and CKM_ECDSA_SHA224 were registered but unadvertised.
		// Both sign and verify end to end against a P-256 key, and C_Verify
		// rejects an altered message, so they are promises the module keeps.
		CKM_ECDSA_SHA1:              outsideFIPS,
		CKM_ECDSA_SHA224:            true,
		CKM_ECDSA_SHA256:            true,
		CKM_ECDSA_SHA384:            true,
		CKM_ECDSA_SHA512:            true,
		CKM_ECDH1_DERIVE:            true,
		CKM_ECDH1_COFACTOR_DERIVE:   true,
		CKM_EC_EDWARDS_KEY_PAIR_GEN: true,
		CKM_EDDSA:                   true,

		CKM_AES_KEY_GEN:  true,
		CKM_AES_ECB:      true,
		CKM_AES_CBC:      true,
		CKM_AES_CBC_PAD:  true,
		CKM_AES_GCM:      true,
		CKM_AES_KEY_WRAP: true,
		// CKM_AES_KEY_WRAP_KWP is the current RFC 5649 identifier and
		// CKM_AES_KEY_WRAP_PAD its deprecated alias (v3.2 §6.10). KWP was
		// declared and name-mapped but never registered, so the current
		// identifier was the one that failed; both are advertised and both
		// route to the same construction.
		CKM_AES_KEY_WRAP_KWP: true,
		CKM_AES_KEY_WRAP_PAD: true,

		// The digest mechanisms. CKM_SHA224 was registered but unadvertised;
		// CKM_SHA512_224 and CKM_SHA512_256 had working hashers and no registry
		// entry at all. C_Digest never leaves this process, so for this family
		// "implemented" and "works end to end" are the same claim.
		CKM_SHA_1:      true,
		CKM_SHA224:     true,
		CKM_SHA256:     true,
		CKM_SHA384:     true,
		CKM_SHA512:     true,
		CKM_SHA512_224: true,
		CKM_SHA512_256: true,

		// The key-derivation functions. They were withheld while C_DeriveKey
		// substituted the base key's identifier string for its input keying
		// material; the derivation now runs over the base key's own material,
		// either bytes the application supplied through C_CreateObject or, for
		// a backend-held key, inside the backend that holds it.
		CKM_HKDF_DERIVE:                   outsideFIPS,
		CKM_HKDF_DATA:                     outsideFIPS,
		CKM_SP800_108_COUNTER_KDF:         true,
		CKM_SP800_108_FEEDBACK_KDF:        true,
		CKM_SP800_108_DOUBLE_PIPELINE_KDF: true,

		// The post-quantum mechanisms, proven end to end before being
		// advertised. Key generation reaches the real algorithm through BOTH
		// addressing forms -- the v3.2 standard mechanism with
		// CKA_PARAMETER_SET and the per-level vendor mechanism -- and the
		// generated keys are checked against a reference implementation, not
		// against the module's own inverse:
		// TestGenerateKeyPairMLKEMRoundTripsUnderTheReferenceImplementation
		// encapsulates with the reference and decapsulates on the token, and
		// TestGenerateKeyPairMLDSAProducesARealSigningKey signs on the token
		// and verifies with the reference.
		//
		// They were registered-but-unadvertised while C_GenerateKeyPair failed
		// for every parameter set, which left them undiscoverable through
		// C_GetMechanismList yet reachable by raw constant -- the worst of both.
		CKM_ML_KEM_KEY_PAIR_GEN: true,
		CKM_ML_KEM:              true,
		CKM_ML_DSA_KEY_PAIR_GEN: true,
		CKM_ML_DSA:              true,
	}

	got := defaultMechanismInfo()

	for mechType, advertised := range want {
		_, ok := got[mechType]
		if advertised && !ok {
			t.Errorf("%v is expected to be advertised but is not; applications can no "+
				"longer discover it through C_GetMechanismList", mechType)
		}
		if !advertised && ok {
			t.Errorf("%v is advertised in FIPS mode, which withholds it", mechType)
		}
	}
	for mechType := range got {
		if _, listed := want[mechType]; !listed {
			t.Errorf("%v is advertised but is not in the deliberate set. Advertising a "+
				"mechanism promises applications they may rely on it -- add it to this "+
				"test only once its implementation is proven end to end", mechType)
		}
	}
}

// TestAdvertisedInfoMatchesTheRegistry proves the advertised description of a
// mechanism is the same one the crypto layer validates against.
//
// These were two independent tables that disagreed. An application would read
// one set of key-size limits and capability flags from C_GetMechanismInfo while
// the module enforced another, so a request the token said it supported could
// still be refused, and vice versa.
func TestAdvertisedInfoMatchesTheRegistry(t *testing.T) {
	for mechType, info := range defaultMechanismInfo() {
		desc := GetMechanismDescriptor(mechType)
		if desc == nil {
			t.Errorf("%v is advertised but has no registry descriptor, so the crypto "+
				"layer has no definition to validate it against", mechType)
			continue
		}
		// The comparison is against the effective range rather than the raw
		// registry fields because the FIPS ceiling narrows one and not the
		// other; effectiveKeySizeRange is the single answer both the advertised
		// info and IsValidKeySize are built from.
		wantMin, wantMax := effectiveKeySizeRange(desc)
		if info.MinKeySize != wantMin || info.MaxKeySize != wantMax {
			t.Errorf("%v advertises key sizes %d-%d but the registry enforces %d-%d",
				mechType, info.MinKeySize, info.MaxKeySize, wantMin, wantMax)
		}
		if info.Flags != desc.Flags {
			t.Errorf("%v advertises flags 0x%x but the registry defines 0x%x",
				mechType, info.Flags, desc.Flags)
		}
	}
}

// TestRSAKeySizeFloorIsStandardsCompliant asserts no RSA mechanism accepts a
// modulus below 2048 bits.
//
// PKCS#11 v3.2 §6.1.21 permits only 1024, 2048 or 3072 bits for CKM_RSA_PKCS in
// FIPS mode, so 512 is not a permitted modulus length at all, and NIST
// SP 800-131A has disallowed RSA below 2048 since 2014. This module targets
// FedRAMP, PCI and HIPAA deployments, so 2048 is the floor. The registry
// previously declared 512, which meant the module would have generated and
// signed with a 512-bit RSA key on request.
func TestRSAKeySizeFloorIsStandardsCompliant(t *testing.T) {
	const floor = 2048

	for mechType, desc := range mechanismRegistry {
		if desc.MinKeySize == 0 {
			continue // no meaningful key size for this mechanism
		}
		name := desc.Name
		if !strings.Contains(name, "RSA") {
			continue
		}
		if desc.MinKeySize < floor {
			t.Errorf("%s (%v) accepts a %d-bit RSA modulus; the floor is %d bits",
				name, mechType, desc.MinKeySize, floor)
		}
	}
}

// TestFIPSMode covers the algorithm restriction the module applies when FIPS
// mode is active.
//
// The two claims are separate and both matter. PKCS#11 conformance says what a
// Cryptoki module must implement; FIPS 140-3 says which of it a validated
// deployment may use. So the module ships the full OASIS surface by default —
// including SHA-1 signing, which the spec defines and applications still need
// for legacy interop — and narrows to approved algorithms only when a
// deployment asks for FIPS.
//
// The restriction is applied at the mechanism lookup every operation's *Init
// goes through, so what the module advertises and what it will actually perform
// cannot drift apart: an offered mechanism works, an unoffered one is refused,
// and there is no third state.
func TestFIPSMode(t *testing.T) {
	// SHA-1 signature generation is disallowed by NIST SP 800-131A. SHA-1 as a
	// plain digest stays approved (FIPS 180-4), so only the signing mechanism
	// is withheld.
	const nonApproved = CKM_SHA1_RSA_PKCS

	t.Run("the full OASIS surface is available by default", func(t *testing.T) {
		withFIPSMode(t, false)

		desc := GetMechanismDescriptor(nonApproved)
		require.NotNil(t, desc, "a spec-defined mechanism must be available outside FIPS mode")
		assert.False(t, desc.FIPSApproved)

		_, advertised := defaultMechanismInfo()[nonApproved]
		assert.True(t, advertised, "C_GetMechanismList must offer it outside FIPS mode")
	})

	t.Run("FIPS mode withholds a non-approved mechanism", func(t *testing.T) {
		withFIPSMode(t, true)

		assert.Nil(t, GetMechanismDescriptor(nonApproved),
			"every *Init resolves through this lookup, so a nil descriptor is what "+
				"turns into CKR_MECHANISM_INVALID for a non-approved mechanism")

		_, advertised := defaultMechanismInfo()[nonApproved]
		assert.False(t, advertised,
			"a mechanism the module will refuse must not be advertised")
	})

	t.Run("FIPS mode keeps the approved mechanisms", func(t *testing.T) {
		withFIPSMode(t, true)

		for _, mechType := range []MechanismType{
			CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_SHA256_RSA_PKCS, CKM_SHA256_RSA_PKCS_PSS,
			CKM_EC_KEY_PAIR_GEN, CKM_ECDSA_SHA256, CKM_ECDH1_DERIVE,
			CKM_AES_KEY_GEN, CKM_AES_GCM, CKM_AES_KEY_WRAP,
			CKM_SHA256, CKM_SHA384, CKM_SHA512,
			CKM_EDDSA, // FIPS 186-5 approves EdDSA
		} {
			assert.NotNil(t, GetMechanismDescriptor(mechType),
				"%v is FIPS-approved and must remain usable", mechType)
			_, advertised := defaultMechanismInfo()[mechType]
			assert.True(t, advertised, "%v must remain advertised in FIPS mode", mechType)
		}
	})

	t.Run("every advertised mechanism declares its FIPS status deliberately", func(t *testing.T) {
		// The flag defaults to false, so a mechanism added without thinking
		// about it silently disappears in FIPS mode. This pins the one
		// mechanism that is meant to.
		withFIPSMode(t, false)

		var withheld []MechanismType
		for mechType := range defaultMechanismInfo() {
			if !mechanismRegistry[mechType].FIPSApproved {
				withheld = append(withheld, mechType)
			}
		}
		// ElementsMatch, not Equal: the set is built by ranging a map, so any
		// expectation with more than one member would be order-dependent and
		// flaky.
		//
		// The two HKDF mechanisms join SHA-1 signature generation here on
		// purpose. SP 800-56C Rev. 2 approves extract-then-expand for deriving
		// from a shared secret an approved key-establishment scheme produced;
		// C_DeriveKey applies it to an arbitrary base key, which that document
		// does not cover. The SP 800-108 modes are approved and are marked so.
		//
		// CKM_ECDSA_SHA1 joins CKM_SHA1_RSA_PKCS for the same reason the latter
		// is here: SP 800-131A Rev. 2 disallows SHA-1 for signature generation,
		// whichever signature algorithm consumes the digest.
		assert.ElementsMatch(t,
			[]MechanismType{nonApproved, CKM_ECDSA_SHA1, CKM_HKDF_DERIVE, CKM_HKDF_DATA},
			withheld,
			"only SHA-1 signature generation and the two HKDF derivations are expected to be "+
				"non-approved; a new entry here means a mechanism will vanish in FIPS mode")
	})
}

// TestRSAModulusCeilingIsASizeTheModuleGenerates holds ulMaxKeySize to the only
// thing it can honestly mean.
//
// PKCS#11 v3.2 §6.1.4 defines the RSA family's ulMinKeySize/ulMaxKeySize as
// "the supported range of RSA modulus sizes, in bits", and §5.5 makes that
// range how an application chooses what to ask for. Every value inside it must
// therefore be a modulus the token will produce. The registry advertised 16384,
// and generating a key at that advertised maximum exhausted memory and killed
// the daemon serving the token: an authenticated caller could take the service
// down with a CKA_MODULUS_BITS value the module itself had called valid.
//
// The ceiling is asserted, never generated. Producing a 16384-bit modulus is
// precisely the operation that caused the outage, and it would prove nothing
// that the advertised number does not already state.
func TestRSAModulusCeilingIsASizeTheModuleGenerates(t *testing.T) {
	withFIPSMode(t, false)

	if rsaModulusBitsMax > 4096 {
		t.Fatalf("the advertised RSA ceiling is %d bits; nothing in this stack generates a "+
			"modulus above 4096 (types.RSAKeySize4096), so a larger ceiling promises a size "+
			"the token cannot produce", rsaModulusBitsMax)
	}
	if rsaModulusBitsMax <= rsaModulusBitsMin {
		t.Fatalf("the RSA ceiling %d is not above the floor %d, so the advertised range is empty",
			rsaModulusBitsMax, rsaModulusBitsMin)
	}

	for mechType, desc := range mechanismRegistry {
		if !strings.Contains(desc.Name, "RSA") || desc.MaxKeySize == 0 {
			continue
		}
		if desc.MaxKeySize != rsaModulusBitsMax {
			t.Errorf("%s (%v) advertises a %d-bit ceiling; every RSA mechanism must advertise "+
				"the same %d-bit ceiling, or an application that picks a size from one "+
				"mechanism's range is refused by another", desc.Name, mechType,
				desc.MaxKeySize, rsaModulusBitsMax)
		}
		if desc.FIPSMaxKeySize != rsaModulusBitsFIPSMax {
			t.Errorf("%s (%v) declares FIPSMaxKeySize %d; PKCS#11 v3.2 §6.1.21 permits only "+
				"1024, 2048 or 3072 bits in FIPS mode, so every RSA mechanism must declare "+
				"a %d-bit FIPS ceiling", desc.Name, mechType, desc.FIPSMaxKeySize,
				rsaModulusBitsFIPSMax)
		}
	}

	if !IsValidKeySize(CKM_RSA_PKCS_KEY_PAIR_GEN, rsaModulusBitsMax) {
		t.Errorf("the module refuses its own advertised ceiling of %d bits", rsaModulusBitsMax)
	}
	if IsValidKeySize(CKM_RSA_PKCS_KEY_PAIR_GEN, rsaModulusBitsMax+1) {
		t.Errorf("%d bits is accepted although the advertised ceiling is %d; an unbounded "+
			"CKA_MODULUS_BITS is what let a caller exhaust the daemon",
			rsaModulusBitsMax+1, rsaModulusBitsMax)
	}
	if IsValidKeySize(CKM_RSA_PKCS_KEY_PAIR_GEN, 16384) {
		t.Error("16384 bits is still accepted; that is the size whose generation killed the daemon")
	}
}

// TestRSAModulusCeilingNarrowsUnderFIPS pins the §6.1.21 ceiling to both halves
// of the contract: what the module advertises and what it will accept.
//
// PKCS#11 v3.2 §6.1.21 (FIPS 186-4): "When CKM_RSA_PKCS is operated in FIPS
// mode, the length of the modulus SHALL only be 1024, 2048, or 3072 bits."
// 4096 was accepted under FIPS while C_GetMechanismInfo reported a maximum far
// above it, so nothing in the module contradicted a caller who asked for a size
// FIPS forbids.
func TestRSAModulusCeilingNarrowsUnderFIPS(t *testing.T) {
	withFIPSMode(t, true)

	info, err := GetMechanismInfo(CKM_RSA_PKCS_KEY_PAIR_GEN)
	if err != nil {
		t.Fatalf("GetMechanismInfo(CKM_RSA_PKCS_KEY_PAIR_GEN): %v", err)
	}
	if info.MaxKeySize != rsaModulusBitsFIPSMax {
		t.Errorf("C_GetMechanismInfo advertises ulMaxKeySize=%d under FIPS, want %d; "+
			"PKCS#11 v3.2 §6.1.21 permits only 1024, 2048 or 3072 bits",
			info.MaxKeySize, rsaModulusBitsFIPSMax)
	}
	if info.MinKeySize != rsaModulusBitsMin {
		t.Errorf("the FIPS floor moved to %d; narrowing the ceiling must not disturb the floor",
			info.MinKeySize)
	}

	advertised, ok := defaultMechanismInfo()[CKM_RSA_PKCS_KEY_PAIR_GEN]
	if !ok {
		t.Fatal("CKM_RSA_PKCS_KEY_PAIR_GEN vanished from C_GetMechanismList under FIPS")
	}
	if advertised.MaxKeySize != info.MaxKeySize {
		t.Errorf("C_GetMechanismList describes a %d-bit ceiling while C_GetMechanismInfo "+
			"reports %d; the two halves of mechanism discovery must agree",
			advertised.MaxKeySize, info.MaxKeySize)
	}

	if !IsValidKeySize(CKM_RSA_PKCS_KEY_PAIR_GEN, rsaModulusBitsFIPSMax) {
		t.Errorf("%d bits is refused under FIPS although §6.1.21 permits it", rsaModulusBitsFIPSMax)
	}
	if IsValidKeySize(CKM_RSA_PKCS_KEY_PAIR_GEN, 4096) {
		t.Error("a 4096-bit modulus is accepted under FIPS; PKCS#11 v3.2 §6.1.21 permits " +
			"only 1024, 2048 or 3072 bits")
	}
}

// TestRSAModulusFloorNeverInvertsBetweenRegimes pins the one size where the
// module's own floor and §6.1.21 disagree.
//
// §6.1.21 permits a 1024-bit modulus in FIPS mode; this module refuses it in
// both regimes because NIST SP 800-131A disallowed RSA below 2048 bits in 2014
// and FIPS 140-3 no longer approves 1024-bit RSA for signature generation. A
// module may be stricter than §6.1.21. What it must never be is stricter
// outside FIPS than inside: a size available *only* under FIPS would mean
// turning the mode on weakened the module.
func TestRSAModulusFloorNeverInvertsBetweenRegimes(t *testing.T) {
	const belowFloor = 1024

	t.Run("refused outside FIPS", func(t *testing.T) {
		withFIPSMode(t, false)
		if IsValidKeySize(CKM_RSA_PKCS_KEY_PAIR_GEN, belowFloor) {
			t.Errorf("a %d-bit modulus is accepted; the floor is %d bits", belowFloor, rsaModulusBitsMin)
		}
	})

	t.Run("refused under FIPS", func(t *testing.T) {
		withFIPSMode(t, true)
		if IsValidKeySize(CKM_RSA_PKCS_KEY_PAIR_GEN, belowFloor) {
			t.Errorf("a %d-bit modulus is accepted under FIPS but refused outside it; FIPS "+
				"mode must only ever narrow what the module accepts", belowFloor)
		}
	})

	t.Run("FIPS never widens the range", func(t *testing.T) {
		for mechType, desc := range mechanismRegistry {
			if desc.FIPSMaxKeySize == 0 {
				continue
			}
			if desc.FIPSMaxKeySize > desc.MaxKeySize {
				t.Errorf("%s (%v) allows %d in FIPS mode but only %d outside it",
					desc.Name, mechType, desc.FIPSMaxKeySize, desc.MaxKeySize)
			}
		}
	})
}

// TestIsValidKeySizeHonoursTheNoMaximumSentinel covers the registry's
// MaxKeySize: 0 convention, used by the generic-secret and KDF families where
// PKCS#11 v3.2 §6.9 and §6.62.3 place no upper bound on the key.
//
// Comparing a key size against that sentinel literally made the predicate false
// for every size those mechanisms accept, so the one check meant to keep an
// oversized RSA modulus out would have rejected every legal key had a caller
// consulted it.
//
// CKM_SHA256_HMAC used to stand in for the family here. It has been removed
// from the registry: it carried CKF_SIGN and CKF_VERIFY while C_Sign with it
// fails with CKR_FUNCTION_FAILED, since the module has no symmetric-MAC signing
// path. The constant survives as a KDF PRF selector, which
// mechanismToHashFromPRF resolves by switch rather than through this registry.
func TestIsValidKeySizeHonoursTheNoMaximumSentinel(t *testing.T) {
	withFIPSMode(t, false)

	for _, mechType := range []MechanismType{CKM_GENERIC_SECRET_KEY_GEN} {
		desc := GetMechanismDescriptor(mechType)
		if desc == nil {
			t.Fatalf("%v is missing from the registry", mechType)
		}
		if desc.MaxKeySize != 0 {
			t.Fatalf("%v no longer uses the no-maximum sentinel; this test is testing nothing", mechType)
		}

		for _, size := range []uint32{desc.MinKeySize, 32, 1 << 20} {
			if !IsValidKeySize(mechType, size) {
				t.Errorf("IsValidKeySize(%v, %d) = false; MaxKeySize 0 means no enforced "+
					"maximum, not a maximum of zero", mechType, size)
			}
		}
		if desc.MinKeySize > 0 && IsValidKeySize(mechType, desc.MinKeySize-1) {
			t.Errorf("IsValidKeySize(%v, %d) = true, below the declared minimum of %d; the "+
				"absent maximum must not disable the minimum", mechType,
				desc.MinKeySize-1, desc.MinKeySize)
		}
	}
}

// TestIsValidKeySizeRejectsBadInput covers the inputs that carry no valid
// answer: a mechanism the registry does not define, and one FIPS mode has
// withheld. Both must be false rather than defaulting to permissive, because a
// caller uses this to decide whether to start an operation.
func TestIsValidKeySizeRejectsBadInput(t *testing.T) {
	t.Run("unknown mechanism", func(t *testing.T) {
		withFIPSMode(t, false)
		if IsValidKeySize(MechanismType(0xFFFFFFFF), 2048) {
			t.Error("an unregistered mechanism reported a valid key size")
		}
	})

	t.Run("mechanism withheld by FIPS", func(t *testing.T) {
		withFIPSMode(t, true)
		if IsValidKeySize(CKM_SHA1_RSA_PKCS, 2048) {
			t.Error("CKM_SHA1_RSA_PKCS reported a valid key size under FIPS although the " +
				"mechanism itself is withheld; every size is invalid for a mechanism the " +
				"module will refuse")
		}
	})
}

// TestECDH1CofactorDeriveIsDiscoverable covers the mechanism that worked but
// could not be found.
//
// C_DeriveKey has always performed CKM_ECDH1_COFACTOR_DERIVE — module.DeriveKey
// routes it and CKM_ECDH1_DERIVE to the same key-agreement path — but
// C_GetMechanismList did not offer it, so p11-kit, OpenSSL's pkcs11-provider
// and every other caller that enumerates before it calls could never reach it.
//
// Its description must also be true, not merely present: PKCS#11 v3.2 §6.3.18
// gives the mechanism CK_ECDH1_DERIVE_PARAMS and the same EC field-size range
// as §6.3.17, and an application reads CKF_DERIVE to decide it may be used for
// derivation at all.
func TestECDH1CofactorDeriveIsDiscoverable(t *testing.T) {
	withFIPSMode(t, false)

	info, err := GetMechanismInfo(CKM_ECDH1_COFACTOR_DERIVE)
	if err != nil {
		t.Fatalf("GetMechanismInfo(CKM_ECDH1_COFACTOR_DERIVE): %v", err)
	}
	if _, advertised := defaultMechanismInfo()[CKM_ECDH1_COFACTOR_DERIVE]; !advertised {
		t.Fatal("CKM_ECDH1_COFACTOR_DERIVE is absent from C_GetMechanismList, so an " +
			"application that enumerates mechanisms cannot discover a derivation the " +
			"module performs")
	}

	if info.Flags&CKF_DERIVE == 0 {
		t.Error("CKM_ECDH1_COFACTOR_DERIVE is advertised without CKF_DERIVE, so no " +
			"application would select it for the one operation it supports")
	}

	plain, err := GetMechanismInfo(CKM_ECDH1_DERIVE)
	if err != nil {
		t.Fatalf("GetMechanismInfo(CKM_ECDH1_DERIVE): %v", err)
	}
	if info.MinKeySize != plain.MinKeySize || info.MaxKeySize != plain.MaxKeySize {
		t.Errorf("cofactor derive advertises the field-size range %d-%d but plain ECDH1 "+
			"advertises %d-%d; both run over the same curves on the same code path",
			info.MinKeySize, info.MaxKeySize, plain.MinKeySize, plain.MaxKeySize)
	}

	t.Run("stays available under FIPS", func(t *testing.T) {
		withFIPSMode(t, true)
		if _, advertised := defaultMechanismInfo()[CKM_ECDH1_COFACTOR_DERIVE]; !advertised {
			t.Error("cofactor ECDH is withheld under FIPS although NIST SP 800-56A approves " +
				"it and the non-cofactor form remains advertised")
		}
	})
}

// TestKDFsAreAdvertisedAndDescribedTruthfully replaces the guard that used to
// pin these mechanisms as withheld.
//
// They were withheld because module.DeriveKey substituted the base key's
// identifier string for its input keying material whenever CKA_VALUE was
// absent — which was every key C_GenerateKey produced — so the KDF ran over a
// label-plus-timestamp string and anyone who knew the label could reproduce
// the derived key. That fallback is gone: a base key that resolves to neither
// CKA_VALUE nor a backend key identifier is now refused, and a backend-held
// key is derived from inside the backend.
//
// C_GetMechanismList must therefore offer them (v3.2 §5.5), and
// C_GetMechanismInfo must describe them the way the module actually behaves:
// derivation-capable, with no key-size bound, because neither RFC 5869 nor
// SP 800-108r1 bounds the length of the key they derive from.
func TestKDFsAreAdvertisedAndDescribedTruthfully(t *testing.T) {
	withFIPSMode(t, false)

	advertised := defaultMechanismInfo()
	for _, mechType := range []MechanismType{
		CKM_HKDF_DERIVE, CKM_HKDF_DATA,
		CKM_SP800_108_COUNTER_KDF, CKM_SP800_108_FEEDBACK_KDF,
		CKM_SP800_108_DOUBLE_PIPELINE_KDF,
	} {
		info, ok := advertised[mechType]
		if !ok {
			t.Errorf("%v is not offered by C_GetMechanismList; C_DeriveKey performs it, and an "+
				"application that enumerates mechanisms before using them can never reach it", mechType)
			continue
		}
		if info.Flags&CKF_DERIVE == 0 {
			t.Errorf("%v is advertised without CKF_DERIVE, so C_GetMechanismInfo denies the one "+
				"function C_DeriveKey will actually perform with it", mechType)
		}
		// 0/0 is PKCS#11 v3.2 §6.1 Table 10's "the ulMinKeySize and
		// ulMaxKeySize fields have meaningless values" encoding, which is what
		// IsValidKeySize reads it as. It is the truthful answer here: neither
		// RFC 5869 nor SP 800-108r1 bounds the length of the key derived from,
		// and the module enforces no bound. A non-zero minimum with a zero
		// maximum is this registry's separate "no enforced maximum" sentinel,
		// and it reads to an application — and to the conformance suite — as
		// ulMinKeySize > ulMaxKeySize, which is an impossible range.
		if info.MinKeySize != 0 || info.MaxKeySize != 0 {
			t.Errorf("%v advertises a base-key size range of %d..%d; the module enforces no bound "+
				"on the base key, so anything other than 0..0 is either a promise it does not keep "+
				"or an impossible range",
				mechType, info.MinKeySize, info.MaxKeySize)
		}
		if GetMechanismDescriptor(mechType) == nil {
			t.Errorf("%v is advertised but absent from the registry, so C_DeriveKey would refuse "+
				"the mechanism C_GetMechanismList just offered", mechType)
		}
	}
}

// TestEffectiveKeySizeRange covers the one function that decides which regime's
// key-size ceiling applies, directly rather than through its three callers.
//
// The degenerate rows matter as much as the FIPS row: a mechanism that declares
// no FIPS ceiling, or declares one no narrower than its own, must come back
// unchanged, or turning FIPS on would silently move a limit nobody set.
func TestEffectiveKeySizeRange(t *testing.T) {
	tests := []struct {
		name    string
		desc    MechanismDescriptor
		fips    bool
		wantMin uint32
		wantMax uint32
	}{
		{
			name:    "FIPS ceiling applies in FIPS mode",
			desc:    MechanismDescriptor{MinKeySize: 2048, MaxKeySize: 4096, FIPSMaxKeySize: 3072},
			fips:    true,
			wantMin: 2048,
			wantMax: 3072,
		},
		{
			name:    "FIPS ceiling is ignored outside FIPS mode",
			desc:    MechanismDescriptor{MinKeySize: 2048, MaxKeySize: 4096, FIPSMaxKeySize: 3072},
			fips:    false,
			wantMin: 2048,
			wantMax: 4096,
		},
		{
			name:    "no declared FIPS ceiling leaves the range alone",
			desc:    MechanismDescriptor{MinKeySize: 16, MaxKeySize: 32},
			fips:    true,
			wantMin: 16,
			wantMax: 32,
		},
		{
			name: "a FIPS ceiling above the mechanism's own never widens it",
			desc: MechanismDescriptor{MinKeySize: 16, MaxKeySize: 32, FIPSMaxKeySize: 64},
			fips: true,
			// FIPS may only narrow what the module offers; a wider FIPS
			// ceiling is a data error and must not take effect.
			wantMin: 16,
			wantMax: 32,
		},
		{
			name:    "the no-maximum sentinel survives the clamp",
			desc:    MechanismDescriptor{MinKeySize: 1, MaxKeySize: 0},
			fips:    true,
			wantMin: 1,
			wantMax: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withFIPSMode(t, tt.fips)

			gotMin, gotMax := effectiveKeySizeRange(&tt.desc)
			if gotMin != tt.wantMin || gotMax != tt.wantMax {
				t.Errorf("effectiveKeySizeRange() = %d-%d, want %d-%d",
					gotMin, gotMax, tt.wantMin, tt.wantMax)
			}
		})
	}
}
