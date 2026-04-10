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
			name:     "HKDF derive supported",
			mechType: CKM_HKDF_DERIVE,
			want:     true,
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
			name:       "RSA PKCS",
			mechType:   CKM_RSA_PKCS,
			wantErr:    false,
			wantMinKey: 512,
			wantMaxKey: 16384,
		},
		{
			name:       "AES GCM",
			mechType:   CKM_AES_GCM,
			wantErr:    false,
			wantMinKey: 128,
			wantMaxKey: 256,
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

// TestMechanismRequiresParams tests MechanismRequiresParams function.
func TestMechanismRequiresParams(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     bool
	}{
		{
			name:     "AES GCM requires params",
			mechType: CKM_AES_GCM,
			want:     true,
		},
		{
			name:     "RSA OAEP requires params",
			mechType: CKM_RSA_PKCS_OAEP,
			want:     true,
		},
		{
			name:     "RSA PSS requires params",
			mechType: CKM_RSA_PKCS_PSS,
			want:     true,
		},
		{
			name:     "HKDF derive requires params",
			mechType: CKM_HKDF_DERIVE,
			want:     true,
		},
		{
			name:     "AES ECB no params",
			mechType: CKM_AES_ECB,
			want:     false,
		},
		{
			name:     "SHA256 no params",
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
			got := MechanismRequiresParams(tt.mechType)
			if got != tt.want {
				t.Errorf("MechanismRequiresParams(%v) = %v, want %v", tt.mechType, got, tt.want)
			}
		})
	}
}

// TestGetMechanismParamsType tests GetMechanismParamsType function.
func TestGetMechanismParamsType(t *testing.T) {
	tests := []struct {
		name     string
		mechType MechanismType
		want     string
	}{
		{
			name:     "AES GCM",
			mechType: CKM_AES_GCM,
			want:     "AESGCMParams",
		},
		{
			name:     "RSA OAEP",
			mechType: CKM_RSA_PKCS_OAEP,
			want:     "RSAOAEPParams",
		},
		{
			name:     "RSA PSS",
			mechType: CKM_RSA_PKCS_PSS,
			want:     "RSAPSSParams",
		},
		{
			name:     "HKDF derive",
			mechType: CKM_HKDF_DERIVE,
			want:     "HKDFParams",
		},
		{
			name:     "ECDH derive",
			mechType: CKM_ECDH1_DERIVE,
			want:     "ECDHParams",
		},
		{
			name:     "AES ECB no params",
			mechType: CKM_AES_ECB,
			want:     "",
		},
		{
			name:     "unknown mechanism",
			mechType: MechanismType(0xFFFFFFFF),
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetMechanismParamsType(tt.mechType)
			if got != tt.want {
				t.Errorf("GetMechanismParamsType(%v) = %v, want %v", tt.mechType, got, tt.want)
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
		{
			name:     "HKDF key gen",
			mechType: CKM_HKDF_KEY_GEN,
			want:     true,
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
		{
			name:     "AES GCM cannot wrap",
			mechType: CKM_AES_GCM,
			want:     false,
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
		{
			name:     "AES GCM cannot unwrap",
			mechType: CKM_AES_GCM,
			want:     false,
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
			name:     "HKDF derive",
			mechType: CKM_HKDF_DERIVE,
			want:     true,
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
			name:     "SHA3-256",
			mechType: CKM_SHA3_256,
			want:     true,
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
			name:     "AES 128 valid",
			mechType: CKM_AES_KEY_GEN,
			keySize:  128,
			want:     true,
		},
		{
			name:     "AES 256 valid",
			mechType: CKM_AES_KEY_GEN,
			keySize:  256,
			want:     true,
		},
		{
			name:     "AES 192 valid",
			mechType: CKM_AES_KEY_GEN,
			keySize:  192,
			want:     true,
		},
		{
			name:     "AES 64 too small",
			mechType: CKM_AES_KEY_GEN,
			keySize:  64,
			want:     false,
		},
		{
			name:     "AES 512 too large",
			mechType: CKM_AES_KEY_GEN,
			keySize:  512,
			want:     false,
		},
		{
			name:     "RSA 2048 valid",
			mechType: CKM_RSA_PKCS_KEY_PAIR_GEN,
			keySize:  2048,
			want:     true,
		},
		{
			name:     "RSA 4096 valid",
			mechType: CKM_RSA_PKCS_KEY_PAIR_GEN,
			keySize:  4096,
			want:     true,
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
		// SHA-3 digest mechanism hex-pinning (corrected from draft values)
		{
			name:     "CKM_SHA3_224",
			constant: CKM_SHA3_224,
			want:     0x000002B5,
		},
		{
			name:     "CKM_SHA3_256",
			constant: CKM_SHA3_256,
			want:     0x000002C0,
		},
		{
			name:     "CKM_SHA3_384",
			constant: CKM_SHA3_384,
			want:     0x000002D0,
		},
		{
			name:     "CKM_SHA3_512",
			constant: CKM_SHA3_512,
			want:     0x000002E0,
		},
		// SHA-3 HMAC hex-pinning
		{
			name:     "CKM_SHA3_256_HMAC",
			constant: CKM_SHA3_256_HMAC,
			want:     0x000002C1,
		},
		{
			name:     "CKM_SHA3_384_HMAC",
			constant: CKM_SHA3_384_HMAC,
			want:     0x000002D1,
		},
		{
			name:     "CKM_SHA3_512_HMAC",
			constant: CKM_SHA3_512_HMAC,
			want:     0x000002E1,
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
		// HKDF mechanism hex-pinning (corrected from shifted values)
		{
			name:     "CKM_HKDF_DERIVE",
			constant: CKM_HKDF_DERIVE,
			want:     0x0000402C,
		},
		{
			name:     "CKM_HKDF_DATA",
			constant: CKM_HKDF_DATA,
			want:     0x0000402D,
		},
		{
			name:     "CKM_HKDF_KEY_GEN",
			constant: CKM_HKDF_KEY_GEN,
			want:     0x0000402E,
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
			name:     "CKF_HKDF_SALT_KEY",
			constant: CKF_HKDF_SALT_KEY,
			want:     0x00000003,
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
