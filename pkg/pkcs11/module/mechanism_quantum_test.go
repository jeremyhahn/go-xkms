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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuantumMechanismConstants(t *testing.T) {
	t.Run("ML-DSA mechanism values are vendor-defined", func(t *testing.T) {
		assert.True(t, CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN >= CKM_VENDOR_DEFINED,
			"ML-DSA-44 key pair gen should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_DSA_44 >= CKM_VENDOR_DEFINED,
			"ML-DSA-44 should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN >= CKM_VENDOR_DEFINED,
			"ML-DSA-65 key pair gen should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_DSA_65 >= CKM_VENDOR_DEFINED,
			"ML-DSA-65 should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN >= CKM_VENDOR_DEFINED,
			"ML-DSA-87 key pair gen should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_DSA_87 >= CKM_VENDOR_DEFINED,
			"ML-DSA-87 should be in vendor-defined range")
	})

	t.Run("ML-KEM mechanism values are vendor-defined", func(t *testing.T) {
		assert.True(t, CKM_VENDOR_ML_KEM_512_KEY_GEN >= CKM_VENDOR_DEFINED,
			"ML-KEM-512 key gen should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_KEM_512_ENCAPSULATE >= CKM_VENDOR_DEFINED,
			"ML-KEM-512 encapsulate should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_KEM_512_DECAPSULATE >= CKM_VENDOR_DEFINED,
			"ML-KEM-512 decapsulate should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_KEM_768_KEY_GEN >= CKM_VENDOR_DEFINED,
			"ML-KEM-768 key gen should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_KEM_768_ENCAPSULATE >= CKM_VENDOR_DEFINED,
			"ML-KEM-768 encapsulate should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_KEM_768_DECAPSULATE >= CKM_VENDOR_DEFINED,
			"ML-KEM-768 decapsulate should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_KEM_1024_KEY_GEN >= CKM_VENDOR_DEFINED,
			"ML-KEM-1024 key gen should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_KEM_1024_ENCAPSULATE >= CKM_VENDOR_DEFINED,
			"ML-KEM-1024 encapsulate should be in vendor-defined range")
		assert.True(t, CKM_VENDOR_ML_KEM_1024_DECAPSULATE >= CKM_VENDOR_DEFINED,
			"ML-KEM-1024 decapsulate should be in vendor-defined range")
	})

	t.Run("mechanism numbering scheme is correct", func(t *testing.T) {
		// ML-DSA mechanisms should be in 0x80001xxx range
		assert.Equal(t, MechanismType(0x80001001), CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN)
		assert.Equal(t, MechanismType(0x80001002), CKM_VENDOR_ML_DSA_44)
		assert.Equal(t, MechanismType(0x80001003), CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN)
		assert.Equal(t, MechanismType(0x80001004), CKM_VENDOR_ML_DSA_65)
		assert.Equal(t, MechanismType(0x80001005), CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN)
		assert.Equal(t, MechanismType(0x80001006), CKM_VENDOR_ML_DSA_87)

		// ML-KEM mechanisms should be in 0x80002xxx range
		assert.Equal(t, MechanismType(0x80002001), CKM_VENDOR_ML_KEM_512_KEY_GEN)
		assert.Equal(t, MechanismType(0x80002002), CKM_VENDOR_ML_KEM_512_ENCAPSULATE)
		assert.Equal(t, MechanismType(0x80002003), CKM_VENDOR_ML_KEM_512_DECAPSULATE)
		assert.Equal(t, MechanismType(0x80002004), CKM_VENDOR_ML_KEM_768_KEY_GEN)
		assert.Equal(t, MechanismType(0x80002005), CKM_VENDOR_ML_KEM_768_ENCAPSULATE)
		assert.Equal(t, MechanismType(0x80002006), CKM_VENDOR_ML_KEM_768_DECAPSULATE)
		assert.Equal(t, MechanismType(0x80002007), CKM_VENDOR_ML_KEM_1024_KEY_GEN)
		assert.Equal(t, MechanismType(0x80002008), CKM_VENDOR_ML_KEM_1024_ENCAPSULATE)
		assert.Equal(t, MechanismType(0x80002009), CKM_VENDOR_ML_KEM_1024_DECAPSULATE)
	})
}

func TestQuantumKeyTypeConstants(t *testing.T) {
	t.Run("key types are vendor-defined", func(t *testing.T) {
		assert.True(t, CKK_VENDOR_ML_DSA >= CKK_VENDOR_DEFINED,
			"ML-DSA key type should be in vendor-defined range")
		assert.True(t, CKK_VENDOR_ML_KEM >= CKK_VENDOR_DEFINED,
			"ML-KEM key type should be in vendor-defined range")
	})

	t.Run("key type values are correct", func(t *testing.T) {
		assert.Equal(t, KeyType(0x80000001), CKK_VENDOR_ML_DSA)
		assert.Equal(t, KeyType(0x80000002), CKK_VENDOR_ML_KEM)
	})
}

func TestQuantumMechanismRegistration(t *testing.T) {
	t.Run("ML-DSA mechanisms are registered in global registry", func(t *testing.T) {
		mechanisms := []MechanismType{
			CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_44,
			CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_65,
			CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_87,
		}

		for _, mech := range mechanisms {
			desc := GetMechanismDescriptor(mech)
			require.NotNil(t, desc, "mechanism %v should be registered", mech)
		}
	})

	t.Run("ML-KEM mechanisms are registered in global registry", func(t *testing.T) {
		// All three FIPS 203 parameter sets are registered; TestMLKEM512IsFullyWired
		// pins the 512 case, which was unavailable while these paths wrapped only
		// crypto/mlkem.
		mechanisms := []MechanismType{
			CKM_VENDOR_ML_KEM_768_KEY_GEN,
			CKM_VENDOR_ML_KEM_768_ENCAPSULATE,
			CKM_VENDOR_ML_KEM_768_DECAPSULATE,
			CKM_VENDOR_ML_KEM_1024_KEY_GEN,
			CKM_VENDOR_ML_KEM_1024_ENCAPSULATE,
			CKM_VENDOR_ML_KEM_1024_DECAPSULATE,
		}

		for _, mech := range mechanisms {
			desc := GetMechanismDescriptor(mech)
			require.NotNil(t, desc, "mechanism %v should be registered", mech)
		}
	})

	t.Run("mechanism names are registered", func(t *testing.T) {
		testCases := []struct {
			mech MechanismType
			name string
		}{
			{CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN, "CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN"},
			{CKM_VENDOR_ML_DSA_44, "CKM_VENDOR_ML_DSA_44"},
			{CKM_VENDOR_ML_KEM_768_KEY_GEN, "CKM_VENDOR_ML_KEM_768_KEY_GEN"},
			{CKM_VENDOR_ML_KEM_768_ENCAPSULATE, "CKM_VENDOR_ML_KEM_768_ENCAPSULATE"},
			{CKM_VENDOR_ML_KEM_768_DECAPSULATE, "CKM_VENDOR_ML_KEM_768_DECAPSULATE"},
		}

		for _, tc := range testCases {
			name := GetMechanismName(tc.mech)
			assert.Equal(t, tc.name, name)
		}
	})
}

func TestQuantumMechanismDescriptors(t *testing.T) {
	t.Run("ML-DSA-44 key pair gen has correct properties", func(t *testing.T) {
		desc := GetQuantumMechanismDescriptor(CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN)
		require.NotNil(t, desc)

		assert.Equal(t, "CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN", desc.Name)
		assert.True(t, desc.Flags&CKF_GENERATE_KEY_PAIR != 0,
			"should support key pair generation")
		assert.True(t, desc.Flags&CKF_EXTENSION != 0,
			"should have extension flag")
		assert.Contains(t, desc.Categories, CategoryKeyPairGen)
	})

	t.Run("ML-DSA-44 signing has correct properties", func(t *testing.T) {
		desc := GetQuantumMechanismDescriptor(CKM_VENDOR_ML_DSA_44)
		require.NotNil(t, desc)

		assert.Equal(t, "CKM_VENDOR_ML_DSA_44", desc.Name)
		assert.True(t, desc.Flags&CKF_SIGN != 0, "should support signing")
		assert.True(t, desc.Flags&CKF_VERIFY != 0, "should support verification")
		assert.True(t, desc.Flags&CKF_EXTENSION != 0, "should have extension flag")
		assert.Contains(t, desc.Categories, CategorySign)
		assert.Contains(t, desc.Categories, CategoryVerify)
	})

	t.Run("ML-KEM-768 key gen has correct properties", func(t *testing.T) {
		desc := GetQuantumMechanismDescriptor(CKM_VENDOR_ML_KEM_768_KEY_GEN)
		require.NotNil(t, desc)

		assert.Equal(t, "CKM_VENDOR_ML_KEM_768_KEY_GEN", desc.Name)
		assert.True(t, desc.Flags&CKF_GENERATE_KEY_PAIR != 0,
			"should support key pair generation")
		assert.True(t, desc.Flags&CKF_EXTENSION != 0,
			"should have extension flag")
	})

	t.Run("ML-KEM-768 encapsulate has correct properties", func(t *testing.T) {
		desc := GetQuantumMechanismDescriptor(CKM_VENDOR_ML_KEM_768_ENCAPSULATE)
		require.NotNil(t, desc)

		assert.Equal(t, "CKM_VENDOR_ML_KEM_768_ENCAPSULATE", desc.Name)
		// CKF_ENCAPSULATE, not CKF_DERIVE. PKCS#11 v3.2 §5.20 gates
		// C_EncapsulateKey on the former and C_DeriveKey on the latter, and this
		// mechanism appears in no C_DeriveKey dispatch -- so CKF_DERIVE made
		// CanDerive answer true for an operation that always returns
		// CKR_MECHANISM_INVALID, while the flag that gates the operation it does
		// perform went unset.
		assert.True(t, desc.Flags&CKF_ENCAPSULATE != 0, "should support encapsulation")
		assert.True(t, desc.Flags&CKF_DERIVE == 0, "must not claim derivation")
		assert.True(t, desc.Flags&CKF_EXTENSION != 0, "should have extension flag")
		assert.Contains(t, desc.Categories, CategoryEncapsulate)
	})

	t.Run("ML-KEM-768 decapsulate has correct properties", func(t *testing.T) {
		desc := GetQuantumMechanismDescriptor(CKM_VENDOR_ML_KEM_768_DECAPSULATE)
		require.NotNil(t, desc)

		assert.Equal(t, "CKM_VENDOR_ML_KEM_768_DECAPSULATE", desc.Name)
		// CKF_DECAPSULATE, not CKF_DERIVE; see the encapsulate case above.
		assert.True(t, desc.Flags&CKF_DECAPSULATE != 0, "should support decapsulation")
		assert.True(t, desc.Flags&CKF_DERIVE == 0, "must not claim derivation")
		assert.True(t, desc.Flags&CKF_EXTENSION != 0, "should have extension flag")
		assert.Contains(t, desc.Categories, CategoryDecapsulate)
	})
}

func TestIsQuantumMechanism(t *testing.T) {
	t.Run("returns true for quantum mechanisms", func(t *testing.T) {
		quantumMechs := []MechanismType{
			CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_44,
			CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_65,
			CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_87,
			// ML-KEM-512 is unregistered, so IsQuantumMechanism -- which
			// resolves through the registry -- correctly answers false for it.
			CKM_VENDOR_ML_KEM_768_KEY_GEN,
			CKM_VENDOR_ML_KEM_768_ENCAPSULATE,
			CKM_VENDOR_ML_KEM_768_DECAPSULATE,
			CKM_VENDOR_ML_KEM_1024_KEY_GEN,
			CKM_VENDOR_ML_KEM_1024_ENCAPSULATE,
			CKM_VENDOR_ML_KEM_1024_DECAPSULATE,
		}

		for _, mech := range quantumMechs {
			assert.True(t, IsQuantumMechanism(mech), "mechanism %v should be quantum", mech)
		}
	})

	t.Run("returns false for classical mechanisms", func(t *testing.T) {
		classicalMechs := []MechanismType{
			CKM_RSA_PKCS_KEY_PAIR_GEN,
			CKM_RSA_PKCS,
			CKM_ECDSA,
			CKM_EC_KEY_PAIR_GEN,
			CKM_AES_KEY_GEN,
			CKM_SHA256,
		}

		for _, mech := range classicalMechs {
			assert.False(t, IsQuantumMechanism(mech), "mechanism %v should not be quantum", mech)
		}
	})
}

func TestIsMLDSAMechanism(t *testing.T) {
	t.Run("returns true for ML-DSA mechanisms", func(t *testing.T) {
		mldsaMechs := []MechanismType{
			CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_44,
			CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_65,
			CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_87,
		}

		for _, mech := range mldsaMechs {
			assert.True(t, IsMLDSAMechanism(mech), "mechanism %v should be ML-DSA", mech)
		}
	})

	t.Run("returns false for ML-KEM mechanisms", func(t *testing.T) {
		mlkemMechs := []MechanismType{
			CKM_VENDOR_ML_KEM_512_KEY_GEN,
			CKM_VENDOR_ML_KEM_768_KEY_GEN,
			CKM_VENDOR_ML_KEM_1024_KEY_GEN,
		}

		for _, mech := range mlkemMechs {
			assert.False(t, IsMLDSAMechanism(mech), "mechanism %v should not be ML-DSA", mech)
		}
	})
}

func TestIsMLKEMMechanism(t *testing.T) {
	t.Run("returns true for ML-KEM mechanisms", func(t *testing.T) {
		mlkemMechs := []MechanismType{
			CKM_VENDOR_ML_KEM_512_KEY_GEN,
			CKM_VENDOR_ML_KEM_512_ENCAPSULATE,
			CKM_VENDOR_ML_KEM_512_DECAPSULATE,
			CKM_VENDOR_ML_KEM_768_KEY_GEN,
			CKM_VENDOR_ML_KEM_768_ENCAPSULATE,
			CKM_VENDOR_ML_KEM_768_DECAPSULATE,
			CKM_VENDOR_ML_KEM_1024_KEY_GEN,
			CKM_VENDOR_ML_KEM_1024_ENCAPSULATE,
			CKM_VENDOR_ML_KEM_1024_DECAPSULATE,
		}

		for _, mech := range mlkemMechs {
			assert.True(t, IsMLKEMMechanism(mech), "mechanism %v should be ML-KEM", mech)
		}
	})

	t.Run("returns false for ML-DSA mechanisms", func(t *testing.T) {
		mldsaMechs := []MechanismType{
			CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_44,
			CKM_VENDOR_ML_DSA_65,
		}

		for _, mech := range mldsaMechs {
			assert.False(t, IsMLKEMMechanism(mech), "mechanism %v should not be ML-KEM", mech)
		}
	})
}

func TestGetQuantumKeyType(t *testing.T) {
	t.Run("returns ML-DSA key type for ML-DSA mechanisms", func(t *testing.T) {
		mldsaMechs := []MechanismType{
			CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_44,
			CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_65,
			CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_87,
		}

		for _, mech := range mldsaMechs {
			kt := GetQuantumKeyType(mech)
			assert.Equal(t, CKK_VENDOR_ML_DSA, kt, "mechanism %v should return ML-DSA key type", mech)
		}
	})

	t.Run("returns ML-KEM key type for ML-KEM mechanisms", func(t *testing.T) {
		mlkemMechs := []MechanismType{
			CKM_VENDOR_ML_KEM_512_KEY_GEN,
			CKM_VENDOR_ML_KEM_512_ENCAPSULATE,
			CKM_VENDOR_ML_KEM_512_DECAPSULATE,
			CKM_VENDOR_ML_KEM_768_KEY_GEN,
			CKM_VENDOR_ML_KEM_768_ENCAPSULATE,
			CKM_VENDOR_ML_KEM_768_DECAPSULATE,
			CKM_VENDOR_ML_KEM_1024_KEY_GEN,
			CKM_VENDOR_ML_KEM_1024_ENCAPSULATE,
			CKM_VENDOR_ML_KEM_1024_DECAPSULATE,
		}

		for _, mech := range mlkemMechs {
			kt := GetQuantumKeyType(mech)
			assert.Equal(t, CKK_VENDOR_ML_KEM, kt, "mechanism %v should return ML-KEM key type", mech)
		}
	})

	t.Run("returns vendor-defined for unknown mechanisms", func(t *testing.T) {
		kt := GetQuantumKeyType(CKM_RSA_PKCS)
		assert.Equal(t, CKK_VENDOR_DEFINED, kt)
	})
}

func TestGetMLDSASecurityLevel(t *testing.T) {
	testCases := []struct {
		mech  MechanismType
		level int
	}{
		{CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN, 44},
		{CKM_VENDOR_ML_DSA_44, 44},
		{CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN, 65},
		{CKM_VENDOR_ML_DSA_65, 65},
		{CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN, 87},
		{CKM_VENDOR_ML_DSA_87, 87},
		{CKM_RSA_PKCS, 0}, // Non-ML-DSA mechanism
	}

	for _, tc := range testCases {
		t.Run(GetMechanismName(tc.mech), func(t *testing.T) {
			level := GetMLDSASecurityLevel(tc.mech)
			assert.Equal(t, tc.level, level)
		})
	}
}

func TestGetMLKEMSecurityLevel(t *testing.T) {
	testCases := []struct {
		mech  MechanismType
		level int
	}{
		{CKM_VENDOR_ML_KEM_512_KEY_GEN, 512},
		{CKM_VENDOR_ML_KEM_512_ENCAPSULATE, 512},
		{CKM_VENDOR_ML_KEM_512_DECAPSULATE, 512},
		{CKM_VENDOR_ML_KEM_768_KEY_GEN, 768},
		{CKM_VENDOR_ML_KEM_768_ENCAPSULATE, 768},
		{CKM_VENDOR_ML_KEM_768_DECAPSULATE, 768},
		{CKM_VENDOR_ML_KEM_1024_KEY_GEN, 1024},
		{CKM_VENDOR_ML_KEM_1024_ENCAPSULATE, 1024},
		{CKM_VENDOR_ML_KEM_1024_DECAPSULATE, 1024},
		{CKM_RSA_PKCS, 0}, // Non-ML-KEM mechanism
	}

	for _, tc := range testCases {
		t.Run(GetMechanismName(tc.mech), func(t *testing.T) {
			level := GetMLKEMSecurityLevel(tc.mech)
			assert.Equal(t, tc.level, level)
		})
	}
}

func TestListQuantumMechanisms(t *testing.T) {
	mechanisms := ListQuantumMechanisms()

	t.Run("returns all quantum mechanisms", func(t *testing.T) {
		// 6 ML-DSA + 9 ML-KEM: three parameter sets, each with key generation,
		// encapsulation and decapsulation. The ML-KEM-512 trio was unregistered
		// while pkg/quantum wrapped only crypto/mlkem, which implements 768 and
		// 1024 alone.
		assert.Len(t, mechanisms, 15)
	})

	t.Run("contains ML-DSA mechanisms", func(t *testing.T) {
		expected := []MechanismType{
			CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_44,
			CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_65,
			CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN,
			CKM_VENDOR_ML_DSA_87,
		}

		for _, mech := range expected {
			assert.Contains(t, mechanisms, mech)
		}
	})

	t.Run("contains ML-KEM mechanisms", func(t *testing.T) {
		expected := []MechanismType{
			CKM_VENDOR_ML_KEM_768_KEY_GEN,
			CKM_VENDOR_ML_KEM_768_ENCAPSULATE,
			CKM_VENDOR_ML_KEM_768_DECAPSULATE,
			CKM_VENDOR_ML_KEM_1024_KEY_GEN,
			CKM_VENDOR_ML_KEM_1024_ENCAPSULATE,
			CKM_VENDOR_ML_KEM_1024_DECAPSULATE,
		}

		for _, mech := range expected {
			assert.Contains(t, mechanisms, mech)
		}
	})
}

// TestMLKEM512IsFullyWired is the inverse of the test that used to stand here.
//
// ML-KEM-512 was unavailable while the module's KEM paths wrapped only
// crypto/mlkem, which implements the 768 and 1024 parameter sets and no other.
// The mechanisms were left unregistered on purpose: advertising them would have
// let C_EncapsulateKey's size query answer CKR_OK for an encapsulation that then
// refused the mechanism, which is the shape the no-stub policy exists to prevent.
//
// pkg/quantum/mlkem512 now supplies the parameter set from CIRCL's FIPS 203
// implementation, so the requirement inverts: every routing table that was
// checked for the *absence* of a 512 entry is now checked for its presence. A
// missing entry in any one of them reproduces the original defect from the other
// direction -- an advertised mechanism whose dispatch silently falls through to
// ML-KEM-768, which is exactly what resolveMLKEMLevel's default did before these
// entries were added.
func TestMLKEM512IsFullyWired(t *testing.T) {
	registered := []MechanismType{
		CKM_VENDOR_ML_KEM_512_KEY_GEN,
		CKM_VENDOR_ML_KEM_512_ENCAPSULATE,
		CKM_VENDOR_ML_KEM_512_DECAPSULATE,
	}

	for _, mech := range registered {
		t.Run(GetMechanismName(mech), func(t *testing.T) {
			assert.NotNil(t, GetMechanismDescriptor(mech),
				"ML-KEM-512 is implemented, so its mechanisms must be resolvable")
			assert.Contains(t, ListQuantumMechanisms(), mech)
		})
	}

	t.Run("every routing table resolves 512", func(t *testing.T) {
		encapsulate, ok := mlkemEncapsulateVendorMechanism[512]
		require.True(t, ok, "C_EncapsulateKey cannot dispatch an ML-KEM-512 key without this")
		assert.Equal(t, CKM_VENDOR_ML_KEM_512_ENCAPSULATE, encapsulate)

		decapsulate, ok := mlkemDecapsulateVendorMechanism[512]
		require.True(t, ok, "C_DecapsulateKey cannot dispatch an ML-KEM-512 key without this")
		assert.Equal(t, CKM_VENDOR_ML_KEM_512_DECAPSULATE, decapsulate)

		size, ok := mlkemCiphertextSizeByLevel[512]
		require.True(t, ok, "the C ABI size probe needs this before it will call through")
		assert.Equal(t, uint64(MLKEM512CiphertextSize), size)
	})

	// The level must be resolvable from the key's own parameter set, because a
	// private key cannot be told apart by length: every ML-KEM level stores the
	// same 64-byte seed.
	t.Run("CKA_PARAMETER_SET resolves the level", func(t *testing.T) {
		key := &Object{Attributes: map[AttributeType][]byte{}}
		key.SetAttribute(CKA_PARAMETER_SET, NewUint32Attribute(CKA_PARAMETER_SET, uint32(CKP_ML_KEM_512)).Value)

		assert.Equal(t, 512, resolveMLKEMLevel(key, mlkemSeedSize),
			"a 64-byte seed is ambiguous across levels, so CKA_PARAMETER_SET has to decide")
	})
}

func TestQuantumKeySizeConstants(t *testing.T) {
	t.Run("ML-DSA-44 sizes match NIST FIPS 204", func(t *testing.T) {
		assert.Equal(t, 1312, MLDSA44PublicKeySize)
		assert.Equal(t, 2560, MLDSA44SecretKeySize)
		assert.Equal(t, 2420, MLDSA44SignatureSize)
	})

	t.Run("ML-DSA-65 sizes match NIST FIPS 204", func(t *testing.T) {
		assert.Equal(t, 1952, MLDSA65PublicKeySize)
		assert.Equal(t, 4032, MLDSA65SecretKeySize)
		assert.Equal(t, 3309, MLDSA65SignatureSize)
	})

	t.Run("ML-DSA-87 sizes match NIST FIPS 204", func(t *testing.T) {
		assert.Equal(t, 2592, MLDSA87PublicKeySize)
		assert.Equal(t, 4896, MLDSA87SecretKeySize)
		assert.Equal(t, 4627, MLDSA87SignatureSize)
	})

	t.Run("ML-KEM-512 sizes match NIST FIPS 203", func(t *testing.T) {
		assert.Equal(t, 800, MLKEM512PublicKeySize)
		assert.Equal(t, 1632, MLKEM512SecretKeySize)
		assert.Equal(t, 768, MLKEM512CiphertextSize)
		assert.Equal(t, 32, MLKEM512SharedSecretSize)
	})

	t.Run("ML-KEM-768 sizes match NIST FIPS 203", func(t *testing.T) {
		assert.Equal(t, 1184, MLKEM768PublicKeySize)
		assert.Equal(t, 2400, MLKEM768SecretKeySize)
		assert.Equal(t, 1088, MLKEM768CiphertextSize)
		assert.Equal(t, 32, MLKEM768SharedSecretSize)
	})

	t.Run("ML-KEM-1024 sizes match NIST FIPS 203", func(t *testing.T) {
		assert.Equal(t, 1568, MLKEM1024PublicKeySize)
		assert.Equal(t, 3168, MLKEM1024SecretKeySize)
		assert.Equal(t, 1568, MLKEM1024CiphertextSize)
		assert.Equal(t, 32, MLKEM1024SharedSecretSize)
	})
}

func TestKeyTypeStringMethods(t *testing.T) {
	t.Run("ML-DSA key type String method", func(t *testing.T) {
		assert.Equal(t, "CKK_VENDOR_ML_DSA", CKK_VENDOR_ML_DSA.String())
	})

	t.Run("ML-KEM key type String method", func(t *testing.T) {
		assert.Equal(t, "CKK_VENDOR_ML_KEM", CKK_VENDOR_ML_KEM.String())
	})
}

func TestMechanismTypeStringMethods(t *testing.T) {
	testCases := []struct {
		mech     MechanismType
		expected string
	}{
		{CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN, "CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN"},
		{CKM_VENDOR_ML_DSA_44, "CKM_VENDOR_ML_DSA_44"},
		{CKM_VENDOR_ML_KEM_768_KEY_GEN, "CKM_VENDOR_ML_KEM_768_KEY_GEN"},
		{CKM_VENDOR_ML_KEM_768_ENCAPSULATE, "CKM_VENDOR_ML_KEM_768_ENCAPSULATE"},
		{CKM_VENDOR_ML_KEM_768_DECAPSULATE, "CKM_VENDOR_ML_KEM_768_DECAPSULATE"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.mech.String())
		})
	}
}
