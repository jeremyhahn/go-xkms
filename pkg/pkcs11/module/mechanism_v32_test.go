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
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestV32MechanismConstants(t *testing.T) {

	t.Run("ML-KEM mechanism IDs match PKCS#11 v3.2 spec", func(t *testing.T) {
		assert.Equal(t, MechanismType(0x0000000f), CKM_ML_KEM_KEY_PAIR_GEN)
		assert.Equal(t, MechanismType(0x00000017), CKM_ML_KEM)
	})

	t.Run("ML-DSA mechanism IDs match PKCS#11 v3.2 spec", func(t *testing.T) {
		assert.Equal(t, MechanismType(0x0000001c), CKM_ML_DSA_KEY_PAIR_GEN)
		assert.Equal(t, MechanismType(0x0000001d), CKM_ML_DSA)
	})

	t.Run("SLH-DSA mechanism IDs match PKCS#11 v3.2 spec", func(t *testing.T) {
		assert.Equal(t, MechanismType(0x0000002d), CKM_SLH_DSA_KEY_PAIR_GEN)
		assert.Equal(t, MechanismType(0x0000002e), CKM_SLH_DSA)
	})

	t.Run("HSS/LMS mechanism IDs match PKCS#11 v3.2 spec", func(t *testing.T) {
		assert.Equal(t, MechanismType(0x00004032), CKM_HSS_KEY_PAIR_GEN)
		assert.Equal(t, MechanismType(0x00004033), CKM_HSS)
	})

	t.Run("XMSS mechanism IDs match PKCS#11 v3.2 spec", func(t *testing.T) {
		assert.Equal(t, MechanismType(0x00004034), CKM_XMSS_KEY_PAIR_GEN)
		assert.Equal(t, MechanismType(0x00004036), CKM_XMSS)
	})

	t.Run("XMSS-MT mechanism IDs match PKCS#11 v3.2 spec", func(t *testing.T) {
		assert.Equal(t, MechanismType(0x00004035), CKM_XMSSMT_KEY_PAIR_GEN)
		assert.Equal(t, MechanismType(0x00004037), CKM_XMSSMT)
	})

	t.Run("mechanisms are in standard range not vendor-defined", func(t *testing.T) {
		v32Mechs := []MechanismType{
			CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA,
			CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM,
			CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA,
			CKM_HSS_KEY_PAIR_GEN, CKM_HSS,
			CKM_XMSS_KEY_PAIR_GEN, CKM_XMSS,
			CKM_XMSSMT_KEY_PAIR_GEN, CKM_XMSSMT,
		}
		for _, mech := range v32Mechs {
			assert.True(t, mech < CKM_VENDOR_DEFINED,
				"mechanism 0x%08X should be in standard range", mech)
		}
	})
}

func TestV32KeyTypeConstants(t *testing.T) {

	t.Run("v3.2 PQC key types have correct hex values", func(t *testing.T) {
		assert.Equal(t, KeyType(0x46), CKK_HSS)
		assert.Equal(t, KeyType(0x47), CKK_XMSS)
		assert.Equal(t, KeyType(0x48), CKK_XMSSMT)
		assert.Equal(t, KeyType(0x49), CKK_ML_KEM)
		assert.Equal(t, KeyType(0x4A), CKK_ML_DSA)
		assert.Equal(t, KeyType(0x4B), CKK_SLH_DSA)
	})

	t.Run("v3.2 key types are in standard range not vendor-defined", func(t *testing.T) {
		keyTypes := []KeyType{
			CKK_HSS, CKK_XMSS, CKK_XMSSMT,
			CKK_ML_DSA, CKK_ML_KEM, CKK_SLH_DSA,
		}
		for _, kt := range keyTypes {
			assert.True(t, kt < CKK_VENDOR_DEFINED,
				"key type 0x%08X should be in standard range", kt)
		}
	})
}

func TestV32MechanismRegistration(t *testing.T) {

	t.Run("all v3.2 mechanisms registered in global mechanismRegistry", func(t *testing.T) {
		v32Mechs := []MechanismType{
			CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA,
			CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM,
			CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA,
			CKM_HSS_KEY_PAIR_GEN, CKM_HSS,
			CKM_XMSS_KEY_PAIR_GEN, CKM_XMSS,
			CKM_XMSSMT_KEY_PAIR_GEN, CKM_XMSSMT,
		}
		for _, mech := range v32Mechs {
			desc, ok := mechanismRegistry[mech]
			require.True(t, ok, "mechanism 0x%08X should be in global registry", mech)
			assert.Equal(t, mech, desc.Type)
			assert.NotEmpty(t, desc.Name)
		}
	})

	t.Run("all v3.2 mechanisms registered in global mechanismNames", func(t *testing.T) {
		expected := map[MechanismType]string{
			CKM_ML_DSA_KEY_PAIR_GEN:  "CKM_ML_DSA_KEY_PAIR_GEN",
			CKM_ML_DSA:               "CKM_ML_DSA",
			CKM_ML_KEM_KEY_PAIR_GEN:  "CKM_ML_KEM_KEY_PAIR_GEN",
			CKM_ML_KEM:               "CKM_ML_KEM",
			CKM_SLH_DSA_KEY_PAIR_GEN: "CKM_SLH_DSA_KEY_PAIR_GEN",
			CKM_SLH_DSA:              "CKM_SLH_DSA",
			CKM_HSS_KEY_PAIR_GEN:     "CKM_HSS_KEY_PAIR_GEN",
			CKM_HSS:                  "CKM_HSS",
			CKM_XMSS_KEY_PAIR_GEN:    "CKM_XMSS_KEY_PAIR_GEN",
			CKM_XMSS:                 "CKM_XMSS",
			CKM_XMSSMT_KEY_PAIR_GEN:  "CKM_XMSSMT_KEY_PAIR_GEN",
			CKM_XMSSMT:               "CKM_XMSSMT",
		}
		for mech, name := range expected {
			actual, ok := mechanismNames[mech]
			require.True(t, ok, "mechanism 0x%08X should have a name", mech)
			assert.Equal(t, name, actual)
		}
	})

	t.Run("v32MechanismNames map has exactly 39 entries", func(t *testing.T) {
		assert.Len(t, v32MechanismNames, 39)
	})

	t.Run("v32MechanismRegistry map has exactly 39 entries", func(t *testing.T) {
		assert.Len(t, v32MechanismRegistry, 39)
	})

	t.Run("v32KeyTypeMap has exactly 36 entries", func(t *testing.T) {
		assert.Len(t, v32KeyTypeMap, 36)
	})
}

func TestV32MechanismFlags(t *testing.T) {

	t.Run("key pair generation mechanisms have CKF_GENERATE_KEY_PAIR flag", func(t *testing.T) {
		keygenMechs := []MechanismType{
			CKM_ML_DSA_KEY_PAIR_GEN,
			CKM_ML_KEM_KEY_PAIR_GEN,
			CKM_SLH_DSA_KEY_PAIR_GEN,
			CKM_HSS_KEY_PAIR_GEN,
			CKM_XMSS_KEY_PAIR_GEN,
			CKM_XMSSMT_KEY_PAIR_GEN,
		}
		for _, mech := range keygenMechs {
			desc := mechanismRegistry[mech]
			require.NotNil(t, desc, "mechanism 0x%08X descriptor should exist", mech)
			assert.True(t, desc.Flags&CKF_GENERATE_KEY_PAIR != 0,
				"%s should have CKF_GENERATE_KEY_PAIR flag", desc.Name)
			assert.Contains(t, desc.Categories, CategoryKeyPairGen)
		}
	})

	t.Run("sign/verify mechanisms have CKF_SIGN and CKF_VERIFY flags", func(t *testing.T) {
		signVerifyMechs := []MechanismType{
			CKM_ML_DSA,
			CKM_SLH_DSA,
			CKM_HSS,
			CKM_XMSS,
			CKM_XMSSMT,
		}
		for _, mech := range signVerifyMechs {
			desc := mechanismRegistry[mech]
			require.NotNil(t, desc, "mechanism 0x%08X descriptor should exist", mech)
			assert.True(t, desc.Flags&CKF_SIGN != 0,
				"%s should have CKF_SIGN flag", desc.Name)
			assert.True(t, desc.Flags&CKF_VERIFY != 0,
				"%s should have CKF_VERIFY flag", desc.Name)
			assert.Contains(t, desc.Categories, CategorySign)
			assert.Contains(t, desc.Categories, CategoryVerify)
		}
	})

	t.Run("ML-KEM operation mechanism has CKF_ENCAPSULATE and CKF_DECAPSULATE flags", func(t *testing.T) {
		desc := mechanismRegistry[CKM_ML_KEM]
		require.NotNil(t, desc)
		assert.True(t, desc.Flags&CKF_ENCAPSULATE != 0,
			"CKM_ML_KEM should have CKF_ENCAPSULATE flag")
		assert.True(t, desc.Flags&CKF_DECAPSULATE != 0,
			"CKM_ML_KEM should have CKF_DECAPSULATE flag")
		assert.Contains(t, desc.Categories, v32CategoryEncapsulate)
		assert.Contains(t, desc.Categories, v32CategoryDecapsulate)
	})

	t.Run("CKF_ENCAPSULATE and CKF_DECAPSULATE have correct values", func(t *testing.T) {
		assert.Equal(t, MechanismFlag(0x10000000), CKF_ENCAPSULATE)
		assert.Equal(t, MechanismFlag(0x20000000), CKF_DECAPSULATE)
	})
}

func TestV32MechanismKeySizes(t *testing.T) {

	t.Run("ML-DSA keygen has correct key size bounds", func(t *testing.T) {
		desc := mechanismRegistry[CKM_ML_DSA_KEY_PAIR_GEN]
		require.NotNil(t, desc)
		assert.Equal(t, uint32(v32MLDSA44PublicKeySize*8), desc.MinKeySize)
		assert.Equal(t, uint32(v32MLDSA87SecretKeySize*8), desc.MaxKeySize)
	})

	t.Run("ML-KEM keygen has correct key size bounds", func(t *testing.T) {
		desc := mechanismRegistry[CKM_ML_KEM_KEY_PAIR_GEN]
		require.NotNil(t, desc)
		assert.Equal(t, uint32(v32MLKEM512PublicKeySize*8), desc.MinKeySize)
		assert.Equal(t, uint32(v32MLKEM1024SecretKeySize*8), desc.MaxKeySize)
	})
}

func TestV32SLHDSAKeygenKeySizeBounds(t *testing.T) {

	t.Run("SLH-DSA keygen descriptor exists in registry", func(t *testing.T) {
		desc, ok := mechanismRegistry[CKM_SLH_DSA_KEY_PAIR_GEN]
		require.True(t, ok, "CKM_SLH_DSA_KEY_PAIR_GEN should be in mechanismRegistry")
		assert.Equal(t, CKM_SLH_DSA_KEY_PAIR_GEN, desc.Type)
		assert.Equal(t, "CKM_SLH_DSA_KEY_PAIR_GEN", desc.Name)
		assert.Contains(t, desc.Categories, CategoryKeyPairGen)
		assert.True(t, desc.Flags&CKF_GENERATE_KEY_PAIR != 0,
			"CKM_SLH_DSA_KEY_PAIR_GEN should have CKF_GENERATE_KEY_PAIR flag")
	})

	t.Run("SLH-DSA keygen has zero key size bounds (parameter-set driven)", func(t *testing.T) {
		// SLH-DSA key sizes depend on the parameter set (CKP_SLH_DSA_*) rather
		// than a fixed min/max key size. The descriptor intentionally uses
		// zero bounds because the 12 parameter sets (SHA2 and SHAKE at 128/192/256
		// in S and F variants) have widely varying key sizes.
		desc := mechanismRegistry[CKM_SLH_DSA_KEY_PAIR_GEN]
		require.NotNil(t, desc)
		assert.Equal(t, uint32(0), desc.MinKeySize,
			"SLH-DSA keygen MinKeySize should be 0 (parameter-set driven)")
		assert.Equal(t, uint32(0), desc.MaxKeySize,
			"SLH-DSA keygen MaxKeySize should be 0 (parameter-set driven)")
	})

	t.Run("SLH-DSA sign/verify descriptor exists with zero key size bounds", func(t *testing.T) {
		desc, ok := mechanismRegistry[CKM_SLH_DSA]
		require.True(t, ok, "CKM_SLH_DSA should be in mechanismRegistry")
		assert.Equal(t, uint32(0), desc.MinKeySize)
		assert.Equal(t, uint32(0), desc.MaxKeySize)
		assert.True(t, desc.Flags&CKF_SIGN != 0,
			"CKM_SLH_DSA should have CKF_SIGN flag")
		assert.True(t, desc.Flags&CKF_VERIFY != 0,
			"CKM_SLH_DSA should have CKF_VERIFY flag")
	})

	t.Run("SLH-DSA parameter sets are defined for all 12 variants", func(t *testing.T) {
		paramSets := []struct {
			name  string
			value ParameterSetType
		}{
			{"SLH-DSA-SHA2-128S", CKP_SLH_DSA_SHA2_128S},
			{"SLH-DSA-SHA2-128F", CKP_SLH_DSA_SHA2_128F},
			{"SLH-DSA-SHA2-192S", CKP_SLH_DSA_SHA2_192S},
			{"SLH-DSA-SHA2-192F", CKP_SLH_DSA_SHA2_192F},
			{"SLH-DSA-SHA2-256S", CKP_SLH_DSA_SHA2_256S},
			{"SLH-DSA-SHA2-256F", CKP_SLH_DSA_SHA2_256F},
			{"SLH-DSA-SHAKE-128S", CKP_SLH_DSA_SHAKE_128S},
			{"SLH-DSA-SHAKE-128F", CKP_SLH_DSA_SHAKE_128F},
			{"SLH-DSA-SHAKE-192S", CKP_SLH_DSA_SHAKE_192S},
			{"SLH-DSA-SHAKE-192F", CKP_SLH_DSA_SHAKE_192F},
			{"SLH-DSA-SHAKE-256S", CKP_SLH_DSA_SHAKE_256S},
			{"SLH-DSA-SHAKE-256F", CKP_SLH_DSA_SHAKE_256F},
		}
		for _, ps := range paramSets {
			t.Run(ps.name, func(t *testing.T) {
				resolved, ok := parameterSetNames[ps.name]
				require.True(t, ok, "%s should be in parameterSetNames", ps.name)
				assert.Equal(t, ps.value, resolved,
					"%s should resolve to correct ParameterSetType", ps.name)
			})
		}
	})

	t.Run("SLH-DSA parameter set values span 1 through 12", func(t *testing.T) {
		assert.Equal(t, ParameterSetType(0x01), CKP_SLH_DSA_SHA2_128S)
		assert.Equal(t, ParameterSetType(0x0C), CKP_SLH_DSA_SHAKE_256F)
	})
}

func TestIsV32PQCMechanism(t *testing.T) {

	t.Run("returns true for all 12 v3.2 PQC mechanisms", func(t *testing.T) {
		v32Mechs := []MechanismType{
			CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA,
			CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM,
			CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA,
			CKM_HSS_KEY_PAIR_GEN, CKM_HSS,
			CKM_XMSS_KEY_PAIR_GEN, CKM_XMSS,
			CKM_XMSSMT_KEY_PAIR_GEN, CKM_XMSSMT,
		}
		for _, mech := range v32Mechs {
			assert.True(t, IsV32PQCMechanism(mech),
				"IsV32PQCMechanism should return true for 0x%08X", mech)
		}
	})

	t.Run("returns false for non-v3.2 mechanisms", func(t *testing.T) {
		nonV32 := []MechanismType{
			CKM_RSA_PKCS,
			CKM_AES_GCM,
			CKM_ECDSA,
			CKM_SHA256,
			MechanismType(0xFFFFFFFF),
			MechanismType(0x00000000),
		}
		for _, mech := range nonV32 {
			assert.False(t, IsV32PQCMechanism(mech),
				"IsV32PQCMechanism should return false for 0x%08X", mech)
		}
	})
}

func TestGetV32KeyType(t *testing.T) {

	t.Run("returns correct key type for each mechanism", func(t *testing.T) {
		expected := map[MechanismType]KeyType{
			CKM_ML_DSA_KEY_PAIR_GEN:  CKK_ML_DSA,
			CKM_ML_DSA:               CKK_ML_DSA,
			CKM_ML_KEM_KEY_PAIR_GEN:  CKK_ML_KEM,
			CKM_ML_KEM:               CKK_ML_KEM,
			CKM_SLH_DSA_KEY_PAIR_GEN: CKK_SLH_DSA,
			CKM_SLH_DSA:              CKK_SLH_DSA,
			CKM_HSS_KEY_PAIR_GEN:     CKK_HSS,
			CKM_HSS:                  CKK_HSS,
			CKM_XMSS_KEY_PAIR_GEN:    CKK_XMSS,
			CKM_XMSS:                 CKK_XMSS,
			CKM_XMSSMT_KEY_PAIR_GEN:  CKK_XMSSMT,
			CKM_XMSSMT:               CKK_XMSSMT,
		}
		for mech, expectedKT := range expected {
			actual := GetV32KeyType(mech)
			assert.Equal(t, expectedKT, actual,
				"GetV32KeyType(0x%08X) should return 0x%08X", mech, expectedKT)
		}
	})

	t.Run("returns CKK_VENDOR_DEFINED for unknown mechanisms", func(t *testing.T) {
		unknowns := []MechanismType{
			CKM_RSA_PKCS,
			CKM_AES_GCM,
			MechanismType(0xFFFFFFFF),
			MechanismType(0x00000000),
		}
		for _, mech := range unknowns {
			actual := GetV32KeyType(mech)
			assert.Equal(t, CKK_VENDOR_DEFINED, actual,
				"GetV32KeyType(0x%08X) should return CKK_VENDOR_DEFINED", mech)
		}
	})
}

func TestV32MechanismDescriptorConsistency(t *testing.T) {

	t.Run("descriptor Name matches mechanismNames entry", func(t *testing.T) {
		for mechType, desc := range v32MechanismRegistry {
			name, ok := v32MechanismNames[mechType]
			require.True(t, ok, "mechanism 0x%08X in registry should have name entry", mechType)
			assert.Equal(t, name, desc.Name,
				"descriptor Name should match mechanismNames for 0x%08X", mechType)
		}
	})

	t.Run("descriptor Type field matches map key", func(t *testing.T) {
		for mechType, desc := range v32MechanismRegistry {
			assert.Equal(t, mechType, desc.Type,
				"descriptor Type should match map key for 0x%08X", mechType)
		}
	})
}

func TestV32CategoryConstants(t *testing.T) {

	t.Run("v32 encapsulation categories have expected values", func(t *testing.T) {
		assert.Equal(t, MechanismCategory(10), v32CategoryEncapsulate)
		assert.Equal(t, MechanismCategory(11), v32CategoryDecapsulate)
	})

	t.Run("v32 categories do not collide with standard categories", func(t *testing.T) {
		standardCategories := []MechanismCategory{
			CategoryDigest, CategorySign, CategoryVerify,
			CategoryKeyPairGen,
		}
		for _, cat := range standardCategories {
			assert.NotEqual(t, cat, v32CategoryEncapsulate,
				"v32CategoryEncapsulate should not equal standard category %d", cat)
			assert.NotEqual(t, cat, v32CategoryDecapsulate,
				"v32CategoryDecapsulate should not equal standard category %d", cat)
		}
	})
}

// --- New comprehensive tests for v3.2 additions ---

func TestV32HashMLDSAMechanisms(t *testing.T) {

	type hashMLDSAEntry struct {
		mech MechanismType
		hex  uint32
		name string
	}

	entries := []hashMLDSAEntry{
		{CKM_HASH_ML_DSA, 0x1f, "CKM_HASH_ML_DSA"},
		{CKM_HASH_ML_DSA_SHA224, 0x23, "CKM_HASH_ML_DSA_SHA224"},
		{CKM_HASH_ML_DSA_SHA256, 0x24, "CKM_HASH_ML_DSA_SHA256"},
		{CKM_HASH_ML_DSA_SHA384, 0x25, "CKM_HASH_ML_DSA_SHA384"},
		{CKM_HASH_ML_DSA_SHA512, 0x26, "CKM_HASH_ML_DSA_SHA512"},
		{CKM_HASH_ML_DSA_SHA3_224, 0x27, "CKM_HASH_ML_DSA_SHA3_224"},
		{CKM_HASH_ML_DSA_SHA3_256, 0x28, "CKM_HASH_ML_DSA_SHA3_256"},
		{CKM_HASH_ML_DSA_SHA3_384, 0x29, "CKM_HASH_ML_DSA_SHA3_384"},
		{CKM_HASH_ML_DSA_SHA3_512, 0x2a, "CKM_HASH_ML_DSA_SHA3_512"},
		{CKM_HASH_ML_DSA_SHAKE128, 0x2b, "CKM_HASH_ML_DSA_SHAKE128"},
		{CKM_HASH_ML_DSA_SHAKE256, 0x2c, "CKM_HASH_ML_DSA_SHAKE256"},
	}

	t.Run("constant hex values match PKCS#11 v3.2 spec", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				assert.Equal(t, MechanismType(e.hex), e.mech,
					"%s should have value 0x%02x", e.name, e.hex)
			})
		}
	})

	t.Run("all in standard range not vendor-defined", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				assert.True(t, e.mech < CKM_VENDOR_DEFINED,
					"%s (0x%08X) should be in standard range", e.name, e.mech)
			})
		}
	})

	t.Run("all registered in mechanismRegistry with CKF_SIGN|CKF_VERIFY", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				desc, ok := mechanismRegistry[e.mech]
				require.True(t, ok, "%s should be in global mechanismRegistry", e.name)
				assert.Equal(t, e.mech, desc.Type)
				assert.Equal(t, e.name, desc.Name)
				assert.True(t, desc.Flags&CKF_SIGN != 0,
					"%s should have CKF_SIGN flag", e.name)
				assert.True(t, desc.Flags&CKF_VERIFY != 0,
					"%s should have CKF_VERIFY flag", e.name)
				assert.Contains(t, desc.Categories, CategorySign)
				assert.Contains(t, desc.Categories, CategoryVerify)
			})
		}
	})

	t.Run("all registered in mechanismNames", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				actual, ok := mechanismNames[e.mech]
				require.True(t, ok, "%s should have a name in mechanismNames", e.name)
				assert.Equal(t, e.name, actual)
			})
		}
	})

	t.Run("all map to CKK_ML_DSA in v32KeyTypeMap", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				kt, ok := v32KeyTypeMap[e.mech]
				require.True(t, ok, "%s should be in v32KeyTypeMap", e.name)
				assert.Equal(t, CKK_ML_DSA, kt,
					"%s should map to CKK_ML_DSA", e.name)
			})
		}
	})

	t.Run("CKM_HASH_ML_DSA base variant has multi-part message flags", func(t *testing.T) {
		desc := mechanismRegistry[CKM_HASH_ML_DSA]
		require.NotNil(t, desc)
		assert.True(t, desc.Flags&CKF_MESSAGE_SIGN != 0,
			"CKM_HASH_ML_DSA should have CKF_MESSAGE_SIGN flag")
		assert.True(t, desc.Flags&CKF_MESSAGE_VERIFY != 0,
			"CKM_HASH_ML_DSA should have CKF_MESSAGE_VERIFY flag")
	})

	t.Run("SHA variant mechanisms do not have multi-part message flags", func(t *testing.T) {
		singlePartMechs := []MechanismType{
			CKM_HASH_ML_DSA_SHA224, CKM_HASH_ML_DSA_SHA256,
			CKM_HASH_ML_DSA_SHA384, CKM_HASH_ML_DSA_SHA512,
			CKM_HASH_ML_DSA_SHA3_224, CKM_HASH_ML_DSA_SHA3_256,
			CKM_HASH_ML_DSA_SHA3_384, CKM_HASH_ML_DSA_SHA3_512,
			CKM_HASH_ML_DSA_SHAKE128, CKM_HASH_ML_DSA_SHAKE256,
		}
		for _, mech := range singlePartMechs {
			desc := mechanismRegistry[mech]
			require.NotNil(t, desc, "mechanism 0x%08X descriptor should exist", mech)
			assert.True(t, desc.Flags&CKF_MESSAGE_SIGN == 0,
				"%s should not have CKF_MESSAGE_SIGN flag (single-part only)", desc.Name)
			assert.True(t, desc.Flags&CKF_MESSAGE_VERIFY == 0,
				"%s should not have CKF_MESSAGE_VERIFY flag (single-part only)", desc.Name)
		}
	})

	t.Run("IsV32PQCMechanism returns true for all HashML-DSA mechanisms", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				assert.True(t, IsV32PQCMechanism(e.mech),
					"IsV32PQCMechanism should return true for %s", e.name)
			})
		}
	})

	t.Run("GetV32KeyType returns CKK_ML_DSA for all HashML-DSA mechanisms", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				assert.Equal(t, CKK_ML_DSA, GetV32KeyType(e.mech),
					"GetV32KeyType should return CKK_ML_DSA for %s", e.name)
			})
		}
	})
}

func TestV32HashSLHDSAMechanisms(t *testing.T) {

	type hashSLHDSAEntry struct {
		mech MechanismType
		hex  uint32
		name string
	}

	entries := []hashSLHDSAEntry{
		{CKM_HASH_SLH_DSA, 0x34, "CKM_HASH_SLH_DSA"},
		{CKM_HASH_SLH_DSA_SHA224, 0x36, "CKM_HASH_SLH_DSA_SHA224"},
		{CKM_HASH_SLH_DSA_SHA256, 0x37, "CKM_HASH_SLH_DSA_SHA256"},
		{CKM_HASH_SLH_DSA_SHA384, 0x38, "CKM_HASH_SLH_DSA_SHA384"},
		{CKM_HASH_SLH_DSA_SHA512, 0x39, "CKM_HASH_SLH_DSA_SHA512"},
		{CKM_HASH_SLH_DSA_SHA3_224, 0x3a, "CKM_HASH_SLH_DSA_SHA3_224"},
		{CKM_HASH_SLH_DSA_SHA3_256, 0x3b, "CKM_HASH_SLH_DSA_SHA3_256"},
		{CKM_HASH_SLH_DSA_SHA3_384, 0x3c, "CKM_HASH_SLH_DSA_SHA3_384"},
		{CKM_HASH_SLH_DSA_SHA3_512, 0x3d, "CKM_HASH_SLH_DSA_SHA3_512"},
		{CKM_HASH_SLH_DSA_SHAKE128, 0x3e, "CKM_HASH_SLH_DSA_SHAKE128"},
		{CKM_HASH_SLH_DSA_SHAKE256, 0x3f, "CKM_HASH_SLH_DSA_SHAKE256"},
	}

	t.Run("constant hex values match PKCS#11 v3.2 spec", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				assert.Equal(t, MechanismType(e.hex), e.mech,
					"%s should have value 0x%02x", e.name, e.hex)
			})
		}
	})

	t.Run("all in standard range not vendor-defined", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				assert.True(t, e.mech < CKM_VENDOR_DEFINED,
					"%s (0x%08X) should be in standard range", e.name, e.mech)
			})
		}
	})

	t.Run("all registered in mechanismRegistry with CKF_SIGN|CKF_VERIFY", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				desc, ok := mechanismRegistry[e.mech]
				require.True(t, ok, "%s should be in global mechanismRegistry", e.name)
				assert.Equal(t, e.mech, desc.Type)
				assert.Equal(t, e.name, desc.Name)
				assert.True(t, desc.Flags&CKF_SIGN != 0,
					"%s should have CKF_SIGN flag", e.name)
				assert.True(t, desc.Flags&CKF_VERIFY != 0,
					"%s should have CKF_VERIFY flag", e.name)
				assert.Contains(t, desc.Categories, CategorySign)
				assert.Contains(t, desc.Categories, CategoryVerify)
			})
		}
	})

	t.Run("all registered in mechanismNames", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				actual, ok := mechanismNames[e.mech]
				require.True(t, ok, "%s should have a name in mechanismNames", e.name)
				assert.Equal(t, e.name, actual)
			})
		}
	})

	t.Run("all map to CKK_SLH_DSA in v32KeyTypeMap", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				kt, ok := v32KeyTypeMap[e.mech]
				require.True(t, ok, "%s should be in v32KeyTypeMap", e.name)
				assert.Equal(t, CKK_SLH_DSA, kt,
					"%s should map to CKK_SLH_DSA", e.name)
			})
		}
	})

	t.Run("CKM_HASH_SLH_DSA base variant has multi-part message flags", func(t *testing.T) {
		desc := mechanismRegistry[CKM_HASH_SLH_DSA]
		require.NotNil(t, desc)
		assert.True(t, desc.Flags&CKF_MESSAGE_SIGN != 0,
			"CKM_HASH_SLH_DSA should have CKF_MESSAGE_SIGN flag")
		assert.True(t, desc.Flags&CKF_MESSAGE_VERIFY != 0,
			"CKM_HASH_SLH_DSA should have CKF_MESSAGE_VERIFY flag")
	})

	t.Run("SHA variant mechanisms do not have multi-part message flags", func(t *testing.T) {
		singlePartMechs := []MechanismType{
			CKM_HASH_SLH_DSA_SHA224, CKM_HASH_SLH_DSA_SHA256,
			CKM_HASH_SLH_DSA_SHA384, CKM_HASH_SLH_DSA_SHA512,
			CKM_HASH_SLH_DSA_SHA3_224, CKM_HASH_SLH_DSA_SHA3_256,
			CKM_HASH_SLH_DSA_SHA3_384, CKM_HASH_SLH_DSA_SHA3_512,
			CKM_HASH_SLH_DSA_SHAKE128, CKM_HASH_SLH_DSA_SHAKE256,
		}
		for _, mech := range singlePartMechs {
			desc := mechanismRegistry[mech]
			require.NotNil(t, desc, "mechanism 0x%08X descriptor should exist", mech)
			assert.True(t, desc.Flags&CKF_MESSAGE_SIGN == 0,
				"%s should not have CKF_MESSAGE_SIGN flag (single-part only)", desc.Name)
			assert.True(t, desc.Flags&CKF_MESSAGE_VERIFY == 0,
				"%s should not have CKF_MESSAGE_VERIFY flag (single-part only)", desc.Name)
		}
	})

	t.Run("IsV32PQCMechanism returns true for all HashSLH-DSA mechanisms", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				assert.True(t, IsV32PQCMechanism(e.mech),
					"IsV32PQCMechanism should return true for %s", e.name)
			})
		}
	})

	t.Run("GetV32KeyType returns CKK_SLH_DSA for all HashSLH-DSA mechanisms", func(t *testing.T) {
		for _, e := range entries {
			t.Run(e.name, func(t *testing.T) {
				assert.Equal(t, CKK_SLH_DSA, GetV32KeyType(e.mech),
					"GetV32KeyType should return CKK_SLH_DSA for %s", e.name)
			})
		}
	})
}

func TestV32AdditionalMechanisms(t *testing.T) {

	t.Run("ECDH key wrap mechanism constants", func(t *testing.T) {
		t.Run("CKM_ECDH_X_AES_KEY_WRAP has correct hex value", func(t *testing.T) {
			assert.Equal(t, MechanismType(0x4038), CKM_ECDH_X_AES_KEY_WRAP)
			assert.True(t, CKM_ECDH_X_AES_KEY_WRAP < CKM_VENDOR_DEFINED,
				"CKM_ECDH_X_AES_KEY_WRAP should be in standard range")
		})

		t.Run("CKM_ECDH_COF_AES_KEY_WRAP has correct hex value", func(t *testing.T) {
			assert.Equal(t, MechanismType(0x4039), CKM_ECDH_COF_AES_KEY_WRAP)
			assert.True(t, CKM_ECDH_COF_AES_KEY_WRAP < CKM_VENDOR_DEFINED,
				"CKM_ECDH_COF_AES_KEY_WRAP should be in standard range")
		})
	})

	t.Run("CKM_PUB_KEY_FROM_PRIV_KEY has correct hex value", func(t *testing.T) {
		assert.Equal(t, MechanismType(0x403a), CKM_PUB_KEY_FROM_PRIV_KEY)
		assert.True(t, CKM_PUB_KEY_FROM_PRIV_KEY < CKM_VENDOR_DEFINED,
			"CKM_PUB_KEY_FROM_PRIV_KEY should be in standard range")
	})

	t.Run("TLS 1.2 extended master key mechanisms have correct hex values", func(t *testing.T) {
		t.Run("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE", func(t *testing.T) {
			assert.Equal(t, MechanismType(0x56), CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE)
			assert.True(t, CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE < CKM_VENDOR_DEFINED,
				"CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE should be in standard range")
		})

		t.Run("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH", func(t *testing.T) {
			assert.Equal(t, MechanismType(0x57), CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH)
			assert.True(t, CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH < CKM_VENDOR_DEFINED,
				"CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH should be in standard range")
		})
	})

	t.Run("ECDH key wrap mechanisms registered with CKF_WRAP|CKF_UNWRAP", func(t *testing.T) {
		wrapMechs := []struct {
			mech MechanismType
			name string
		}{
			{CKM_ECDH_X_AES_KEY_WRAP, "CKM_ECDH_X_AES_KEY_WRAP"},
			{CKM_ECDH_COF_AES_KEY_WRAP, "CKM_ECDH_COF_AES_KEY_WRAP"},
		}
		for _, wm := range wrapMechs {
			t.Run(wm.name, func(t *testing.T) {
				desc, ok := mechanismRegistry[wm.mech]
				require.True(t, ok, "%s should be in mechanismRegistry", wm.name)
				assert.Equal(t, wm.name, desc.Name)
				assert.True(t, desc.Flags&CKF_WRAP != 0,
					"%s should have CKF_WRAP flag", wm.name)
				assert.True(t, desc.Flags&CKF_UNWRAP != 0,
					"%s should have CKF_UNWRAP flag", wm.name)
				assert.Contains(t, desc.Categories, CategoryWrap)
				assert.Contains(t, desc.Categories, CategoryUnwrap)
			})
		}
	})

	t.Run("ECDH key wrap mechanisms map to CKK_EC in v32KeyTypeMap", func(t *testing.T) {
		t.Run("CKM_ECDH_X_AES_KEY_WRAP maps to CKK_EC", func(t *testing.T) {
			kt, ok := v32KeyTypeMap[CKM_ECDH_X_AES_KEY_WRAP]
			require.True(t, ok, "CKM_ECDH_X_AES_KEY_WRAP should be in v32KeyTypeMap")
			assert.Equal(t, CKK_EC, kt)
		})

		t.Run("CKM_ECDH_COF_AES_KEY_WRAP maps to CKK_EC", func(t *testing.T) {
			kt, ok := v32KeyTypeMap[CKM_ECDH_COF_AES_KEY_WRAP]
			require.True(t, ok, "CKM_ECDH_COF_AES_KEY_WRAP should be in v32KeyTypeMap")
			assert.Equal(t, CKK_EC, kt)
		})
	})

	t.Run("TLS 1.2 extended master key mechanisms registered with CKF_DERIVE", func(t *testing.T) {
		tlsMechs := []struct {
			mech MechanismType
			name string
		}{
			{CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE, "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE"},
			{CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH, "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH"},
		}
		for _, tm := range tlsMechs {
			t.Run(tm.name, func(t *testing.T) {
				desc, ok := mechanismRegistry[tm.mech]
				require.True(t, ok, "%s should be in mechanismRegistry", tm.name)
				assert.Equal(t, tm.name, desc.Name)
				assert.True(t, desc.Flags&CKF_DERIVE != 0,
					"%s should have CKF_DERIVE flag", tm.name)
				assert.Contains(t, desc.Categories, CategoryDerive)
			})
		}
	})

	t.Run("CKM_PUB_KEY_FROM_PRIV_KEY registered with CKF_DERIVE", func(t *testing.T) {
		desc, ok := mechanismRegistry[CKM_PUB_KEY_FROM_PRIV_KEY]
		require.True(t, ok, "CKM_PUB_KEY_FROM_PRIV_KEY should be in mechanismRegistry")
		assert.Equal(t, "CKM_PUB_KEY_FROM_PRIV_KEY", desc.Name)
		assert.True(t, desc.Flags&CKF_DERIVE != 0,
			"CKM_PUB_KEY_FROM_PRIV_KEY should have CKF_DERIVE flag")
		assert.Contains(t, desc.Categories, CategoryDerive)
	})

	t.Run("CKM_PUB_KEY_FROM_PRIV_KEY not in v32KeyTypeMap (algorithm-agnostic)", func(t *testing.T) {
		_, ok := v32KeyTypeMap[CKM_PUB_KEY_FROM_PRIV_KEY]
		assert.False(t, ok,
			"CKM_PUB_KEY_FROM_PRIV_KEY should not be in v32KeyTypeMap since it is algorithm-agnostic")
	})

	t.Run("additional mechanisms registered in mechanismNames", func(t *testing.T) {
		expected := map[MechanismType]string{
			CKM_ECDH_X_AES_KEY_WRAP:                 "CKM_ECDH_X_AES_KEY_WRAP",
			CKM_ECDH_COF_AES_KEY_WRAP:               "CKM_ECDH_COF_AES_KEY_WRAP",
			CKM_PUB_KEY_FROM_PRIV_KEY:               "CKM_PUB_KEY_FROM_PRIV_KEY",
			CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE:    "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE",
			CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH: "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH",
		}
		for mech, name := range expected {
			t.Run(name, func(t *testing.T) {
				actual, ok := mechanismNames[mech]
				require.True(t, ok, "%s should have a name in mechanismNames", name)
				assert.Equal(t, name, actual)
			})
		}
	})
}

func TestV32NewAttributeConstants(t *testing.T) {

	t.Run("HSS attributes have correct hex values", func(t *testing.T) {
		hssAttrs := []struct {
			attr AttributeType
			hex  uint32
			name string
		}{
			{CKA_HSS_LEVELS, 0x617, "CKA_HSS_LEVELS"},
			{CKA_HSS_LMS_TYPE, 0x618, "CKA_HSS_LMS_TYPE"},
			{CKA_HSS_LMOTS_TYPE, 0x619, "CKA_HSS_LMOTS_TYPE"},
			{CKA_HSS_LMS_TYPES, 0x61A, "CKA_HSS_LMS_TYPES"},
			{CKA_HSS_LMOTS_TYPES, 0x61B, "CKA_HSS_LMOTS_TYPES"},
			{CKA_HSS_KEYS_REMAINING, 0x61C, "CKA_HSS_KEYS_REMAINING"},
		}
		for _, a := range hssAttrs {
			t.Run(a.name, func(t *testing.T) {
				assert.Equal(t, AttributeType(a.hex), a.attr,
					"%s should have value 0x%03x", a.name, a.hex)
				assert.True(t, a.attr < CKA_VENDOR_DEFINED,
					"%s should be in standard range", a.name)
			})
		}
	})

	t.Run("PQC parameter and validation attributes have correct hex values", func(t *testing.T) {
		validationAttrs := []struct {
			attr AttributeType
			hex  uint32
			name string
		}{
			{CKA_PARAMETER_SET, 0x61D, "CKA_PARAMETER_SET"},
			{CKA_OBJECT_VALIDATION_FLAGS, 0x61E, "CKA_OBJECT_VALIDATION_FLAGS"},
			{CKA_VALIDATION_TYPE, 0x61F, "CKA_VALIDATION_TYPE"},
			{CKA_VALIDATION_VERSION, 0x620, "CKA_VALIDATION_VERSION"},
			{CKA_VALIDATION_LEVEL, 0x621, "CKA_VALIDATION_LEVEL"},
			{CKA_VALIDATION_MODULE_ID, 0x622, "CKA_VALIDATION_MODULE_ID"},
			{CKA_VALIDATION_FLAG, 0x623, "CKA_VALIDATION_FLAG"},
			{CKA_VALIDATION_AUTHORITY_TYPE, 0x624, "CKA_VALIDATION_AUTHORITY_TYPE"},
			{CKA_VALIDATION_COUNTRY, 0x625, "CKA_VALIDATION_COUNTRY"},
			{CKA_VALIDATION_CERTIFICATE_IDENTIFIER, 0x626, "CKA_VALIDATION_CERTIFICATE_IDENTIFIER"},
			{CKA_VALIDATION_CERTIFICATE_URI, 0x627, "CKA_VALIDATION_CERTIFICATE_URI"},
			{CKA_VALIDATION_VENDOR_URI, 0x628, "CKA_VALIDATION_VENDOR_URI"},
			{CKA_VALIDATION_PROFILE, 0x629, "CKA_VALIDATION_PROFILE"},
		}
		for _, a := range validationAttrs {
			t.Run(a.name, func(t *testing.T) {
				assert.Equal(t, AttributeType(a.hex), a.attr,
					"%s should have value 0x%03x", a.name, a.hex)
				assert.True(t, a.attr < CKA_VENDOR_DEFINED,
					"%s should be in standard range", a.name)
			})
		}
	})

	t.Run("KEM template attributes have correct hex values with CKF_ARRAY_ATTRIBUTE", func(t *testing.T) {
		t.Run("CKA_ENCAPSULATE_TEMPLATE", func(t *testing.T) {
			assert.Equal(t, AttributeType(0x4000062A), CKA_ENCAPSULATE_TEMPLATE)
			assert.True(t, CKA_ENCAPSULATE_TEMPLATE < CKA_VENDOR_DEFINED)
		})

		t.Run("CKA_DECAPSULATE_TEMPLATE", func(t *testing.T) {
			assert.Equal(t, AttributeType(0x4000062B), CKA_DECAPSULATE_TEMPLATE)
			assert.True(t, CKA_DECAPSULATE_TEMPLATE < CKA_VENDOR_DEFINED)
		})
	})

	t.Run("trust attributes have correct hex values", func(t *testing.T) {
		trustAttrs := []struct {
			attr AttributeType
			hex  uint32
			name string
		}{
			{CKA_TRUST_SERVER_AUTH, 0x62C, "CKA_TRUST_SERVER_AUTH"},
			{CKA_TRUST_CLIENT_AUTH, 0x62D, "CKA_TRUST_CLIENT_AUTH"},
			{CKA_TRUST_CODE_SIGNING, 0x62E, "CKA_TRUST_CODE_SIGNING"},
			{CKA_TRUST_EMAIL_PROTECTION, 0x62F, "CKA_TRUST_EMAIL_PROTECTION"},
			{CKA_TRUST_IPSEC_IKE, 0x630, "CKA_TRUST_IPSEC_IKE"},
			{CKA_TRUST_TIME_STAMPING, 0x631, "CKA_TRUST_TIME_STAMPING"},
			{CKA_TRUST_OCSP_SIGNING, 0x632, "CKA_TRUST_OCSP_SIGNING"},
		}
		for _, a := range trustAttrs {
			t.Run(a.name, func(t *testing.T) {
				assert.Equal(t, AttributeType(a.hex), a.attr,
					"%s should have value 0x%03x", a.name, a.hex)
				assert.True(t, a.attr < CKA_VENDOR_DEFINED,
					"%s should be in standard range", a.name)
			})
		}
	})

	t.Run("KEM and PQC operational attributes have correct hex values", func(t *testing.T) {
		kemAttrs := []struct {
			attr AttributeType
			hex  uint32
			name string
		}{
			{CKA_ENCAPSULATE, 0x633, "CKA_ENCAPSULATE"},
			{CKA_DECAPSULATE, 0x634, "CKA_DECAPSULATE"},
			{CKA_HASH_OF_CERTIFICATE, 0x635, "CKA_HASH_OF_CERTIFICATE"},
			{CKA_PUBLIC_CRC64_VALUE, 0x636, "CKA_PUBLIC_CRC64_VALUE"},
			{CKA_SEED, 0x637, "CKA_SEED"},
		}
		for _, a := range kemAttrs {
			t.Run(a.name, func(t *testing.T) {
				assert.Equal(t, AttributeType(a.hex), a.attr,
					"%s should have value 0x%03x", a.name, a.hex)
				assert.True(t, a.attr < CKA_VENDOR_DEFINED,
					"%s should be in standard range", a.name)
			})
		}
	})

	t.Run("all v3.2 attributes registered in attributeTypeNames", func(t *testing.T) {
		v32Attrs := map[AttributeType]string{
			// HSS attributes
			CKA_HSS_LEVELS:         "CKA_HSS_LEVELS",
			CKA_HSS_LMS_TYPE:       "CKA_HSS_LMS_TYPE",
			CKA_HSS_LMOTS_TYPE:     "CKA_HSS_LMOTS_TYPE",
			CKA_HSS_LMS_TYPES:      "CKA_HSS_LMS_TYPES",
			CKA_HSS_LMOTS_TYPES:    "CKA_HSS_LMOTS_TYPES",
			CKA_HSS_KEYS_REMAINING: "CKA_HSS_KEYS_REMAINING",
			// Parameter and validation attributes
			CKA_PARAMETER_SET:                     "CKA_PARAMETER_SET",
			CKA_OBJECT_VALIDATION_FLAGS:           "CKA_OBJECT_VALIDATION_FLAGS",
			CKA_VALIDATION_TYPE:                   "CKA_VALIDATION_TYPE",
			CKA_VALIDATION_VERSION:                "CKA_VALIDATION_VERSION",
			CKA_VALIDATION_LEVEL:                  "CKA_VALIDATION_LEVEL",
			CKA_VALIDATION_MODULE_ID:              "CKA_VALIDATION_MODULE_ID",
			CKA_VALIDATION_FLAG:                   "CKA_VALIDATION_FLAG",
			CKA_VALIDATION_AUTHORITY_TYPE:         "CKA_VALIDATION_AUTHORITY_TYPE",
			CKA_VALIDATION_COUNTRY:                "CKA_VALIDATION_COUNTRY",
			CKA_VALIDATION_CERTIFICATE_IDENTIFIER: "CKA_VALIDATION_CERTIFICATE_IDENTIFIER",
			CKA_VALIDATION_CERTIFICATE_URI:        "CKA_VALIDATION_CERTIFICATE_URI",
			CKA_VALIDATION_VENDOR_URI:             "CKA_VALIDATION_VENDOR_URI",
			CKA_VALIDATION_PROFILE:                "CKA_VALIDATION_PROFILE",
			// KEM template attributes
			CKA_ENCAPSULATE_TEMPLATE: "CKA_ENCAPSULATE_TEMPLATE",
			CKA_DECAPSULATE_TEMPLATE: "CKA_DECAPSULATE_TEMPLATE",
			// Trust attributes
			CKA_TRUST_SERVER_AUTH:      "CKA_TRUST_SERVER_AUTH",
			CKA_TRUST_CLIENT_AUTH:      "CKA_TRUST_CLIENT_AUTH",
			CKA_TRUST_CODE_SIGNING:     "CKA_TRUST_CODE_SIGNING",
			CKA_TRUST_EMAIL_PROTECTION: "CKA_TRUST_EMAIL_PROTECTION",
			CKA_TRUST_IPSEC_IKE:        "CKA_TRUST_IPSEC_IKE",
			CKA_TRUST_TIME_STAMPING:    "CKA_TRUST_TIME_STAMPING",
			CKA_TRUST_OCSP_SIGNING:     "CKA_TRUST_OCSP_SIGNING",
			// KEM and PQC attributes
			CKA_ENCAPSULATE:         "CKA_ENCAPSULATE",
			CKA_DECAPSULATE:         "CKA_DECAPSULATE",
			CKA_HASH_OF_CERTIFICATE: "CKA_HASH_OF_CERTIFICATE",
			CKA_PUBLIC_CRC64_VALUE:  "CKA_PUBLIC_CRC64_VALUE",
			CKA_SEED:                "CKA_SEED",
		}
		for attr, expectedName := range v32Attrs {
			t.Run(expectedName, func(t *testing.T) {
				actual, ok := attributeTypeNames[attr]
				require.True(t, ok,
					"%s (0x%03X) should be in attributeTypeNames", expectedName, uint32(attr))
				assert.Equal(t, expectedName, actual)
			})
		}
	})

	t.Run("v3.2 attribute String() method returns correct names", func(t *testing.T) {
		// Spot check a few v3.2 attributes
		assert.Equal(t, "CKA_ENCAPSULATE", CKA_ENCAPSULATE.String())
		assert.Equal(t, "CKA_DECAPSULATE", CKA_DECAPSULATE.String())
		assert.Equal(t, "CKA_PARAMETER_SET", CKA_PARAMETER_SET.String())
		assert.Equal(t, "CKA_SEED", CKA_SEED.String())
		assert.Equal(t, "CKA_HSS_LEVELS", CKA_HSS_LEVELS.String())
		assert.Equal(t, "CKA_TRUST_SERVER_AUTH", CKA_TRUST_SERVER_AUTH.String())
		assert.Equal(t, "CKA_VALIDATION_TYPE", CKA_VALIDATION_TYPE.String())
	})

	t.Run("v3.2 attributes form contiguous range 0x617-0x637", func(t *testing.T) {
		// Verify the lowest and highest v3.2-specific attributes bound the range
		assert.Equal(t, AttributeType(0x617), CKA_HSS_LEVELS, "first v3.2 attr should be 0x617")
		assert.Equal(t, AttributeType(0x637), CKA_SEED, "last v3.2 attr should be 0x637")
	})
}

func TestV32NewErrorCodes(t *testing.T) {

	t.Run("error code constants have correct hex values", func(t *testing.T) {
		v32Errors := []struct {
			code CK_RV
			hex  uint32
			name string
		}{
			{CKR_PENDING, 0x204, "CKR_PENDING"},
			{CKR_SESSION_ASYNC_NOT_SUPPORTED, 0x205, "CKR_SESSION_ASYNC_NOT_SUPPORTED"},
			{CKR_SEED_RANDOM_REQUIRED, 0x206, "CKR_SEED_RANDOM_REQUIRED"},
			{CKR_OPERATION_NOT_VALIDATED, 0x207, "CKR_OPERATION_NOT_VALIDATED"},
			{CKR_PARAMETER_SET_NOT_SUPPORTED, 0x209, "CKR_PARAMETER_SET_NOT_SUPPORTED"},
		}
		for _, e := range v32Errors {
			t.Run(e.name, func(t *testing.T) {
				assert.Equal(t, CK_RV(e.hex), e.code,
					"%s should have value 0x%03x", e.name, e.hex)
				assert.True(t, e.code < CKR_VENDOR_DEFINED,
					"%s should be in standard range", e.name)
			})
		}
	})

	t.Run("error codes registered in ckrNames", func(t *testing.T) {
		expected := map[CK_RV]string{
			CKR_PENDING:                     "CKR_PENDING",
			CKR_SESSION_ASYNC_NOT_SUPPORTED: "CKR_SESSION_ASYNC_NOT_SUPPORTED",
			CKR_SEED_RANDOM_REQUIRED:        "CKR_SEED_RANDOM_REQUIRED",
			CKR_OPERATION_NOT_VALIDATED:     "CKR_OPERATION_NOT_VALIDATED",
			CKR_PARAMETER_SET_NOT_SUPPORTED: "CKR_PARAMETER_SET_NOT_SUPPORTED",
		}
		for code, name := range expected {
			t.Run(name, func(t *testing.T) {
				actual, ok := ckrNames[code]
				require.True(t, ok, "%s should be in ckrNames map", name)
				assert.Equal(t, name, actual)
			})
		}
	})

	t.Run("CK_RV String() returns correct names for v3.2 error codes", func(t *testing.T) {
		assert.Equal(t, "CKR_PENDING", CKR_PENDING.String())
		assert.Equal(t, "CKR_SESSION_ASYNC_NOT_SUPPORTED", CKR_SESSION_ASYNC_NOT_SUPPORTED.String())
		assert.Equal(t, "CKR_SEED_RANDOM_REQUIRED", CKR_SEED_RANDOM_REQUIRED.String())
		assert.Equal(t, "CKR_OPERATION_NOT_VALIDATED", CKR_OPERATION_NOT_VALIDATED.String())
		assert.Equal(t, "CKR_PARAMETER_SET_NOT_SUPPORTED", CKR_PARAMETER_SET_NOT_SUPPORTED.String())
	})

	t.Run("sentinel errors exist for v3.2 error codes", func(t *testing.T) {
		sentinels := []struct {
			sentinel error
			name     string
		}{
			{ErrPending, "ErrPending"},
			{ErrSessionAsyncNotSupported, "ErrSessionAsyncNotSupported"},
			{ErrSeedRandomRequired, "ErrSeedRandomRequired"},
			{ErrOperationNotValidated, "ErrOperationNotValidated"},
			{ErrParameterSetNotSupported, "ErrParameterSetNotSupported"},
		}
		for _, s := range sentinels {
			t.Run(s.name, func(t *testing.T) {
				require.NotNil(t, s.sentinel, "%s should not be nil", s.name)
				assert.NotEmpty(t, s.sentinel.Error(), "%s should have a message", s.name)
			})
		}
	})

	t.Run("sentinelErrors map contains v3.2 error codes", func(t *testing.T) {
		expected := map[CK_RV]error{
			CKR_PENDING:                     ErrPending,
			CKR_SESSION_ASYNC_NOT_SUPPORTED: ErrSessionAsyncNotSupported,
			CKR_SEED_RANDOM_REQUIRED:        ErrSeedRandomRequired,
			CKR_OPERATION_NOT_VALIDATED:     ErrOperationNotValidated,
			CKR_PARAMETER_SET_NOT_SUPPORTED: ErrParameterSetNotSupported,
		}
		for code, expectedSentinel := range expected {
			t.Run(fmt.Sprintf("CKR_%03X", uint32(code)), func(t *testing.T) {
				actual, ok := sentinelErrors[code]
				require.True(t, ok, "sentinelErrors should contain 0x%03X", uint32(code))
				assert.Equal(t, expectedSentinel, actual)
			})
		}
	})

	t.Run("errorToCKR roundtrip for v3.2 sentinel errors", func(t *testing.T) {
		pairs := []struct {
			sentinel error
			code     CK_RV
			name     string
		}{
			{ErrPending, CKR_PENDING, "ErrPending"},
			{ErrSessionAsyncNotSupported, CKR_SESSION_ASYNC_NOT_SUPPORTED, "ErrSessionAsyncNotSupported"},
			{ErrSeedRandomRequired, CKR_SEED_RANDOM_REQUIRED, "ErrSeedRandomRequired"},
			{ErrOperationNotValidated, CKR_OPERATION_NOT_VALIDATED, "ErrOperationNotValidated"},
			{ErrParameterSetNotSupported, CKR_PARAMETER_SET_NOT_SUPPORTED, "ErrParameterSetNotSupported"},
		}
		for _, p := range pairs {
			t.Run(p.name+"_to_CKR", func(t *testing.T) {
				actual, ok := errorToCKR[p.sentinel]
				require.True(t, ok, "%s should be in errorToCKR", p.name)
				assert.Equal(t, p.code, actual,
					"%s should map to 0x%03X", p.name, uint32(p.code))
			})

			t.Run(p.name+"_from_CKR", func(t *testing.T) {
				actualSentinel, ok := sentinelErrors[p.code]
				require.True(t, ok, "code 0x%03X should be in sentinelErrors", uint32(p.code))
				assert.Equal(t, p.sentinel, actualSentinel)
			})
		}
	})

	t.Run("FromError resolves v3.2 sentinel errors to CK_RV", func(t *testing.T) {
		assert.Equal(t, CKR_PENDING, FromError(ErrPending))
		assert.Equal(t, CKR_SESSION_ASYNC_NOT_SUPPORTED, FromError(ErrSessionAsyncNotSupported))
		assert.Equal(t, CKR_SEED_RANDOM_REQUIRED, FromError(ErrSeedRandomRequired))
		assert.Equal(t, CKR_OPERATION_NOT_VALIDATED, FromError(ErrOperationNotValidated))
		assert.Equal(t, CKR_PARAMETER_SET_NOT_SUPPORTED, FromError(ErrParameterSetNotSupported))
	})

	t.Run("PKCS11Error with v3.2 codes works correctly", func(t *testing.T) {
		codes := []CK_RV{
			CKR_PENDING,
			CKR_SESSION_ASYNC_NOT_SUPPORTED,
			CKR_SEED_RANDOM_REQUIRED,
			CKR_OPERATION_NOT_VALIDATED,
			CKR_PARAMETER_SET_NOT_SUPPORTED,
		}
		for _, code := range codes {
			t.Run(code.String(), func(t *testing.T) {
				err := NewPKCS11Error(code)
				assert.Equal(t, code, err.Code)
				assert.Contains(t, err.Error(), code.String())

				// FromError on PKCS11Error returns the code directly
				assert.Equal(t, code, FromError(err))

				// IsPKCS11Error should detect it
				resolvedCode, ok := IsPKCS11Error(err)
				assert.True(t, ok)
				assert.Equal(t, code, resolvedCode)
			})
		}
	})

	t.Run("PKCS11Error.Is matches same code", func(t *testing.T) {
		err1 := NewPKCS11Error(CKR_PENDING)
		err2 := NewPKCS11Error(CKR_PENDING)
		assert.True(t, errors.Is(err1, err2))

		err3 := NewPKCS11Error(CKR_SEED_RANDOM_REQUIRED)
		assert.False(t, errors.Is(err1, err3))
	})

	t.Run("ToError returns nil for CKR_OK and PKCS11Error for v3.2 codes", func(t *testing.T) {
		assert.Nil(t, ToError(CKR_OK))

		for _, code := range []CK_RV{
			CKR_PENDING, CKR_SESSION_ASYNC_NOT_SUPPORTED,
			CKR_SEED_RANDOM_REQUIRED, CKR_OPERATION_NOT_VALIDATED,
			CKR_PARAMETER_SET_NOT_SUPPORTED,
		} {
			t.Run(code.String(), func(t *testing.T) {
				err := ToError(code)
				require.NotNil(t, err)
				var pkcs11Err *PKCS11Error
				require.True(t, errors.As(err, &pkcs11Err))
				assert.Equal(t, code, pkcs11Err.Code)
			})
		}
	})
}

func TestV32IsAsyncError(t *testing.T) {

	t.Run("returns true for async-related errors", func(t *testing.T) {
		asyncErrors := []struct {
			sentinel error
			name     string
		}{
			{ErrPending, "ErrPending"},
			{ErrSessionAsyncNotSupported, "ErrSessionAsyncNotSupported"},
			{ErrOperationCancelFailed, "ErrOperationCancelFailed"},
		}
		for _, ae := range asyncErrors {
			t.Run(ae.name, func(t *testing.T) {
				assert.True(t, IsAsyncError(ae.sentinel),
					"IsAsyncError should return true for %s", ae.name)
			})
		}
	})

	t.Run("returns true for PKCS11Error with async codes", func(t *testing.T) {
		asyncCodes := []CK_RV{
			CKR_PENDING,
			CKR_SESSION_ASYNC_NOT_SUPPORTED,
			CKR_OPERATION_CANCEL_FAILED,
		}
		for _, code := range asyncCodes {
			t.Run(code.String(), func(t *testing.T) {
				err := NewPKCS11Error(code)
				assert.True(t, IsAsyncError(err),
					"IsAsyncError should return true for PKCS11Error with %s", code.String())
			})
		}
	})

	t.Run("returns false for non-async errors", func(t *testing.T) {
		nonAsyncErrors := []struct {
			sentinel error
			name     string
		}{
			{ErrGeneralError, "ErrGeneralError"},
			{ErrMechanismInvalid, "ErrMechanismInvalid"},
			{ErrPINIncorrect, "ErrPINIncorrect"},
			{ErrOperationNotValidated, "ErrOperationNotValidated"},
			{ErrSeedRandomRequired, "ErrSeedRandomRequired"},
		}
		for _, ne := range nonAsyncErrors {
			t.Run(ne.name, func(t *testing.T) {
				assert.False(t, IsAsyncError(ne.sentinel),
					"IsAsyncError should return false for %s", ne.name)
			})
		}
	})
}

func TestV32IsValidationError(t *testing.T) {

	t.Run("returns true for validation-related errors", func(t *testing.T) {
		validationErrors := []struct {
			sentinel error
			name     string
		}{
			{ErrOperationNotValidated, "ErrOperationNotValidated"},
			{ErrParameterSetNotSupported, "ErrParameterSetNotSupported"},
		}
		for _, ve := range validationErrors {
			t.Run(ve.name, func(t *testing.T) {
				assert.True(t, IsValidationError(ve.sentinel),
					"IsValidationError should return true for %s", ve.name)
			})
		}
	})

	t.Run("returns true for PKCS11Error with validation codes", func(t *testing.T) {
		validationCodes := []CK_RV{
			CKR_OPERATION_NOT_VALIDATED,
			CKR_PARAMETER_SET_NOT_SUPPORTED,
		}
		for _, code := range validationCodes {
			t.Run(code.String(), func(t *testing.T) {
				err := NewPKCS11Error(code)
				assert.True(t, IsValidationError(err),
					"IsValidationError should return true for PKCS11Error with %s", code.String())
			})
		}
	})

	t.Run("returns false for non-validation errors", func(t *testing.T) {
		nonValidationErrors := []struct {
			sentinel error
			name     string
		}{
			{ErrGeneralError, "ErrGeneralError"},
			{ErrPending, "ErrPending"},
			{ErrSessionAsyncNotSupported, "ErrSessionAsyncNotSupported"},
			{ErrMechanismInvalid, "ErrMechanismInvalid"},
			{ErrKeyExhausted, "ErrKeyExhausted"},
			{ErrSeedRandomRequired, "ErrSeedRandomRequired"},
		}
		for _, ne := range nonValidationErrors {
			t.Run(ne.name, func(t *testing.T) {
				assert.False(t, IsValidationError(ne.sentinel),
					"IsValidationError should return false for %s", ne.name)
			})
		}
	})
}

func TestV32IsSessionError_IncludesAsyncSession(t *testing.T) {
	t.Run("CKR_SESSION_ASYNC_NOT_SUPPORTED classified as session error", func(t *testing.T) {
		assert.True(t, IsSessionError(ErrSessionAsyncNotSupported),
			"IsSessionError should return true for ErrSessionAsyncNotSupported")
	})

	t.Run("CKR_SESSION_ASYNC_NOT_SUPPORTED via PKCS11Error classified as session error", func(t *testing.T) {
		err := NewPKCS11Error(CKR_SESSION_ASYNC_NOT_SUPPORTED)
		assert.True(t, IsSessionError(err),
			"IsSessionError should return true for PKCS11Error with CKR_SESSION_ASYNC_NOT_SUPPORTED")
	})
}

func TestV32NewFlags(t *testing.T) {

	t.Run("CKF_FIND_OBJECTS has correct value", func(t *testing.T) {
		assert.Equal(t, MechanismFlag(0x40), CKF_FIND_OBJECTS)
	})

	t.Run("CKF_FIND_OBJECTS is a MechanismFlag type", func(t *testing.T) {
		// Verify it can be used in bitwise operations with other MechanismFlag values
		combined := CKF_SIGN | CKF_FIND_OBJECTS
		assert.True(t, combined&CKF_FIND_OBJECTS != 0)
		assert.True(t, combined&CKF_SIGN != 0)
	})

	t.Run("CKF_FIND_OBJECTS does not collide with existing mechanism flags", func(t *testing.T) {
		existingFlags := []struct {
			flag MechanismFlag
			name string
		}{
			{CKF_HW, "CKF_HW"},
			{CKF_MESSAGE_ENCRYPT, "CKF_MESSAGE_ENCRYPT"},
			{CKF_MESSAGE_DECRYPT, "CKF_MESSAGE_DECRYPT"},
			{CKF_MESSAGE_SIGN, "CKF_MESSAGE_SIGN"},
			{CKF_MESSAGE_VERIFY, "CKF_MESSAGE_VERIFY"},
			{CKF_MULTI_MESSAGE, "CKF_MULTI_MESSAGE"},
			{CKF_ENCRYPT, "CKF_ENCRYPT"},
			{CKF_DECRYPT, "CKF_DECRYPT"},
			{CKF_DIGEST, "CKF_DIGEST"},
			{CKF_SIGN, "CKF_SIGN"},
			{CKF_VERIFY, "CKF_VERIFY"},
			{CKF_GENERATE_KEY_PAIR, "CKF_GENERATE_KEY_PAIR"},
			{CKF_WRAP, "CKF_WRAP"},
			{CKF_UNWRAP, "CKF_UNWRAP"},
			{CKF_DERIVE, "CKF_DERIVE"},
			{CKF_ENCAPSULATE, "CKF_ENCAPSULATE"},
			{CKF_DECAPSULATE, "CKF_DECAPSULATE"},
		}
		for _, ef := range existingFlags {
			t.Run("not_"+ef.name, func(t *testing.T) {
				assert.NotEqual(t, CKF_FIND_OBJECTS, ef.flag,
					"CKF_FIND_OBJECTS should not equal %s", ef.name)
			})
		}
	})

	t.Run("CKF_ASYNC_SESSION has correct value and type", func(t *testing.T) {
		assert.Equal(t, uint32(0x08), CKF_ASYNC_SESSION)
	})

	t.Run("CKF_ASYNC_SESSION_SUPPORTED has correct value and type", func(t *testing.T) {
		assert.Equal(t, uint32(0x04000000), CKF_ASYNC_SESSION_SUPPORTED)
	})

	t.Run("CKF_SEED_RANDOM_REQUIRED has correct value and type", func(t *testing.T) {
		assert.Equal(t, uint32(0x02000000), CKF_SEED_RANDOM_REQUIRED)
	})

	t.Run("CKF_END_OF_MESSAGE has correct spec value", func(t *testing.T) {
		// Per PKCS#11 v3.2 spec, CKF_END_OF_MESSAGE = 0x00000001
		assert.Equal(t, MechanismFlag(0x00000001), CKF_END_OF_MESSAGE)
	})

	t.Run("CKF_END_OF_MESSAGE equals CKF_HW in numeric value but different semantic context", func(t *testing.T) {
		// Both are 0x00000001 but used in different flag namespaces:
		// CKF_HW is for CK_MECHANISM_INFO.flags
		// CKF_END_OF_MESSAGE is for CK_FLAGS in message Next functions
		assert.Equal(t, CKF_HW, CKF_END_OF_MESSAGE)
	})

	t.Run("session/token flags do not collide with each other", func(t *testing.T) {
		assert.NotEqual(t, CKF_ASYNC_SESSION, CKF_ASYNC_SESSION_SUPPORTED,
			"CKF_ASYNC_SESSION and CKF_ASYNC_SESSION_SUPPORTED should differ")
		assert.NotEqual(t, CKF_ASYNC_SESSION, CKF_SEED_RANDOM_REQUIRED,
			"CKF_ASYNC_SESSION and CKF_SEED_RANDOM_REQUIRED should differ")
		assert.NotEqual(t, CKF_ASYNC_SESSION_SUPPORTED, CKF_SEED_RANDOM_REQUIRED,
			"CKF_ASYNC_SESSION_SUPPORTED and CKF_SEED_RANDOM_REQUIRED should differ")
	})

	t.Run("session/token flags are powers of two (single bit set)", func(t *testing.T) {
		// CKF_ASYNC_SESSION = 0x08 = one bit set
		assert.Equal(t, uint32(1), popcount(CKF_ASYNC_SESSION),
			"CKF_ASYNC_SESSION should have exactly one bit set")
		// CKF_ASYNC_SESSION_SUPPORTED = 0x04000000 = one bit set
		assert.Equal(t, uint32(1), popcount(CKF_ASYNC_SESSION_SUPPORTED),
			"CKF_ASYNC_SESSION_SUPPORTED should have exactly one bit set")
		// CKF_SEED_RANDOM_REQUIRED = 0x02000000 = one bit set
		assert.Equal(t, uint32(1), popcount(CKF_SEED_RANDOM_REQUIRED),
			"CKF_SEED_RANDOM_REQUIRED should have exactly one bit set")
	})

	t.Run("session/token flags can be used in bitwise operations", func(t *testing.T) {
		combined := CKF_ASYNC_SESSION | CKF_ASYNC_SESSION_SUPPORTED | CKF_SEED_RANDOM_REQUIRED
		assert.True(t, combined&CKF_ASYNC_SESSION != 0)
		assert.True(t, combined&CKF_ASYNC_SESSION_SUPPORTED != 0)
		assert.True(t, combined&CKF_SEED_RANDOM_REQUIRED != 0)
	})
}

// TestArrayAttributeConstants tests that CKF_ARRAY_ATTRIBUTE-flagged attributes
// have the correct hex values per PKCS#11 spec.
func TestArrayAttributeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant AttributeType
		want     uint32
	}{
		{
			name:     "CKA_WRAP_TEMPLATE",
			constant: CKA_WRAP_TEMPLATE,
			want:     0x40000211,
		},
		{
			name:     "CKA_UNWRAP_TEMPLATE",
			constant: CKA_UNWRAP_TEMPLATE,
			want:     0x40000212,
		},
		{
			name:     "CKA_DERIVE_TEMPLATE",
			constant: CKA_DERIVE_TEMPLATE,
			want:     0x40000213,
		},
		{
			name:     "CKA_ALLOWED_MECHANISMS",
			constant: CKA_ALLOWED_MECHANISMS,
			want:     0x40000600,
		},
		{
			name:     "CKA_ENCAPSULATE_TEMPLATE",
			constant: CKA_ENCAPSULATE_TEMPLATE,
			want:     0x4000062A,
		},
		{
			name:     "CKA_DECAPSULATE_TEMPLATE",
			constant: CKA_DECAPSULATE_TEMPLATE,
			want:     0x4000062B,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, uint32(tt.constant),
				"%s should have CKF_ARRAY_ATTRIBUTE (0x40000000) flag set", tt.name)
			// Verify the flag bit is set
			assert.True(t, uint32(tt.constant)&0x40000000 != 0,
				"%s should have CKF_ARRAY_ATTRIBUTE bit set", tt.name)
		})
	}
}

// popcount returns the number of set bits in a uint32 value.
func popcount(v uint32) uint32 {
	var count uint32
	for v != 0 {
		count += v & 1
		v >>= 1
	}
	return count
}
