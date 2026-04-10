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

//go:build integration && conformance

// Package conformance provides OASIS PKCS#11 v3.0 conformance tests.
//
// # Mechanism Conformance Tests
//
// This file tests PKCS#11 mechanism conformance per the OASIS PKCS#11 v3.0
// specification, including mechanism info validation, flag consistency,
// key size range enforcement, and parameter validation.
//
// References:
//   - OASIS PKCS#11 Base v3.0, Section 5.5.4: C_GetMechanismList
//   - OASIS PKCS#11 Base v3.0, Section 5.5.5: C_GetMechanismInfo
//   - OASIS PKCS#11 Current Mechanisms v3.0
package conformance

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// TestMechanism_GetMechanismList tests C_GetMechanismList conformance.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.5.4
func TestMechanism_GetMechanismList(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	t.Run("ValidSlot", func(t *testing.T) {
		mechs, rv := env.Module.GetMechanismList(0)
		if rv != module.CKR_OK {
			t.Fatalf("GetMechanismList: expected CKR_OK, got %s", rv.String())
		}

		// Token should support at least some mechanisms
		if len(mechs) == 0 {
			t.Error("GetMechanismList returned empty list")
		}

		t.Logf("Token supports %d mechanisms", len(mechs))
	})

	t.Run("InvalidSlot", func(t *testing.T) {
		_, rv := env.Module.GetMechanismList(999999)
		if rv != module.CKR_SLOT_ID_INVALID {
			t.Errorf("GetMechanismList invalid slot: expected CKR_SLOT_ID_INVALID, got %s", rv.String())
		}
	})
}

// TestMechanism_GetMechanismInfo tests C_GetMechanismInfo conformance.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.5.5
func TestMechanism_GetMechanismInfo(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	// Get list of supported mechanisms
	mechs, rv := env.Module.GetMechanismList(0)
	if rv != module.CKR_OK {
		t.Fatalf("GetMechanismList: expected CKR_OK, got %s", rv.String())
	}

	// Test each mechanism
	for _, mech := range mechs {
		t.Run(mech.String(), func(t *testing.T) {
			info, rv := env.Module.GetMechanismInfo(0, mech)
			if rv != module.CKR_OK {
				t.Errorf("GetMechanismInfo %s: expected CKR_OK, got %s", mech.String(), rv.String())
				return
			}

			if info == nil {
				t.Errorf("GetMechanismInfo %s: returned nil info", mech.String())
				return
			}

			// Verify CK_MECHANISM_INFO structure
			// Reference: OASIS PKCS#11 v3.0, Section 5.5.5

			// MinKeySize should be <= MaxKeySize
			if info.MinKeySize > info.MaxKeySize {
				t.Errorf("%s: MinKeySize (%d) > MaxKeySize (%d)",
					mech.String(), info.MinKeySize, info.MaxKeySize)
			}

			// At least one operation flag should be set
			opFlags := module.CKF_ENCRYPT | module.CKF_DECRYPT |
				module.CKF_DIGEST | module.CKF_SIGN | module.CKF_VERIFY |
				module.CKF_GENERATE | module.CKF_GENERATE_KEY_PAIR |
				module.CKF_WRAP | module.CKF_UNWRAP | module.CKF_DERIVE

			if info.Flags&opFlags == 0 {
				t.Errorf("%s: no operation flags set", mech.String())
			}

			t.Logf("%s: MinKeySize=%d, MaxKeySize=%d, Flags=0x%08X",
				mech.String(), info.MinKeySize, info.MaxKeySize, info.Flags)
		})
	}
}

// TestMechanism_FlagsMatchOperations tests that mechanism flags match supported operations.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.5.5
// "The flags field contains flag bits that describe capabilities of the mechanism."
func TestMechanism_FlagsMatchOperations(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Test RSA signing mechanism
	t.Run("RSA_PKCS_Signing", func(t *testing.T) {
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_RSA_PKCS)
		if rv != module.CKR_OK {
			t.Skipf("CKM_RSA_PKCS not supported: %s", rv.String())
		}

		// CKM_RSA_PKCS should have CKF_SIGN flag
		if info.Flags&module.CKF_SIGN == 0 {
			t.Log("note: CKM_RSA_PKCS should have CKF_SIGN flag")
		}

		// CKM_RSA_PKCS should have CKF_VERIFY flag
		if info.Flags&module.CKF_VERIFY == 0 {
			t.Log("note: CKM_RSA_PKCS should have CKF_VERIFY flag")
		}
	})

	// Test AES encryption mechanism
	t.Run("AES_CBC_Encryption", func(t *testing.T) {
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_AES_CBC)
		if rv != module.CKR_OK {
			t.Skipf("CKM_AES_CBC not supported: %s", rv.String())
		}

		// CKM_AES_CBC should have CKF_ENCRYPT flag
		if info.Flags&module.CKF_ENCRYPT == 0 {
			t.Log("note: CKM_AES_CBC should have CKF_ENCRYPT flag")
		}

		// CKM_AES_CBC should have CKF_DECRYPT flag
		if info.Flags&module.CKF_DECRYPT == 0 {
			t.Log("note: CKM_AES_CBC should have CKF_DECRYPT flag")
		}
	})

	// Test RSA key generation mechanism
	t.Run("RSA_KEY_PAIR_GEN", func(t *testing.T) {
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_RSA_PKCS_KEY_PAIR_GEN)
		if rv != module.CKR_OK {
			t.Skipf("CKM_RSA_PKCS_KEY_PAIR_GEN not supported: %s", rv.String())
		}

		// Should have CKF_GENERATE_KEY_PAIR flag
		if info.Flags&module.CKF_GENERATE_KEY_PAIR == 0 {
			t.Error("CKM_RSA_PKCS_KEY_PAIR_GEN missing CKF_GENERATE_KEY_PAIR flag")
		}
	})

	// Test AES key generation mechanism
	t.Run("AES_KEY_GEN", func(t *testing.T) {
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_AES_KEY_GEN)
		if rv != module.CKR_OK {
			t.Skipf("CKM_AES_KEY_GEN not supported: %s", rv.String())
		}

		// Should have CKF_GENERATE flag
		if info.Flags&module.CKF_GENERATE == 0 {
			t.Error("CKM_AES_KEY_GEN missing CKF_GENERATE flag")
		}
	})

	// Test digest mechanism
	t.Run("SHA256_Digest", func(t *testing.T) {
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_SHA256)
		if rv != module.CKR_OK {
			t.Skipf("CKM_SHA256 not supported: %s", rv.String())
		}

		// Should have CKF_DIGEST flag
		if info.Flags&module.CKF_DIGEST == 0 {
			t.Error("CKM_SHA256 missing CKF_DIGEST flag")
		}
	})

	// Test ECDSA mechanism
	t.Run("ECDSA_Signing", func(t *testing.T) {
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_ECDSA)
		if rv != module.CKR_OK {
			t.Skipf("CKM_ECDSA not supported: %s", rv.String())
		}

		// Should have CKF_SIGN and CKF_VERIFY flags
		if info.Flags&module.CKF_SIGN == 0 {
			t.Log("note: CKM_ECDSA should have CKF_SIGN flag")
		}
		if info.Flags&module.CKF_VERIFY == 0 {
			t.Log("note: CKM_ECDSA should have CKF_VERIFY flag")
		}
	})

	// Test EC key generation mechanism
	t.Run("EC_KEY_PAIR_GEN", func(t *testing.T) {
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_EC_KEY_PAIR_GEN)
		if rv != module.CKR_OK {
			t.Skipf("CKM_EC_KEY_PAIR_GEN not supported: %s", rv.String())
		}

		// Should have CKF_GENERATE_KEY_PAIR flag
		if info.Flags&module.CKF_GENERATE_KEY_PAIR == 0 {
			t.Error("CKM_EC_KEY_PAIR_GEN missing CKF_GENERATE_KEY_PAIR flag")
		}
	})

	_ = session // Keep session reference for future tests
}

// TestMechanism_KeySizeRange tests key size range enforcement.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.5.5
// "minKeySize and maxKeySize specify the minimum and maximum key sizes supported
// by the mechanism."
func TestMechanism_KeySizeRange(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// Test RSA key size range
	t.Run("RSA_KeySizeRange", func(t *testing.T) {
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_RSA_PKCS_KEY_PAIR_GEN)
		if rv != module.CKR_OK {
			t.Skipf("CKM_RSA_PKCS_KEY_PAIR_GEN not supported: %s", rv.String())
		}

		t.Logf("RSA key size range: %d - %d bits", info.MinKeySize, info.MaxKeySize)

		// Typical RSA range should include 2048 bits
		if info.MinKeySize > 2048 || info.MaxKeySize < 2048 {
			t.Logf("note: 2048-bit RSA may not be supported (range: %d-%d)",
				info.MinKeySize, info.MaxKeySize)
		}
	})

	// Test AES key size range
	t.Run("AES_KeySizeRange", func(t *testing.T) {
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_AES_KEY_GEN)
		if rv != module.CKR_OK {
			t.Skipf("CKM_AES_KEY_GEN not supported: %s", rv.String())
		}

		t.Logf("AES key size range: %d - %d bits", info.MinKeySize, info.MaxKeySize)

		// AES supports 128, 192, 256 bits
		// MinKeySize should be at most 128
		if info.MinKeySize > 128 {
			t.Logf("note: AES MinKeySize (%d) should be <= 128", info.MinKeySize)
		}

		// MaxKeySize should be at least 256
		if info.MaxKeySize < 256 {
			t.Logf("note: AES MaxKeySize (%d) should be >= 256", info.MaxKeySize)
		}
	})

	// Test EC key size range
	t.Run("EC_KeySizeRange", func(t *testing.T) {
		info, rv := env.Module.GetMechanismInfo(0, module.CKM_EC_KEY_PAIR_GEN)
		if rv != module.CKR_OK {
			t.Skipf("CKM_EC_KEY_PAIR_GEN not supported: %s", rv.String())
		}

		t.Logf("EC key size range: %d - %d bits", info.MinKeySize, info.MaxKeySize)

		// Common EC curves: P-256 (256-bit), P-384 (384-bit), P-521 (521-bit)
		if info.MinKeySize > 256 {
			t.Logf("note: P-256 may not be supported (MinKeySize: %d)", info.MinKeySize)
		}
	})

	_ = session // Keep session reference for future tests
}

// TestMechanism_InvalidMechanism tests error handling for invalid mechanisms.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.5.5
func TestMechanism_InvalidMechanism(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	t.Run("NonExistentMechanism", func(t *testing.T) {
		// Use a mechanism type that doesn't exist
		_, rv := env.Module.GetMechanismInfo(0, module.MechanismType(0xFFFFFFFF))
		if rv != module.CKR_MECHANISM_INVALID {
			t.Errorf("GetMechanismInfo invalid: expected CKR_MECHANISM_INVALID, got %s", rv.String())
		}
	})

	t.Run("VendorDefinedMechanism", func(t *testing.T) {
		// Use a vendor-defined mechanism type
		_, rv := env.Module.GetMechanismInfo(0, module.MechanismType(0x80000001))
		if rv != module.CKR_MECHANISM_INVALID {
			// May return CKR_MECHANISM_INVALID or CKR_OK if vendor mechanism is supported
			t.Logf("GetMechanismInfo vendor-defined: got %s", rv.String())
		}
	})
}

// TestMechanism_DigestMechanisms tests digest mechanism conformance.
//
// Reference: OASIS PKCS#11 Current Mechanisms v3.0, Section 6
func TestMechanism_DigestMechanisms(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	digestMechs := []struct {
		mech       module.MechanismType
		name       string
		digestSize int
	}{
		{module.CKM_SHA_1, "SHA-1", 20},
		{module.CKM_SHA256, "SHA-256", 32},
		{module.CKM_SHA384, "SHA-384", 48},
		{module.CKM_SHA512, "SHA-512", 64},
		{module.CKM_SHA3_256, "SHA3-256", 32},
		{module.CKM_SHA3_384, "SHA3-384", 48},
		{module.CKM_SHA3_512, "SHA3-512", 64},
	}

	for _, dm := range digestMechs {
		t.Run(dm.name, func(t *testing.T) {
			info, rv := env.Module.GetMechanismInfo(0, dm.mech)
			if rv != module.CKR_OK {
				t.Skipf("%s not supported: %s", dm.name, rv.String())
			}

			// Should have CKF_DIGEST flag
			if info.Flags&module.CKF_DIGEST == 0 {
				t.Errorf("%s missing CKF_DIGEST flag", dm.name)
			}

			// Test actual digest operation
			rv = env.Module.DigestInit(session, &module.Mechanism{Type: dm.mech})
			if rv != module.CKR_OK {
				t.Logf("DigestInit %s: %s", dm.name, rv.String())
				return
			}

			testData := []byte("test data for digest")
			digest, rv := env.Module.Digest(session, testData)
			if rv != module.CKR_OK {
				t.Errorf("Digest %s: expected CKR_OK, got %s", dm.name, rv.String())
				return
			}

			if len(digest) != dm.digestSize {
				t.Errorf("%s digest size: expected %d, got %d", dm.name, dm.digestSize, len(digest))
			}
		})
	}
}

// TestMechanism_SignatureMechanisms tests signature mechanism conformance.
//
// Reference: OASIS PKCS#11 Current Mechanisms v3.0, Sections 7, 8
func TestMechanism_SignatureMechanisms(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	sigMechs := []struct {
		mech module.MechanismType
		name string
	}{
		{module.CKM_RSA_PKCS, "RSA-PKCS"},
		{module.CKM_SHA256_RSA_PKCS, "SHA256-RSA-PKCS"},
		{module.CKM_SHA384_RSA_PKCS, "SHA384-RSA-PKCS"},
		{module.CKM_SHA512_RSA_PKCS, "SHA512-RSA-PKCS"},
		{module.CKM_RSA_PKCS_PSS, "RSA-PKCS-PSS"},
		{module.CKM_ECDSA, "ECDSA"},
		{module.CKM_ECDSA_SHA256, "ECDSA-SHA256"},
		{module.CKM_ECDSA_SHA384, "ECDSA-SHA384"},
		{module.CKM_ECDSA_SHA512, "ECDSA-SHA512"},
		{module.CKM_EDDSA, "EdDSA"},
	}

	for _, sm := range sigMechs {
		t.Run(sm.name, func(t *testing.T) {
			info, rv := env.Module.GetMechanismInfo(0, sm.mech)
			if rv != module.CKR_OK {
				t.Skipf("%s not supported: %s", sm.name, rv.String())
			}

			// Should have CKF_SIGN and CKF_VERIFY flags
			if info.Flags&module.CKF_SIGN == 0 {
				t.Logf("note: %s should have CKF_SIGN flag", sm.name)
			}
			if info.Flags&module.CKF_VERIFY == 0 {
				t.Logf("note: %s should have CKF_VERIFY flag", sm.name)
			}

			t.Logf("%s: Flags=0x%08X, KeySize=%d-%d", sm.name, info.Flags, info.MinKeySize, info.MaxKeySize)
		})
	}
}

// TestMechanism_EncryptionMechanisms tests encryption mechanism conformance.
//
// Reference: OASIS PKCS#11 Current Mechanisms v3.0, Sections 7, 9, 10
func TestMechanism_EncryptionMechanisms(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	encMechs := []struct {
		mech module.MechanismType
		name string
	}{
		{module.CKM_RSA_PKCS, "RSA-PKCS"},
		{module.CKM_RSA_PKCS_OAEP, "RSA-PKCS-OAEP"},
		{module.CKM_AES_ECB, "AES-ECB"},
		{module.CKM_AES_CBC, "AES-CBC"},
		{module.CKM_AES_CBC_PAD, "AES-CBC-PAD"},
		{module.CKM_AES_GCM, "AES-GCM"},
		{module.CKM_AES_CTR, "AES-CTR"},
		{module.CKM_DES3_ECB, "DES3-ECB"},
		{module.CKM_DES3_CBC, "DES3-CBC"},
		{module.CKM_DES3_CBC_PAD, "DES3-CBC-PAD"},
	}

	for _, em := range encMechs {
		t.Run(em.name, func(t *testing.T) {
			info, rv := env.Module.GetMechanismInfo(0, em.mech)
			if rv != module.CKR_OK {
				t.Skipf("%s not supported: %s", em.name, rv.String())
			}

			// Should have CKF_ENCRYPT and CKF_DECRYPT flags
			if info.Flags&module.CKF_ENCRYPT == 0 {
				t.Logf("note: %s should have CKF_ENCRYPT flag", em.name)
			}
			if info.Flags&module.CKF_DECRYPT == 0 {
				t.Logf("note: %s should have CKF_DECRYPT flag", em.name)
			}

			t.Logf("%s: Flags=0x%08X, KeySize=%d-%d", em.name, info.Flags, info.MinKeySize, info.MaxKeySize)
		})
	}
}

// TestMechanism_KeyGenerationMechanisms tests key generation mechanism conformance.
//
// Reference: OASIS PKCS#11 Current Mechanisms v3.0, Sections 7-10
func TestMechanism_KeyGenerationMechanisms(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	keyGenMechs := []struct {
		mech     module.MechanismType
		name     string
		isKeyGen bool // true for C_GenerateKey, false for C_GenerateKeyPair
	}{
		{module.CKM_RSA_PKCS_KEY_PAIR_GEN, "RSA-KEY-PAIR-GEN", false},
		{module.CKM_EC_KEY_PAIR_GEN, "EC-KEY-PAIR-GEN", false},
		{module.CKM_EC_EDWARDS_KEY_PAIR_GEN, "EC-EDWARDS-KEY-PAIR-GEN", false},
		{module.CKM_EC_MONTGOMERY_KEY_PAIR_GEN, "EC-MONTGOMERY-KEY-PAIR-GEN", false},
		{module.CKM_AES_KEY_GEN, "AES-KEY-GEN", true},
		{module.CKM_DES3_KEY_GEN, "DES3-KEY-GEN", true},
		{module.CKM_GENERIC_SECRET_KEY_GEN, "GENERIC-SECRET-KEY-GEN", true},
		{module.CKM_DSA_KEY_PAIR_GEN, "DSA-KEY-PAIR-GEN", false},
		{module.CKM_DH_PKCS_KEY_PAIR_GEN, "DH-KEY-PAIR-GEN", false},
	}

	for _, km := range keyGenMechs {
		t.Run(km.name, func(t *testing.T) {
			info, rv := env.Module.GetMechanismInfo(0, km.mech)
			if rv != module.CKR_OK {
				t.Skipf("%s not supported: %s", km.name, rv.String())
			}

			if km.isKeyGen {
				// Should have CKF_GENERATE flag for symmetric keys
				if info.Flags&module.CKF_GENERATE == 0 {
					t.Errorf("%s missing CKF_GENERATE flag", km.name)
				}
			} else {
				// Should have CKF_GENERATE_KEY_PAIR flag for asymmetric keys
				if info.Flags&module.CKF_GENERATE_KEY_PAIR == 0 {
					t.Errorf("%s missing CKF_GENERATE_KEY_PAIR flag", km.name)
				}
			}

			t.Logf("%s: Flags=0x%08X, KeySize=%d-%d", km.name, info.Flags, info.MinKeySize, info.MaxKeySize)
		})
	}
}

// TestMechanism_KeyDeriveMechanisms tests key derivation mechanism conformance.
//
// Reference: OASIS PKCS#11 Current Mechanisms v3.0, Sections 11, 12
func TestMechanism_KeyDeriveMechanisms(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	deriveMechs := []struct {
		mech module.MechanismType
		name string
	}{
		{module.CKM_ECDH1_DERIVE, "ECDH1-DERIVE"},
		{module.CKM_ECDH1_COFACTOR_DERIVE, "ECDH1-COFACTOR-DERIVE"},
		{module.CKM_DH_PKCS_DERIVE, "DH-PKCS-DERIVE"},
		{module.CKM_SHA256_KEY_DERIVATION, "SHA256-KEY-DERIVATION"},
		{module.CKM_SHA384_KEY_DERIVATION, "SHA384-KEY-DERIVATION"},
		{module.CKM_SHA512_KEY_DERIVATION, "SHA512-KEY-DERIVATION"},
		{module.CKM_HKDF_DERIVE, "HKDF-DERIVE"},
		{module.CKM_HKDF_DATA, "HKDF-DATA"},
		{module.CKM_HKDF_KEY_GEN, "HKDF-KEY-GEN"},
	}

	for _, dm := range deriveMechs {
		t.Run(dm.name, func(t *testing.T) {
			info, rv := env.Module.GetMechanismInfo(0, dm.mech)
			if rv != module.CKR_OK {
				t.Skipf("%s not supported: %s", dm.name, rv.String())
			}

			// Should have CKF_DERIVE flag
			if info.Flags&module.CKF_DERIVE == 0 {
				t.Logf("note: %s should have CKF_DERIVE flag", dm.name)
			}

			t.Logf("%s: Flags=0x%08X, KeySize=%d-%d", dm.name, info.Flags, info.MinKeySize, info.MaxKeySize)
		})
	}
}

// TestMechanism_WrapUnwrapMechanisms tests key wrap/unwrap mechanism conformance.
//
// Reference: OASIS PKCS#11 Current Mechanisms v3.0, Section 5.12
func TestMechanism_WrapUnwrapMechanisms(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	wrapMechs := []struct {
		mech module.MechanismType
		name string
	}{
		{module.CKM_RSA_PKCS, "RSA-PKCS"},
		{module.CKM_RSA_PKCS_OAEP, "RSA-PKCS-OAEP"},
		{module.CKM_AES_KEY_WRAP, "AES-KEY-WRAP"},
		{module.CKM_AES_KEY_WRAP_PAD, "AES-KEY-WRAP-PAD"},
		{module.CKM_AES_GCM, "AES-GCM"},
		{module.CKM_AES_CBC_PAD, "AES-CBC-PAD"},
	}

	for _, wm := range wrapMechs {
		t.Run(wm.name, func(t *testing.T) {
			info, rv := env.Module.GetMechanismInfo(0, wm.mech)
			if rv != module.CKR_OK {
				t.Skipf("%s not supported: %s", wm.name, rv.String())
			}

			hasWrap := info.Flags&module.CKF_WRAP != 0
			hasUnwrap := info.Flags&module.CKF_UNWRAP != 0

			t.Logf("%s: Wrap=%v, Unwrap=%v, Flags=0x%08X", wm.name, hasWrap, hasUnwrap, info.Flags)

			// If a mechanism supports wrap, it typically supports unwrap too
			if hasWrap && !hasUnwrap {
				t.Logf("note: %s has CKF_WRAP but not CKF_UNWRAP", wm.name)
			}
			if hasUnwrap && !hasWrap {
				t.Logf("note: %s has CKF_UNWRAP but not CKF_WRAP", wm.name)
			}
		})
	}
}

// TestMechanism_HWFlags tests hardware-related mechanism flags.
//
// Reference: OASIS PKCS#11 v3.0, Section 5.5.5
func TestMechanism_HWFlags(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)
	env.MustInitializeModule(t)
	env.MustInitializeToken(t, testutil.TestPINs.SO, testutil.TestLabels.Token)

	mechs, rv := env.Module.GetMechanismList(0)
	if rv != module.CKR_OK {
		t.Fatalf("GetMechanismList: expected CKR_OK, got %s", rv.String())
	}

	hwMechCount := 0
	for _, mech := range mechs {
		info, rv := env.Module.GetMechanismInfo(0, mech)
		if rv != module.CKR_OK {
			continue
		}

		// Check CKF_HW flag
		if info.Flags&module.CKF_HW != 0 {
			hwMechCount++
			t.Logf("%s has CKF_HW flag (hardware-accelerated)", mech.String())
		}
	}

	t.Logf("Total mechanisms with CKF_HW: %d out of %d", hwMechCount, len(mechs))
}
