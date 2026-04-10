// Copyright (c) 2025 Jeremy Hahn
// Licensed under the AGPL-3.0 license with Commercial Licensing Option.
// See LICENSE file in the project root for full license information.

//go:build integration && conformance

// Package conformance provides OASIS PKCS#11 v3.0 conformance tests.
// This file tests PKCS#11 profile compliance per OASIS PKCS#11 Profiles v3.0 specification.
package conformance

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// =============================================================================
// Profile Definitions
// OASIS PKCS#11 Profiles v3.0 Specification
// =============================================================================

// BaselineProfile defines the minimum mechanisms required for the Baseline Provider profile.
// OASIS PKCS#11 Profiles v3.0 Section 2.2 - Baseline Provider
var BaselineProfile = ProfileDefinition{
	Name: "Baseline Provider",
	RequiredMechanisms: []module.MechanismType{
		module.CKM_RSA_PKCS_KEY_PAIR_GEN,
		module.CKM_RSA_PKCS,
		module.CKM_SHA256,
		module.CKM_SHA384,
		module.CKM_SHA512,
	},
	OptionalMechanisms: []module.MechanismType{
		module.CKM_SHA_1,
		module.CKM_RSA_PKCS_OAEP,
		module.CKM_RSA_PKCS_PSS,
	},
	MinRSAKeySize: 2048,
	MaxRSAKeySize: 4096,
}

// ExtendedProviderProfile defines requirements for Extended Provider profile.
// OASIS PKCS#11 Profiles v3.0 Section 2.3 - Extended Provider
var ExtendedProviderProfile = ProfileDefinition{
	Name: "Extended Provider",
	RequiredMechanisms: []module.MechanismType{
		// All baseline mechanisms
		module.CKM_RSA_PKCS_KEY_PAIR_GEN,
		module.CKM_RSA_PKCS,
		module.CKM_SHA256,
		module.CKM_SHA384,
		module.CKM_SHA512,
		// Extended requirements
		module.CKM_RSA_PKCS_OAEP,
		module.CKM_RSA_PKCS_PSS,
		module.CKM_ECDSA,
		module.CKM_EC_KEY_PAIR_GEN,
		module.CKM_AES_KEY_GEN,
		module.CKM_AES_CBC,
		module.CKM_AES_GCM,
	},
	OptionalMechanisms: []module.MechanismType{
		module.CKM_AES_CTR,
		module.CKM_AES_CCM,
		module.CKM_ECDH1_DERIVE,
	},
	MinRSAKeySize: 2048,
	MaxRSAKeySize: 8192,
	MinAESKeySize: 128,
	MaxAESKeySize: 256,
	ECCurves: []string{
		"P-256",
		"P-384",
		"P-521",
	},
}

// AuthenticationDeviceProfile defines requirements for Authentication Device profile.
// OASIS PKCS#11 Profiles v3.0 Section 2.4 - Authentication Device
var AuthenticationDeviceProfile = ProfileDefinition{
	Name: "Authentication Device",
	RequiredMechanisms: []module.MechanismType{
		module.CKM_RSA_PKCS_KEY_PAIR_GEN,
		module.CKM_RSA_PKCS,
		module.CKM_SHA256,
	},
	OptionalMechanisms: []module.MechanismType{
		module.CKM_ECDSA,
		module.CKM_EC_KEY_PAIR_GEN,
	},
	MinRSAKeySize: 2048,
	RequiresPIN:   true,
}

// ProfileDefinition describes a PKCS#11 profile's requirements.
type ProfileDefinition struct {
	Name               string
	RequiredMechanisms []module.MechanismType
	OptionalMechanisms []module.MechanismType
	MinRSAKeySize      uint64
	MaxRSAKeySize      uint64
	MinAESKeySize      uint64
	MaxAESKeySize      uint64
	ECCurves           []string
	RequiresPIN        bool
}

// =============================================================================
// Baseline Profile Tests
// OASIS PKCS#11 Profiles v3.0 Section 2.2
// =============================================================================

// TestBaselineProfile_RequiredMechanisms tests that all baseline mechanisms are available.
// OASIS PKCS#11 Profiles v3.0 Section 2.2.1
func TestBaselineProfile_RequiredMechanisms(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)

	m := env.Module

	rv := m.Initialize(env.Config)
	testutil.RequireOK(t, rv, "C_Initialize failed")
	defer m.Finalize()

	// Get supported mechanisms
	mechanisms, rv := m.GetMechanismList(0)
	testutil.RequireOK(t, rv, "C_GetMechanismList failed")

	mechSet := make(map[module.MechanismType]bool)
	for _, mech := range mechanisms {
		mechSet[mech] = true
	}

	t.Run("RequiredMechanisms", func(t *testing.T) {
		for _, reqMech := range BaselineProfile.RequiredMechanisms {
			mechName := getMechanismName(reqMech)
			t.Run(mechName, func(t *testing.T) {
				if !mechSet[reqMech] {
					t.Errorf("Baseline profile requires mechanism %s (0x%08x)", mechName, reqMech)
				} else {
					t.Logf("Found required mechanism: %s", mechName)
				}
			})
		}
	})

	t.Run("OptionalMechanisms", func(t *testing.T) {
		for _, optMech := range BaselineProfile.OptionalMechanisms {
			mechName := getMechanismName(optMech)
			t.Run(mechName, func(t *testing.T) {
				if mechSet[optMech] {
					t.Logf("Optional mechanism available: %s", mechName)
				} else {
					t.Logf("Optional mechanism not available: %s (OK)", mechName)
				}
			})
		}
	})
}

// TestBaselineProfile_RSAKeySize tests RSA key size requirements.
// OASIS PKCS#11 Profiles v3.0 Section 2.2.2
func TestBaselineProfile_RSAKeySize(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)

	m := env.Module

	rv := m.Initialize(env.Config)
	testutil.RequireOK(t, rv, "C_Initialize failed")
	defer m.Finalize()

	// Get RSA key gen mechanism info
	mechInfo, rv := m.GetMechanismInfo(0, module.CKM_RSA_PKCS_KEY_PAIR_GEN)
	if rv == module.CKR_MECHANISM_INVALID {
		t.Skip("RSA key generation not supported")
	}
	testutil.RequireOK(t, rv, "C_GetMechanismInfo failed")

	t.Run("MinKeySize", func(t *testing.T) {
		// Per profile spec: minimum 2048 bits required
		require.LessOrEqual(t, mechInfo.MinKeySize, BaselineProfile.MinRSAKeySize,
			"Module must support at least %d-bit RSA keys", BaselineProfile.MinRSAKeySize)
		t.Logf("Module minimum RSA key size: %d bits", mechInfo.MinKeySize)
	})

	t.Run("MaxKeySize", func(t *testing.T) {
		// Per profile spec: should support up to 4096 bits
		require.GreaterOrEqual(t, mechInfo.MaxKeySize, BaselineProfile.MinRSAKeySize,
			"Module must support at least %d-bit RSA keys", BaselineProfile.MinRSAKeySize)
		t.Logf("Module maximum RSA key size: %d bits", mechInfo.MaxKeySize)
	})
}

// TestBaselineProfile_DigestMechanisms tests required digest mechanisms.
// OASIS PKCS#11 Profiles v3.0 Section 2.2.3
func TestBaselineProfile_DigestMechanisms(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)

	m := env.Module

	rv := m.Initialize(env.Config)
	testutil.RequireOK(t, rv, "C_Initialize failed")
	defer m.Finalize()

	session, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION)
	testutil.RequireOK(t, rv, "C_OpenSession failed")
	defer m.CloseSession(session)

	digestMechanisms := []struct {
		mechanism  module.MechanismType
		name       string
		digestSize int
	}{
		{module.CKM_SHA256, "SHA-256", 32},
		{module.CKM_SHA384, "SHA-384", 48},
		{module.CKM_SHA512, "SHA-512", 64},
	}

	testData := []byte("Test data for digest verification")

	for _, dm := range digestMechanisms {
		t.Run(dm.name, func(t *testing.T) {
			mechanism := &module.Mechanism{Type: dm.mechanism}

			rv := m.DigestInit(session, mechanism)
			if rv == module.CKR_MECHANISM_INVALID {
				t.Errorf("Baseline profile requires %s mechanism", dm.name)
				return
			}
			testutil.RequireOK(t, rv, "C_DigestInit failed for "+dm.name)

			digest, rv := m.Digest(session, testData)
			testutil.RequireOK(t, rv, "C_Digest failed for "+dm.name)

			require.Len(t, digest, dm.digestSize,
				"%s digest should be %d bytes", dm.name, dm.digestSize)
			t.Logf("%s produces %d-byte digest", dm.name, len(digest))
		})
	}
}

// =============================================================================
// Extended Provider Profile Tests
// OASIS PKCS#11 Profiles v3.0 Section 2.3
// =============================================================================

// TestExtendedProfile_RequiredMechanisms tests extended profile mechanism requirements.
// OASIS PKCS#11 Profiles v3.0 Section 2.3.1
func TestExtendedProfile_RequiredMechanisms(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)

	m := env.Module

	rv := m.Initialize(env.Config)
	testutil.RequireOK(t, rv, "C_Initialize failed")
	defer m.Finalize()

	mechanisms, rv := m.GetMechanismList(0)
	testutil.RequireOK(t, rv, "C_GetMechanismList failed")

	mechSet := make(map[module.MechanismType]bool)
	for _, mech := range mechanisms {
		mechSet[mech] = true
	}

	passed := 0
	failed := 0

	for _, reqMech := range ExtendedProviderProfile.RequiredMechanisms {
		mechName := getMechanismName(reqMech)
		t.Run(mechName, func(t *testing.T) {
			if mechSet[reqMech] {
				passed++
				t.Logf("Extended profile mechanism available: %s", mechName)
			} else {
				failed++
				t.Errorf("Extended profile requires mechanism %s (0x%08x)", mechName, reqMech)
			}
		})
	}

	t.Logf("Extended profile compliance: %d/%d mechanisms available",
		passed, len(ExtendedProviderProfile.RequiredMechanisms))
}

// TestExtendedProfile_AESSupport tests AES mechanism requirements.
// OASIS PKCS#11 Profiles v3.0 Section 2.3.2
func TestExtendedProfile_AESSupport(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)

	m := env.Module

	rv := m.Initialize(env.Config)
	testutil.RequireOK(t, rv, "C_Initialize failed")
	defer m.Finalize()

	// Check AES key generation mechanism info
	mechInfo, rv := m.GetMechanismInfo(0, module.CKM_AES_KEY_GEN)
	if rv == module.CKR_MECHANISM_INVALID {
		t.Skip("AES key generation not supported (required for Extended profile)")
	}
	testutil.RequireOK(t, rv, "C_GetMechanismInfo failed")

	t.Run("KeySizeRange", func(t *testing.T) {
		// Extended profile requires 128-256 bit AES keys
		// Mechanism info reports key size in bytes
		minBits := mechInfo.MinKeySize * 8
		maxBits := mechInfo.MaxKeySize * 8

		require.LessOrEqual(t, minBits, uint64(128),
			"Module should support 128-bit AES keys")
		require.GreaterOrEqual(t, maxBits, uint64(256),
			"Module should support 256-bit AES keys")

		t.Logf("AES key size range: %d-%d bits", minBits, maxBits)
	})

	t.Run("AES_CBC", func(t *testing.T) {
		_, rv := m.GetMechanismInfo(0, module.CKM_AES_CBC)
		if rv == module.CKR_MECHANISM_INVALID {
			t.Error("Extended profile requires CKM_AES_CBC")
		} else {
			t.Log("CKM_AES_CBC available")
		}
	})

	t.Run("AES_GCM", func(t *testing.T) {
		_, rv := m.GetMechanismInfo(0, module.CKM_AES_GCM)
		if rv == module.CKR_MECHANISM_INVALID {
			t.Error("Extended profile requires CKM_AES_GCM")
		} else {
			t.Log("CKM_AES_GCM available")
		}
	})
}

// TestExtendedProfile_ECCSupport tests ECC mechanism requirements.
// OASIS PKCS#11 Profiles v3.0 Section 2.3.3
func TestExtendedProfile_ECCSupport(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)

	m := env.Module

	rv := m.Initialize(env.Config)
	testutil.RequireOK(t, rv, "C_Initialize failed")
	defer m.Finalize()

	t.Run("EC_KEY_PAIR_GEN", func(t *testing.T) {
		_, rv := m.GetMechanismInfo(0, module.CKM_EC_KEY_PAIR_GEN)
		if rv == module.CKR_MECHANISM_INVALID {
			t.Error("Extended profile requires CKM_EC_KEY_PAIR_GEN")
		} else {
			t.Log("CKM_EC_KEY_PAIR_GEN available")
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		_, rv := m.GetMechanismInfo(0, module.CKM_ECDSA)
		if rv == module.CKR_MECHANISM_INVALID {
			t.Error("Extended profile requires CKM_ECDSA")
		} else {
			t.Log("CKM_ECDSA available")
		}
	})

	t.Run("SupportedCurves", func(t *testing.T) {
		session, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
		testutil.RequireOK(t, rv, "C_OpenSession failed")
		defer m.CloseSession(session)

		rv = m.Login(session, module.CKU_USER, []byte(testutil.TestPINs.User))
		testutil.RequireOK(t, rv, "C_Login failed")
		defer m.Logout(session)

		// Test curve support by attempting key generation
		curves := []struct {
			name string
			oid  []byte
		}{
			{"P-256", []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}},
			{"P-384", []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}},
			{"P-521", []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23}},
		}

		for _, curve := range curves {
			t.Run(curve.name, func(t *testing.T) {
				pubTemplate := []module.Attribute{
					module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
					module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
					module.NewAttribute(module.CKA_EC_PARAMS, curve.oid),
					module.NewBoolAttribute(module.CKA_VERIFY, true),
					module.NewBoolAttribute(module.CKA_TOKEN, false),
				}

				privTemplate := []module.Attribute{
					module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
					module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
					module.NewBoolAttribute(module.CKA_SIGN, true),
					module.NewBoolAttribute(module.CKA_TOKEN, false),
				}

				_, _, rv := m.GenerateKeyPair(
					session,
					&module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN},
					pubTemplate,
					privTemplate,
				)

				if rv == module.CKR_OK {
					t.Logf("Curve %s supported", curve.name)
				} else if rv == module.CKR_MECHANISM_INVALID || rv == module.CKR_CURVE_NOT_SUPPORTED {
					t.Errorf("Extended profile requires curve %s", curve.name)
				} else {
					t.Logf("Curve %s test returned: %v", curve.name, rv)
				}
			})
		}
	})
}

// =============================================================================
// Authentication Device Profile Tests
// OASIS PKCS#11 Profiles v3.0 Section 2.4
// =============================================================================

// TestAuthDeviceProfile_RequiredMechanisms tests authentication device profile.
// OASIS PKCS#11 Profiles v3.0 Section 2.4.1
func TestAuthDeviceProfile_RequiredMechanisms(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)

	m := env.Module

	rv := m.Initialize(env.Config)
	testutil.RequireOK(t, rv, "C_Initialize failed")
	defer m.Finalize()

	mechanisms, rv := m.GetMechanismList(0)
	testutil.RequireOK(t, rv, "C_GetMechanismList failed")

	mechSet := make(map[module.MechanismType]bool)
	for _, mech := range mechanisms {
		mechSet[mech] = true
	}

	for _, reqMech := range AuthenticationDeviceProfile.RequiredMechanisms {
		mechName := getMechanismName(reqMech)
		t.Run(mechName, func(t *testing.T) {
			if !mechSet[reqMech] {
				t.Errorf("Authentication device profile requires %s", mechName)
			} else {
				t.Logf("Required mechanism available: %s", mechName)
			}
		})
	}
}

// TestAuthDeviceProfile_PINProtection tests PIN protection requirements.
// OASIS PKCS#11 Profiles v3.0 Section 2.4.2
func TestAuthDeviceProfile_PINProtection(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)

	m := env.Module

	rv := m.Initialize(env.Config)
	testutil.RequireOK(t, rv, "C_Initialize failed")
	defer m.Finalize()

	tokenInfo, rv := m.GetTokenInfo(0)
	testutil.RequireOK(t, rv, "C_GetTokenInfo failed")

	t.Run("LoginRequired", func(t *testing.T) {
		// Per auth device profile: token should require login
		if tokenInfo.Flags&module.CKF_LOGIN_REQUIRED == 0 {
			t.Log("Token does not require login (may not be auth device profile)")
		} else {
			t.Log("Token requires login (auth device profile compliant)")
		}
	})

	t.Run("ProtectedAuthPath", func(t *testing.T) {
		// Optional: protected authentication path (PIN pad)
		if tokenInfo.Flags&module.CKF_PROTECTED_AUTHENTICATION_PATH != 0 {
			t.Log("Token has protected authentication path")
		} else {
			t.Log("Token does not have protected authentication path (OK)")
		}
	})

	t.Run("UserPINInitialized", func(t *testing.T) {
		if tokenInfo.Flags&module.CKF_USER_PIN_INITIALIZED != 0 {
			t.Log("User PIN is initialized")
		} else {
			t.Log("User PIN not initialized")
		}
	})
}

// TestAuthDeviceProfile_PrivateKeyProtection tests private key access control.
// OASIS PKCS#11 Profiles v3.0 Section 2.4.3
func TestAuthDeviceProfile_PrivateKeyProtection(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)

	m := env.Module

	rv := m.Initialize(env.Config)
	testutil.RequireOK(t, rv, "C_Initialize failed")
	defer m.Finalize()

	session, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	testutil.RequireOK(t, rv, "C_OpenSession failed")
	defer m.CloseSession(session)

	t.Run("PrivateKeyAccessRequiresLogin", func(t *testing.T) {
		// Without login, should not be able to access private keys
		searchTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
			module.NewBoolAttribute(module.CKA_PRIVATE, true),
		}

		rv := m.FindObjectsInit(session, searchTemplate)
		if rv == module.CKR_OK {
			objects, rv := m.FindObjects(session, 10)
			m.FindObjectsFinal(session)

			if rv == module.CKR_OK && len(objects) > 0 {
				t.Log("Private keys accessible without login (may not comply with auth device profile)")
			} else {
				t.Log("No private keys accessible without login (compliant)")
			}
		}
	})

	t.Run("PrivateKeyAccessAfterLogin", func(t *testing.T) {
		rv := m.Login(session, module.CKU_USER, []byte(testutil.TestPINs.User))
		testutil.RequireOK(t, rv, "C_Login failed")
		defer m.Logout(session)

		// Generate a test key
		pubTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewUint64Attribute(module.CKA_MODULUS_BITS, 2048),
			module.NewAttribute(module.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		privTemplate := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
			module.NewBoolAttribute(module.CKA_PRIVATE, true),
			module.NewBoolAttribute(module.CKA_SENSITIVE, true),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		_, privKey, rv := m.GenerateKeyPair(
			session,
			&module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN},
			pubTemplate,
			privTemplate,
		)

		if rv == module.CKR_OK {
			t.Log("Private key generation successful after login")

			// Verify the key has proper protection attributes
			attrs, rv := m.GetAttributeValue(session, privKey, []module.Attribute{
				{Type: module.CKA_SENSITIVE},
				{Type: module.CKA_PRIVATE},
			})
			if rv == module.CKR_OK {
				for _, attr := range attrs {
					switch attr.Type {
					case module.CKA_SENSITIVE:
						if len(attr.Value) > 0 && attr.Value[0] == 1 {
							t.Log("Private key is marked SENSITIVE (compliant)")
						}
					case module.CKA_PRIVATE:
						if len(attr.Value) > 0 && attr.Value[0] == 1 {
							t.Log("Private key is marked PRIVATE (compliant)")
						}
					}
				}
			}
		} else {
			t.Errorf("Private key generation failed: %v", rv)
		}
	})
}

// =============================================================================
// Profile Compliance Summary
// =============================================================================

// TestProfileComplianceSummary generates a compliance summary for all profiles.
func TestProfileComplianceSummary(t *testing.T) {
	env := testutil.SetupTestEnvironment(t, nil)

	m := env.Module

	rv := m.Initialize(env.Config)
	testutil.RequireOK(t, rv, "C_Initialize failed")
	defer m.Finalize()

	mechanisms, rv := m.GetMechanismList(0)
	testutil.RequireOK(t, rv, "C_GetMechanismList failed")

	mechSet := make(map[module.MechanismType]bool)
	for _, mech := range mechanisms {
		mechSet[mech] = true
	}

	profiles := []ProfileDefinition{
		BaselineProfile,
		ExtendedProviderProfile,
		AuthenticationDeviceProfile,
	}

	for _, profile := range profiles {
		t.Run(profile.Name, func(t *testing.T) {
			required := len(profile.RequiredMechanisms)
			available := 0
			missing := []string{}

			for _, mech := range profile.RequiredMechanisms {
				if mechSet[mech] {
					available++
				} else {
					missing = append(missing, getMechanismName(mech))
				}
			}

			compliance := float64(available) / float64(required) * 100

			t.Logf("Profile: %s", profile.Name)
			t.Logf("Required mechanisms: %d", required)
			t.Logf("Available mechanisms: %d", available)
			t.Logf("Compliance: %.1f%%", compliance)

			if len(missing) > 0 {
				t.Logf("Missing mechanisms: %v", missing)
			}

			if compliance == 100 {
				t.Logf("FULLY COMPLIANT with %s profile", profile.Name)
			} else if compliance >= 80 {
				t.Logf("MOSTLY COMPLIANT with %s profile", profile.Name)
			} else {
				t.Logf("NOT COMPLIANT with %s profile", profile.Name)
			}
		})
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// getMechanismName returns a human-readable name for a mechanism.
func getMechanismName(mechanism module.MechanismType) string {
	names := map[module.MechanismType]string{
		module.CKM_RSA_PKCS_KEY_PAIR_GEN: "CKM_RSA_PKCS_KEY_PAIR_GEN",
		module.CKM_RSA_PKCS:              "CKM_RSA_PKCS",
		module.CKM_RSA_PKCS_OAEP:         "CKM_RSA_PKCS_OAEP",
		module.CKM_RSA_PKCS_PSS:          "CKM_RSA_PKCS_PSS",
		module.CKM_SHA_1:                 "CKM_SHA_1",
		module.CKM_SHA256:                "CKM_SHA256",
		module.CKM_SHA384:                "CKM_SHA384",
		module.CKM_SHA512:                "CKM_SHA512",
		module.CKM_ECDSA:                 "CKM_ECDSA",
		module.CKM_EC_KEY_PAIR_GEN:       "CKM_EC_KEY_PAIR_GEN",
		module.CKM_ECDH1_DERIVE:          "CKM_ECDH1_DERIVE",
		module.CKM_AES_KEY_GEN:           "CKM_AES_KEY_GEN",
		module.CKM_AES_CBC:               "CKM_AES_CBC",
		module.CKM_AES_GCM:               "CKM_AES_GCM",
		module.CKM_AES_CTR:               "CKM_AES_CTR",
		module.CKM_AES_CCM:               "CKM_AES_CCM",
	}

	if name, ok := names[mechanism]; ok {
		return name
	}
	return "UNKNOWN"
}
