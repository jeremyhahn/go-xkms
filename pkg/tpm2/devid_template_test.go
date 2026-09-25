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

package tpm2

import (
	"crypto/elliptic"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file pins the Recoverable IDevID/IAK key creation templates of TCG
// "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12, section 7.3.4,
// against the specification's own tables, and pins the guard that refuses a
// departure from them before TPM2_CreatePrimary.
//
// Every field checked here is an input to a primary key's derivation. A
// template that gets one of them wrong does not produce a slightly wrong key,
// it produces a different key under a different Name that no other
// implementation of the specification can recreate -- which is why each
// mutation below is a test rather than a comment.

// devidPolicyFor is the authPolicy the creation path assigns before handing a
// template to the TPM, so a template under test is only conformant with it.
func devidPolicyFor(t *testing.T, kind DevIDKeyKind, nameAlg tpm2.TPMIAlgHash) tpm2.TPM2BDigest {
	t.Helper()
	digest, err := DevIDKeyPolicyDigest(kind, nameAlg)
	require.NoError(t, err)
	return tpm2.TPM2BDigest{Buffer: digest}
}

// conformantDevIDTemplate builds the template the creation path builds, with
// its policy already assigned, and asserts it passes the guard.
func conformantDevIDTemplate(t *testing.T, spec DevIDTemplateSpec) tpm2.TPMTPublic {
	t.Helper()
	template, err := spec.Template()
	require.NoError(t, err)
	template.AuthPolicy = devidPolicyFor(t, spec.Kind, template.NameAlg)
	require.NoError(t, assertDevIDTemplateConformant(spec.Kind, template),
		"the template the creation path builds must be conformant")
	return template
}

// TestDevIDUniqueString_Table2 pins section 7.3.1, Table 2: the required
// unique string of each key purpose, with the specification's own hex.
func TestDevIDUniqueString_Table2(t *testing.T) {
	idevid, err := DevIDUniqueString(DevIDKeySigning, "")
	require.NoError(t, err)
	assert.Equal(t, []byte{0x49, 0x44, 0x45, 0x56, 0x49, 0x44}, idevid, "'IDEVID'")
	assert.Equal(t, DevIDUniqueIDevID, string(idevid))

	iak, err := DevIDUniqueString(DevIDKeyAttestation, "")
	require.NoError(t, err)
	assert.Equal(t, []byte{0x49, 0x41, 0x4B}, iak, "'IAK'")
	assert.Equal(t, DevIDUniqueIAK, string(iak))

	// "Neither version of the unique string is NUL terminated (i.e., the NUL
	// termination is not supplied to the TPM.)"
	assert.NotContains(t, idevid, byte(0x00))
	assert.NotContains(t, iak, byte(0x00))

	// "the device_str is a sequence of printable ASCII octets ... that are
	// concatenated to the required unique string".
	withDevice, err := DevIDUniqueString(DevIDKeySigning, "SN-0000-0001")
	require.NoError(t, err)
	assert.Equal(t, "IDEVIDSN-0000-0001", string(withDevice))
}

// TestDevIDUniqueString_RefusesInvalidInput covers the error paths: a key kind
// Table 2 defines no string for, and a device string that is not printable
// ASCII -- including the NUL the specification singles out.
func TestDevIDUniqueString_RefusesInvalidInput(t *testing.T) {
	unique, err := DevIDUniqueString(DevIDKeyKind(0), "")
	assert.ErrorIs(t, err, ErrDevIDUniqueString)
	assert.Nil(t, unique)

	for _, deviceString := range []string{"\x00", "SN\x00001", "SN\n0001", "SN\x7f0001", "café"} {
		unique, err := DevIDUniqueString(DevIDKeySigning, deviceString)
		assert.ErrorIs(t, err, ErrDevIDUniqueString, "%q is not printable ASCII", deviceString)
		assert.Nil(t, unique)
	}
}

// TestDevIDTemplateSpec_TemplateH1 pins Template H-1 (section 7.3.4.2,
// Table 4) field by field, for both key purposes.
func TestDevIDTemplateSpec_TemplateH1(t *testing.T) {
	t.Run("IDevID", func(t *testing.T) {
		template := conformantDevIDTemplate(t,
			DevIDTemplateSpec{Kind: DevIDKeySigning, Algorithm: x509.RSA})

		assert.Equal(t, tpm2.TPMAlgRSA, template.Type)
		assert.Equal(t, tpm2.TPMAlgSHA256, template.NameAlg)

		// Table 3 (H-0), with "DevID (signing): Restricted = 0".
		a := template.ObjectAttributes
		assert.True(t, a.FixedTPM)
		assert.False(t, a.STClear)
		assert.True(t, a.FixedParent)
		assert.True(t, a.SensitiveDataOrigin)
		assert.True(t, a.UserWithAuth)
		assert.True(t, a.AdminWithPolicy)
		assert.False(t, a.NoDA)
		assert.False(t, a.EncryptedDuplication)
		assert.False(t, a.Restricted)
		assert.False(t, a.Decrypt)
		assert.True(t, a.SignEncrypt)

		parms, err := template.Parameters.RSADetail()
		require.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgNull, parms.Symmetric.Algorithm, "symmetric->algorithm = TPM_ALG_NULL")
		assert.Equal(t, tpm2.TPMAlgNull, parms.Scheme.Scheme, "scheme->scheme = TPM_ALG_NULL (Signing)")
		assert.Equal(t, tpm2.TPMKeyBits(2048), parms.KeyBits)
		assert.Equal(t, uint32(0), parms.Exponent, "exponent = 0")

		unique, err := template.Unique.RSA()
		require.NoError(t, err)
		assert.Equal(t, []byte("IDEVID"), unique.Buffer)
	})

	t.Run("IAK", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			scheme tpm2.TPMAlgID
		}{
			{"RSASSA", tpm2.TPMAlgRSASSA},
			{"RSAPSS", tpm2.TPMAlgRSAPSS},
		} {
			t.Run(tc.name, func(t *testing.T) {
				template := conformantDevIDTemplate(t, DevIDTemplateSpec{
					Kind:      DevIDKeyAttestation,
					Algorithm: x509.RSA,
					Scheme:    tc.scheme,
				})

				// "AK: Restricted = 1" (Table 3).
				assert.True(t, template.ObjectAttributes.Restricted)

				parms, err := template.Parameters.RSADetail()
				require.NoError(t, err)
				assert.Equal(t, tpm2.TPMAlgNull, parms.Symmetric.Algorithm)
				assert.Equal(t, tc.scheme, parms.Scheme.Scheme)
				assert.Equal(t, uint32(0), parms.Exponent)

				// "scheme->details ... TPM_ALG_SHA256 (AK)": a Restricted
				// signing key must name a hash, and the template's nameAlg is
				// the one it names.
				hashAlg, fixed, err := rsaKeySchemeHash(parms.Scheme)
				require.NoError(t, err)
				assert.True(t, fixed)
				assert.Equal(t, template.NameAlg, hashAlg)

				unique, err := template.Unique.RSA()
				require.NoError(t, err)
				assert.Equal(t, []byte("IAK"), unique.Buffer)
			})
		}
	})
}

// TestDevIDTemplateSpec_TemplatesH2ToH4 pins the three ECC suites (sections
// 7.3.4.3-7.3.4.5, Tables 5-7), which differ only in curve and nameAlg.
func TestDevIDTemplateSpec_TemplatesH2ToH4(t *testing.T) {
	cases := []struct {
		table   string
		curve   elliptic.Curve
		curveID tpm2.TPMECCCurve
		nameAlg tpm2.TPMIAlgHash
	}{
		{"H-2", elliptic.P256(), tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256},
		{"H-3", elliptic.P384(), tpm2.TPMECCNistP384, tpm2.TPMAlgSHA384},
		{"H-4", elliptic.P521(), tpm2.TPMECCNistP521, tpm2.TPMAlgSHA512},
	}
	for _, tc := range cases {
		for _, kind := range []DevIDKeyKind{DevIDKeySigning, DevIDKeyAttestation} {
			t.Run(tc.table+"/"+kind.String(), func(t *testing.T) {
				template := conformantDevIDTemplate(t, DevIDTemplateSpec{
					Kind:      kind,
					Algorithm: x509.ECDSA,
					Curve:     tc.curve,
				})

				assert.Equal(t, tpm2.TPMAlgECC, template.Type)
				assert.Equal(t, tc.nameAlg, template.NameAlg,
					"%s pairs its curve with this nameAlg", tc.table)
				assert.Equal(t, kind == DevIDKeyAttestation, template.ObjectAttributes.Restricted)

				parms, err := template.Parameters.ECCDetail()
				require.NoError(t, err)
				assert.Equal(t, tc.curveID, parms.CurveID)
				assert.Equal(t, tpm2.TPMAlgNull, parms.Symmetric.Algorithm, "symmetric->algorithm = TPM_ALG_NULL")
				assert.Equal(t, tpm2.TPMAlgNull, parms.KDF.Scheme, "kdf->scheme = TPM_ALG_NULL")
				assert.Equal(t, tpm2.TPMAlgECDSA, parms.Scheme.Scheme, "scheme->scheme = TPM_ALG_ECDSA")

				// The tables say "scheme->details = NULL", which no TPM can
				// represent: TPM2_CreatePrimary answers TPM_RC_HASH for a
				// TPMI_ALG_HASH of TPM_ALG_NULL. See eccTemplate, and
				// TestDevIDTemplate_ECDSANullDetailsIsRefusedByTheTPM, which
				// measures it. The details name the template's own nameAlg.
				hashAlg, fixed, err := eccKeySchemeHash(parms.Scheme)
				require.NoError(t, err)
				assert.True(t, fixed)
				assert.Equal(t, tc.nameAlg, hashAlg)

				unique, err := template.Unique.ECC()
				require.NoError(t, err)
				assert.Equal(t, devidUniqueStrings[kind], string(unique.X.Buffer),
					"the unique string goes in unique.x")
				assert.Empty(t, unique.Y.Buffer)
			})
		}
	}
}

// TestDevIDTemplateSpec_CarriesTheDeviceString covers the optional per-device
// string of section 7.3.1 reaching the template's unique field.
func TestDevIDTemplateSpec_CarriesTheDeviceString(t *testing.T) {
	rsa := conformantDevIDTemplate(t, DevIDTemplateSpec{
		Kind:         DevIDKeySigning,
		Algorithm:    x509.RSA,
		DeviceString: "SN-0000-0001",
	})
	rsaUnique, err := rsa.Unique.RSA()
	require.NoError(t, err)
	assert.Equal(t, "IDEVIDSN-0000-0001", string(rsaUnique.Buffer))

	ecc := conformantDevIDTemplate(t, DevIDTemplateSpec{
		Kind:         DevIDKeyAttestation,
		Algorithm:    x509.ECDSA,
		DeviceString: "SN-0000-0001",
	})
	eccUnique, err := ecc.Unique.ECC()
	require.NoError(t, err)
	assert.Equal(t, "IAKSN-0000-0001", string(eccUnique.X.Buffer))
}

// TestDevIDTemplateSpec_RefusesUnbuildableSuites covers the builder's error
// paths: a suite the specification defines no template for, a scheme H-1 does
// not allow for the key's purpose, and a unique string too large for the
// crypto suite's unique field (section 7.3.1: "The combined string size MUST
// NOT be larger than the allowed unique size for the crypto suite selected").
func TestDevIDTemplateSpec_RefusesUnbuildableSuites(t *testing.T) {
	t.Run("hash algorithm with no key policy", func(t *testing.T) {
		_, err := DevIDTemplateSpec{
			Kind:      DevIDKeySigning,
			Algorithm: x509.RSA,
			NameAlg:   tpm2.TPMAlgSHA1,
		}.Template()
		assert.ErrorIs(t, err, ErrDevIDTemplateSuiteUnsupported)
	})

	t.Run("curve with no template", func(t *testing.T) {
		// P-224 is representable in Go and creatable on some TPMs, but
		// section 7.3.4 gives it no template. It is refused as an unsupported
		// crypto suite, the same error every "the specification defines no
		// template for this" case reports -- including H-5 SM2, which cannot
		// reach here because crypto/elliptic has no SM2 curve.
		_, err := DevIDTemplateSpec{
			Kind:      DevIDKeySigning,
			Algorithm: x509.ECDSA,
			Curve:     elliptic.P224(),
		}.Template()
		assert.ErrorIs(t, err, ErrDevIDTemplateSuiteUnsupported)
		assert.Contains(t, err.Error(), "H-5",
			"the refusal names the one defined suite this library does not implement")
	})

	t.Run("a configuration naming SM2 is refused before the template", func(t *testing.T) {
		// H-5's suite cannot be expressed as a DevIDTemplateSpec at all: Go
		// has no SM2 curve. The refusal a deployment actually meets is the
		// configuration one, so that is what is pinned.
		curve, err := types.ParseCurve("SM2")
		assert.ErrorIs(t, err, types.ErrUnknownCurve)
		assert.Nil(t, curve)

		_, ok := eccCurveIDs["SM2-P256"]
		assert.False(t, ok, "crypto/elliptic gained an SM2 curve; H-5 can be revisited")
	})

	t.Run("a DevID may not name a scheme", func(t *testing.T) {
		_, err := DevIDTemplateSpec{
			Kind:      DevIDKeySigning,
			Algorithm: x509.RSA,
			Scheme:    tpm2.TPMAlgRSASSA,
		}.Template()
		assert.ErrorIs(t, err, ErrDevIDTemplateSuiteUnsupported)
	})

	t.Run("an AK may not name an encryption scheme", func(t *testing.T) {
		_, err := DevIDTemplateSpec{
			Kind:      DevIDKeyAttestation,
			Algorithm: x509.RSA,
			Scheme:    tpm2.TPMAlgOAEP,
		}.Template()
		var schemeErr *SchemeNotImplementedError
		assert.ErrorAs(t, err, &schemeErr)
	})

	t.Run("device string larger than the unique field", func(t *testing.T) {
		// A P-256 coordinate is 32 octets; 'IDEVID' plus 27 is 33.
		_, err := DevIDTemplateSpec{
			Kind:         DevIDKeySigning,
			Algorithm:    x509.ECDSA,
			DeviceString: strings.Repeat("S", 27),
		}.Template()
		assert.ErrorIs(t, err, ErrDevIDUniqueStringTooLong)
	})

	t.Run("unsupported key algorithm", func(t *testing.T) {
		_, err := DevIDTemplateSpec{
			Kind:      DevIDKeySigning,
			Algorithm: x509.Ed25519,
		}.Template()
		var algErr *AlgorithmNotSupportedError
		assert.ErrorAs(t, err, &algErr)
	})

	t.Run("unsupported RSA modulus size", func(t *testing.T) {
		_, err := DevIDTemplateSpec{
			Kind:      DevIDKeySigning,
			Algorithm: x509.RSA,
			KeyBits:   1234,
		}.Template()
		var sizeErr *KeySizeNotSupportedError
		assert.ErrorAs(t, err, &sizeErr)
	})

	t.Run("unknown key kind", func(t *testing.T) {
		_, err := DevIDTemplateSpec{Algorithm: x509.RSA}.Template()
		assert.ErrorIs(t, err, ErrDevIDUniqueString)
	})
}

// TestMustDevIDTemplate_PanicsOnInvalidSpec proves mustDevIDTemplate converts
// a spec.Template() error into a panic naming the underlying cause, mirroring
// mustKeyTemplate: it exists only for the package's own built-in template
// variables, so a failure is a defect to be caught the first time the
// package loads rather than at the first key creation.
func TestMustDevIDTemplate_PanicsOnInvalidSpec(t *testing.T) {
	invalid := DevIDTemplateSpec{
		Kind:      DevIDKeySigning,
		Algorithm: x509.RSA,
		NameAlg:   tpm2.TPMAlgSHA1,
	}
	_, wantErr := invalid.Template()
	require.Error(t, wantErr)

	assert.PanicsWithValue(t,
		"tpm: invalid built-in IDevID/IAK template: "+wantErr.Error(),
		func() { mustDevIDTemplate(invalid) })
}

// TestAssertDevIDTemplateConformant_RefusesEveryDeparture is the guard's
// mutation suite: one case per field the specification fixes, each starting
// from the template the creation path builds and breaking exactly one thing.
//
// This is what stands between a changed builder and a fleet of device
// identities no other implementation can recreate, so it is checked field by
// field rather than by comparing whole structures -- a structural comparison
// would say "not equal" without saying which derivation input moved.
func TestAssertDevIDTemplateConformant_RefusesEveryDeparture(t *testing.T) {
	rsaCases := []struct {
		name   string
		mutate func(*tpm2.TPMTPublic)
	}{
		{"fixedTPM cleared", func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false }},
		{"fixedParent cleared", func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedParent = false }},
		{"sensitiveDataOrigin cleared", func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SensitiveDataOrigin = false }},
		{"sign cleared", func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SignEncrypt = false }},
		{"userWithAuth cleared", func(p *tpm2.TPMTPublic) { p.ObjectAttributes.UserWithAuth = false }},
		{"adminWithPolicy cleared", func(p *tpm2.TPMTPublic) { p.ObjectAttributes.AdminWithPolicy = false }},
		{"decrypt set", func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Decrypt = true }},
		{"restricted set on a DevID", func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Restricted = true }},
		{"authPolicy replaced", func(p *tpm2.TPMTPublic) {
			replaced := make([]byte, len(p.AuthPolicy.Buffer))
			copy(replaced, p.AuthPolicy.Buffer)
			replaced[0] ^= 0xFF
			p.AuthPolicy = tpm2.TPM2BDigest{Buffer: replaced}
		}},

		// The audit's two named mutations.
		{"unique zeroed", func(p *tpm2.TPMTPublic) {
			p.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)})
		}},
		{"an RSA IDevID scheme is set", func(p *tpm2.TPMTPublic) {
			setRSAScheme(p, tpm2.TPMTRSAScheme{
				Scheme: tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA,
					&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
			})
		}},

		{"unique carries the wrong purpose", func(p *tpm2.TPMTPublic) {
			p.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{Buffer: []byte("IAK")})
		}},
		{"unique is NUL terminated", func(p *tpm2.TPMTPublic) {
			p.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{Buffer: append([]byte("IDEVID"), 0x00)})
		}},
		{"symmetric names a cipher", func(p *tpm2.TPMTPublic) {
			setRSASymmetric(p, tpm2.TPMTSymDefObject{
				Algorithm: tpm2.TPMAlgAES,
				KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
				Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
			})
		}},
		{"exponent set", func(p *tpm2.TPMTPublic) { setRSAExponent(p, 65537) }},
	}
	for _, tc := range rsaCases {
		t.Run("H-1/"+tc.name, func(t *testing.T) {
			template := conformantDevIDTemplate(t,
				DevIDTemplateSpec{Kind: DevIDKeySigning, Algorithm: x509.RSA})
			before := template
			tc.mutate(&template)
			require.NotEqual(t, marshalPublic(t, before), marshalPublic(t, template),
				"the mutation must actually change the template")

			err := assertDevIDTemplateConformant(DevIDKeySigning, template)
			assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
		})
	}

	eccCases := []struct {
		name   string
		mutate func(*tpm2.TPMTPublic)
	}{
		{"unique zeroed", func(p *tpm2.TPMTPublic) {
			p.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			})
		}},
		{"symmetric names a cipher", func(p *tpm2.TPMTPublic) {
			setECCParms(p, func(parms *tpm2.TPMSECCParms) {
				parms.Symmetric = tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
				}
			})
		}},
		{"kdf names a derivation function", func(p *tpm2.TPMTPublic) {
			setECCParms(p, func(parms *tpm2.TPMSECCParms) {
				parms.KDF = tpm2.TPMTKDFScheme{
					Scheme:  tpm2.TPMAlgKDF1SP800108,
					Details: tpm2.NewTPMUKDFScheme(tpm2.TPMAlgKDF1SP800108, &tpm2.TPMSKDFSchemeKDF1SP800108{HashAlg: tpm2.TPMAlgSHA256}),
				}
			})
		}},
		{"scheme cleared to TPM_ALG_NULL", func(p *tpm2.TPMTPublic) {
			setECCParms(p, func(parms *tpm2.TPMSECCParms) {
				parms.Scheme = tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull}
			})
		}},
		{"curve with no template", func(p *tpm2.TPMTPublic) {
			setECCParms(p, func(parms *tpm2.TPMSECCParms) {
				parms.CurveID = tpm2.TPMECCNistP224
			})
		}},
	}
	for _, tc := range eccCases {
		t.Run("H-2/"+tc.name, func(t *testing.T) {
			template := conformantDevIDTemplate(t,
				DevIDTemplateSpec{Kind: DevIDKeySigning, Algorithm: x509.ECDSA})
			before := template
			tc.mutate(&template)
			require.NotEqual(t, marshalPublic(t, before), marshalPublic(t, template),
				"the mutation must actually change the template")

			err := assertDevIDTemplateConformant(DevIDKeySigning, template)
			assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
		})
	}

	t.Run("authPolicy emptied", func(t *testing.T) {
		// adminWithPolicy SET with no authPolicy is refused by
		// assertAdminAuthorizable, which names the contradiction itself
		// rather than reporting a generic non-conformance: the ADMIN role
		// would be permanently unauthorizable.
		template := conformantDevIDTemplate(t,
			DevIDTemplateSpec{Kind: DevIDKeySigning, Algorithm: x509.RSA})
		template.AuthPolicy = tpm2.TPM2BDigest{}
		assert.ErrorIs(t,
			assertDevIDTemplateConformant(DevIDKeySigning, template),
			ErrAdminWithPolicyNoAuthPolicy)
	})

	t.Run("an AK without a scheme", func(t *testing.T) {
		// A Restricted signing key may not name TPM_ALG_NULL (TCG TPM 2.0
		// Library Part 1, section 25.2.3), which is why H-1 gives the AK a
		// scheme where it gives the DevID none.
		template := conformantDevIDTemplate(t, DevIDTemplateSpec{
			Kind:      DevIDKeyAttestation,
			Algorithm: x509.RSA,
		})
		setRSAScheme(&template, tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull})
		assert.ErrorIs(t,
			assertDevIDTemplateConformant(DevIDKeyAttestation, template),
			ErrDevIDTemplateNonConformant)
	})

	t.Run("a key type with no template", func(t *testing.T) {
		template := conformantDevIDTemplate(t,
			DevIDTemplateSpec{Kind: DevIDKeySigning, Algorithm: x509.RSA})
		template.Type = tpm2.TPMAlgKeyedHash
		assert.ErrorIs(t,
			assertDevIDTemplateConformant(DevIDKeySigning, template),
			ErrDevIDTemplateNonConformant)
	})

	t.Run("a nameAlg with no key policy", func(t *testing.T) {
		template := conformantDevIDTemplate(t,
			DevIDTemplateSpec{Kind: DevIDKeySigning, Algorithm: x509.RSA})
		template.NameAlg = tpm2.TPMAlgSHA1
		assert.ErrorIs(t,
			assertDevIDTemplateConformant(DevIDKeySigning, template),
			ErrDevIDPolicyUnsupported)
	})
}

// TestPackageDevIDTemplatesAreConformant checks that every IDevID and IAK
// template this package exports -- which downstream projects reach through
// sdk/go -- passes the same guard the creation path applies.
func TestPackageDevIDTemplatesAreConformant(t *testing.T) {
	cases := []struct {
		name     string
		kind     DevIDKeyKind
		template tpm2.TPMTPublic
	}{
		{"RSASSAAKTemplate", DevIDKeyAttestation, RSASSAAKTemplate},
		{"RSAPSSAKTemplate", DevIDKeyAttestation, RSAPSSAKTemplate},
		{"ECCAKP256Template", DevIDKeyAttestation, ECCAKP256Template},
		{"ECCAKP384Template", DevIDKeyAttestation, ECCAKP384Template},
		{"ECCAKP521Template", DevIDKeyAttestation, ECCAKP521Template},
		{"RSASSAIDevIDTemplate", DevIDKeySigning, RSASSAIDevIDTemplate},
		{"RSAPSSIDevIDTemplate", DevIDKeySigning, RSAPSSIDevIDTemplate},
		{"ECCIDevIDP256Template", DevIDKeySigning, ECCIDevIDP256Template},
		{"ECCIDevIDP384Template", DevIDKeySigning, ECCIDevIDP384Template},
		{"ECCIDevIDP521Template", DevIDKeySigning, ECCIDevIDP521Template},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The exported templates carry no authPolicy on purpose; the
			// creation path assigns it per nameAlg. Assign it here to check
			// everything else.
			assert.Empty(t, tc.template.AuthPolicy.Buffer,
				"an exported template names no authPolicy; the creation path assigns it")
			template := tc.template
			template.AuthPolicy = devidPolicyFor(t, tc.kind, template.NameAlg)
			assert.NoError(t, assertDevIDTemplateConformant(tc.kind, template))
		})
	}
}

// marshalPublic renders a template as the bytes the TPM would see, which is
// what a mutation has to change to matter.
func marshalPublic(t *testing.T, public tpm2.TPMTPublic) []byte {
	t.Helper()
	marshalled := tpm2.New2B(public)
	return marshalled.Bytes()
}

// setRSAScheme replaces the scheme of an RSA template's parameters.
func setRSAScheme(public *tpm2.TPMTPublic, scheme tpm2.TPMTRSAScheme) {
	parms, err := public.Parameters.RSADetail()
	if err != nil {
		panic(err)
	}
	updated := *parms
	updated.Scheme = scheme
	public.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &updated)
}

// setRSASymmetric replaces the symmetric definition of an RSA template.
func setRSASymmetric(public *tpm2.TPMTPublic, sym tpm2.TPMTSymDefObject) {
	parms, err := public.Parameters.RSADetail()
	if err != nil {
		panic(err)
	}
	updated := *parms
	updated.Symmetric = sym
	public.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &updated)
}

// setRSAExponent replaces the exponent of an RSA template.
func setRSAExponent(public *tpm2.TPMTPublic, exponent uint32) {
	parms, err := public.Parameters.RSADetail()
	if err != nil {
		panic(err)
	}
	updated := *parms
	updated.Exponent = exponent
	public.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &updated)
}

// setECCParms edits the parameters of an ECC template in place.
func setECCParms(public *tpm2.TPMTPublic, edit func(*tpm2.TPMSECCParms)) {
	parms, err := public.Parameters.ECCDetail()
	if err != nil {
		panic(err)
	}
	updated := *parms
	edit(&updated)
	public.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &updated)
}
