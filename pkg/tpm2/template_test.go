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
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// eccSchemeOf reads the signing scheme out of a built ECC template.
func eccSchemeOf(t *testing.T, template tpm2.TPMTPublic) tpm2.TPMTECCScheme {
	t.Helper()
	detail, err := template.Parameters.ECCDetail()
	require.NoError(t, err)
	return detail.Scheme
}

// rsaParmsOf reads the RSA parameters out of a built template.
func rsaParmsOf(t *testing.T, template tpm2.TPMTPublic) *tpm2.TPMSRSAParms {
	t.Helper()
	detail, err := template.Parameters.RSADetail()
	require.NoError(t, err)
	return detail
}

// TestKeyTemplateSpec_ZeroValueIsAnAgileRSASigningKey pins the documented
// default. A spec that names nothing must produce the key this package has
// always created by default -- RSA-2048, signing, unrestricted -- with the one
// change that matters: no fixed scheme, so the digest is chosen per operation.
func TestKeyTemplateSpec_ZeroValueIsAnAgileRSASigningKey(t *testing.T) {
	template, err := KeyTemplateSpec{}.Template()
	require.NoError(t, err)

	assert.Equal(t, tpm2.TPMAlgRSA, template.Type)
	assert.Equal(t, tpm2.TPMAlgSHA256, template.NameAlg)
	assert.True(t, template.ObjectAttributes.SignEncrypt)
	assert.False(t, template.ObjectAttributes.Decrypt)
	assert.False(t, template.ObjectAttributes.Restricted)

	parms := rsaParmsOf(t, template)
	assert.Equal(t, tpm2.TPMKeyBits(2048), parms.KeyBits)
	assert.Equal(t, tpm2.TPMAlgNull, parms.Scheme.Scheme,
		"a general-purpose signing key must not fix its scheme")
}

// TestKeyTemplateSpec_EveryDefinedRSASizeBuilds proves the modulus size comes
// from the request rather than from a constant. A caller asking for RSA-4096
// used to receive a 2048-bit key from a template that hardcoded the size.
func TestKeyTemplateSpec_EveryDefinedRSASizeBuilds(t *testing.T) {
	for _, keyBits := range []uint16{1024, 2048, 3072, 4096} {
		template, err := KeyTemplateSpec{Algorithm: x509.RSA, KeyBits: keyBits}.Template()
		require.NoError(t, err, "RSA-%d", keyBits)

		parms := rsaParmsOf(t, template)
		assert.Equal(t, tpm2.TPMKeyBits(keyBits), parms.KeyBits)

		unique, err := template.Unique.RSA()
		require.NoError(t, err)
		assert.Len(t, unique.Buffer, int(keyBits)/8,
			"the unique buffer must be sized for the modulus, not for a fixed 2048 bits")
	}
}

// TestKeyTemplateSpec_UndefinedRSASizeRefusedByName is the bad-input case. A
// size TPM 2.0 does not define is refused with an error naming both what was
// asked and what is defined, never rounded to a size the caller did not choose.
func TestKeyTemplateSpec_UndefinedRSASizeRefusedByName(t *testing.T) {
	_, err := KeyTemplateSpec{Algorithm: x509.RSA, KeyBits: 2047}.Template()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeySize)

	var sizeErr *KeySizeNotSupportedError
	require.True(t, errors.As(err, &sizeErr))
	assert.Equal(t, 2047, sizeErr.Requested)
	assert.Contains(t, sizeErr.Supported, 2048)
	assert.Contains(t, err.Error(), "2047")
}

// TestKeyTemplateSpec_EveryRepresentableCurveBuilds proves the curve comes from
// the request. P-224 in particular has never had a template in this package, so
// a caller asking for it was previously handed P-256.
func TestKeyTemplateSpec_EveryRepresentableCurveBuilds(t *testing.T) {
	for curve, want := range map[elliptic.Curve]tpm2.TPMECCCurve{
		elliptic.P224(): tpm2.TPMECCNistP224,
		elliptic.P256(): tpm2.TPMECCNistP256,
		elliptic.P384(): tpm2.TPMECCNistP384,
		elliptic.P521(): tpm2.TPMECCNistP521,
	} {
		template, err := KeyTemplateSpec{Algorithm: x509.ECDSA, Curve: curve}.Template()
		require.NoError(t, err, curve.Params().Name)

		detail, err := template.Parameters.ECCDetail()
		require.NoError(t, err)
		assert.Equal(t, want, detail.CurveID, curve.Params().Name)
		assert.Equal(t, tpm2.TPMAlgNull, detail.Scheme.Scheme)
	}
}

// TestKeyTemplateSpec_UnrepresentableCurveRefusedByName is the bad-input case
// that replaces the silent substitution.
//
// A curve this package cannot represent must be refused by name. The previous
// create path logged a debug line and built a P-256 key, so a caller that asked
// for something else was told it had succeeded and received a key of a security
// level it did not choose.
func TestKeyTemplateSpec_UnrepresentableCurveRefusedByName(t *testing.T) {
	_, err := KeyTemplateSpec{Algorithm: x509.ECDSA, Curve: unsupportedCurve{}}.Template()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCurveNotSupported)

	var curveErr *CurveNotSupportedError
	require.True(t, errors.As(err, &curveErr))
	assert.Equal(t, "unsupported-test-curve", curveErr.Requested)
	assert.Contains(t, curveErr.Supported, "P-256")
}

// TestKeyTemplateSpec_FixedSchemeCarriesItsHash covers the deliberate opposite
// of the default: a caller that wants the device itself to refuse anything but
// one scheme gets a public area that says so.
func TestKeyTemplateSpec_FixedSchemeCarriesItsHash(t *testing.T) {
	template, err := KeyTemplateSpec{
		Algorithm:  x509.ECDSA,
		Curve:      elliptic.P384(),
		Scheme:     tpm2.TPMAlgECDSA,
		SchemeHash: tpm2.TPMAlgSHA384,
	}.Template()
	require.NoError(t, err)

	scheme := eccSchemeOf(t, template)
	require.Equal(t, tpm2.TPMAlgECDSA, scheme.Scheme)
	details, err := scheme.Details.ECDSA()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgSHA384, details.HashAlg)
}

// TestKeyTemplateSpec_SchemeWithoutHashRefused is the bad-input case for the
// above: a scheme with no hash is not a valid TPMT_SIG_SCHEME.
func TestKeyTemplateSpec_SchemeWithoutHashRefused(t *testing.T) {
	_, err := KeyTemplateSpec{
		Algorithm: x509.ECDSA,
		Scheme:    tpm2.TPMAlgECDSA,
	}.Template()
	assert.ErrorIs(t, err, ErrSchemeHashRequired)
}

// TestKeyTemplateSpec_HashWithoutSchemeRefused covers the mirror mistake: a
// scheme-less key fixes no hash, so naming one is a contradiction that would
// otherwise be silently discarded.
func TestKeyTemplateSpec_HashWithoutSchemeRefused(t *testing.T) {
	_, err := KeyTemplateSpec{
		Algorithm:  x509.ECDSA,
		SchemeHash: tpm2.TPMAlgSHA256,
	}.Template()
	assert.ErrorIs(t, err, ErrSchemeHashUnexpected)
}

// TestKeyTemplateSpec_RestrictedSigningKeyRequiresScheme protects the
// attestation templates from the change made to the general-purpose ones. A
// restricted signing key may not use TPM_ALG_NULL (TCG TPM 2.0 Library Part 1,
// section 25.2.3), and the TPM would refuse to create one.
func TestKeyTemplateSpec_RestrictedSigningKeyRequiresScheme(t *testing.T) {
	_, err := KeyTemplateSpec{
		Algorithm:  x509.RSA,
		Restricted: true,
		Sign:       true,
	}.Template()
	assert.ErrorIs(t, err, ErrRestrictedSchemeRequired)

	// Naming one makes it valid.
	template, err := KeyTemplateSpec{
		Algorithm:  x509.RSA,
		Restricted: true,
		Sign:       true,
		Scheme:     tpm2.TPMAlgRSASSA,
		SchemeHash: tpm2.TPMAlgSHA256,
	}.Template()
	require.NoError(t, err)
	assert.True(t, template.ObjectAttributes.Restricted)

	// A restricted DECRYPTION key is a different case: a storage parent is
	// restricted and scheme-less, and must stay buildable.
	_, err = KeyTemplateSpec{
		Algorithm:  x509.RSA,
		Restricted: true,
		Decrypt:    true,
	}.Template()
	assert.NoError(t, err)
}

// TestKeyTemplateSpec_DecryptionKeyCarriesTheDecryptAttribute proves the
// sign/decrypt distinction is driven by the spec rather than by patching a
// signing template after the fact.
func TestKeyTemplateSpec_DecryptionKeyCarriesTheDecryptAttribute(t *testing.T) {
	template, err := KeyTemplateSpec{Algorithm: x509.RSA, Decrypt: true}.Template()
	require.NoError(t, err)

	assert.True(t, template.ObjectAttributes.Decrypt)
	assert.False(t, template.ObjectAttributes.SignEncrypt)
	assert.False(t, template.ObjectAttributes.Restricted,
		"a decryption key must stay unrestricted so TPM2_RSA_Decrypt may be used on it")

	parms := rsaParmsOf(t, template)
	assert.Equal(t, tpm2.TPMAlgNull, parms.Scheme.Scheme)
}

// TestKeyTemplateSpec_UnimplementedSchemeRefusedByName proves this package
// refuses to create a key it could not subsequently use.
//
// ECDAA is a real TPM 2.0 signature scheme, and a device may well implement it,
// but no code path here can sign with it. Creating the key anyway would be the
// advertised-but-broken shape in miniature, so the refusal names the gap and
// says it is this package's, not the device's.
func TestKeyTemplateSpec_UnimplementedSchemeRefusedByName(t *testing.T) {
	_, err := KeyTemplateSpec{
		Algorithm:  x509.ECDSA,
		Scheme:     tpm2.TPMAlgECDAA,
		SchemeHash: tpm2.TPMAlgSHA256,
	}.Template()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSchemeNotImplemented)
	assert.NotErrorIs(t, err, ErrAlgorithmNotSupported,
		"a gap in this package must not be reported as a gap in the device")

	var schemeErr *SchemeNotImplementedError
	require.True(t, errors.As(err, &schemeErr))
	assert.Contains(t, schemeErr.Implemented, "ECDSA")
}

// TestKeyTemplateSpec_UnsupportedAlgorithmRefused covers a key type this
// package does not build at all.
func TestKeyTemplateSpec_UnsupportedAlgorithmRefused(t *testing.T) {
	_, err := KeyTemplateSpec{Algorithm: x509.Ed25519}.Template()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAlgorithmNotSupported)
}

// TestMustKeyTemplate_PanicsOnInvalidSpec proves mustKeyTemplate converts a
// spec.Template() error into a panic naming the underlying cause, per its own
// contract: it exists only for package-level template variables, where a
// failure is a mistake in this file to be caught the first time the package
// loads.
func TestMustKeyTemplate_PanicsOnInvalidSpec(t *testing.T) {
	invalid := KeyTemplateSpec{Algorithm: x509.Ed25519}
	_, wantErr := invalid.Template()
	require.Error(t, wantErr)

	assert.PanicsWithValue(t,
		"tpm: invalid built-in key template: "+wantErr.Error(),
		func() { mustKeyTemplate(invalid) })
}

// TestBuiltInTemplates_AreScehemeAgile pins the templates the rest of the
// package still exposes. The three general-purpose signing templates must name
// no scheme, and the PSS template must keep the one it names on purpose.
func TestBuiltInTemplates_AreScehemeAgile(t *testing.T) {
	for name, template := range map[string]tpm2.TPMTPublic{
		"ECCP256Template": ECCP256Template,
		"ECCP384Template": ECCP384Template,
		"ECCP521Template": ECCP521Template,
	} {
		assert.Equal(t, tpm2.TPMAlgNull, eccSchemeOf(t, template).Scheme, name)
	}

	assert.Equal(t, tpm2.TPMAlgNull, rsaParmsOf(t, RSASSATemplate).Scheme.Scheme,
		"RSASSATemplate is the general-purpose RSA signing key")

	assert.Equal(t, tpm2.TPMAlgRSAPSS, rsaParmsOf(t, RSAPSSTemplate).Scheme.Scheme,
		"RSAPSSTemplate pins RSA-PSS deliberately")

	// The restricted attestation templates must NOT have been made agile: a
	// restricted signing key with TPM_ALG_NULL cannot be created.
	assert.Equal(t, tpm2.TPMAlgRSASSA, rsaParmsOf(t, RSASSAAKTemplate).Scheme.Scheme)
	assert.True(t, RSASSAAKTemplate.ObjectAttributes.Restricted)
	assert.Equal(t, tpm2.TPMAlgECDSA, eccSchemeOf(t, ECCAKP256Template).Scheme)
	assert.True(t, ECCAKP256Template.ObjectAttributes.Restricted)
}

// unsupportedCurve is an elliptic.Curve this package has no TPM curve ID for,
// standing in for the SM2, Barreto-Naehrig and Brainpool curves a TPM may
// implement but that KeyAttributes cannot express.
type unsupportedCurve struct{ elliptic.Curve }

func (unsupportedCurve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{Name: "unsupported-test-curve"}
}

// TestDescribeSpec_RendersEveryPresentField pins the shape of the
// ParametersNotSupportedError message: an operator reading "this TPM
// declined the requested key parameters: ECDSA P-256 256-bit ECDSA/SHA-256"
// needs every field that was actually set in the spec to appear, and nothing
// that was not.
func TestDescribeSpec_RendersEveryPresentField(t *testing.T) {
	tests := []struct {
		name string
		spec KeyTemplateSpec
		want string
	}{
		{
			name: "algorithm only",
			spec: KeyTemplateSpec{Algorithm: x509.RSA},
			want: "RSA",
		},
		{
			name: "algorithm and curve",
			spec: KeyTemplateSpec{Algorithm: x509.ECDSA, Curve: elliptic.P256()},
			want: "ECDSA P-256",
		},
		{
			name: "algorithm and key bits",
			spec: KeyTemplateSpec{Algorithm: x509.RSA, KeyBits: 3072},
			want: "RSA 3072-bit",
		},
		{
			name: "algorithm and scheme",
			spec: KeyTemplateSpec{Algorithm: x509.RSA, Scheme: tpm2.TPMAlgRSASSA},
			want: "RSA RSASSA",
		},
		{
			name: "scheme null is not rendered",
			spec: KeyTemplateSpec{Algorithm: x509.RSA, Scheme: tpm2.TPMAlgNull},
			want: "RSA",
		},
		{
			name: "scheme hash without a fixed scheme",
			spec: KeyTemplateSpec{Algorithm: x509.RSA, SchemeHash: tpm2.TPMAlgSHA256},
			want: "RSA/SHA-256",
		},
		{
			name: "every field present",
			spec: KeyTemplateSpec{
				Algorithm:  x509.ECDSA,
				Curve:      elliptic.P256(),
				KeyBits:    256,
				Scheme:     tpm2.TPMAlgECDSA,
				SchemeHash: tpm2.TPMAlgSHA256,
			},
			want: "ECDSA P-256 256-bit ECDSA/SHA-256",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, describeSpec(tt.spec))
		})
	}
}
