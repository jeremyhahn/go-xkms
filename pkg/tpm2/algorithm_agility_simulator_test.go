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

//go:build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file drives its matrix from the device rather than from a list written
// here. What a TPM implements varies by vendor and firmware, so the test asks
// TPM2_GetCapability which algorithms and curves are available and exercises
// exactly those -- a literal table would be a second hardcoded set of
// assumptions of the kind this change exists to remove.
//
// Every signature is verified with crypto/ecdsa or crypto/rsa against the
// public key read back out of the TPM with TPM2_ReadPublic, never against a key
// this package computed and never with the TPM's own verify command. A test
// that used either would pass with a bug on both sides of it.

// agilityHashes is the set of digests this package can name in a
// TPMT_SIG_SCHEME. It is intersected with the device's capability set before
// anything is exercised, so it bounds the matrix without asserting anything
// about the hardware.
var agilityHashes = []struct {
	crypto crypto.Hash
	tpm    tpm2.TPMIAlgHash
}{
	{crypto.SHA256, tpm2.TPMAlgSHA256},
	{crypto.SHA384, tpm2.TPMAlgSHA384},
	{crypto.SHA512, tpm2.TPMAlgSHA512},
}

// agilityCurves is the set of curves this package can represent as an
// elliptic.Curve, likewise intersected with the device's capability set.
var agilityCurves = []struct {
	curve elliptic.Curve
	tpm   tpm2.TPMECCCurve
}{
	{elliptic.P224(), tpm2.TPMECCNistP224},
	{elliptic.P256(), tpm2.TPMECCNistP256},
	{elliptic.P384(), tpm2.TPMECCNistP384},
	{elliptic.P521(), tpm2.TPMECCNistP521},
}

// deviceHashes returns the digests from agilityHashes that this TPM implements.
func deviceHashes(t *testing.T, h *simHarness) []struct {
	crypto crypto.Hash
	tpm    tpm2.TPMIAlgHash
} {
	t.Helper()
	caps, err := h.TPM.Capabilities()
	require.NoError(t, err)

	var supported []struct {
		crypto crypto.Hash
		tpm    tpm2.TPMIAlgHash
	}
	for _, hash := range agilityHashes {
		if caps.SupportsAlgorithm(hash.tpm) {
			supported = append(supported, hash)
		}
	}
	require.NotEmpty(t, supported,
		"a TPM that implements none of SHA-256/384/512 cannot sign anything this package produces")
	return supported
}

// eccPublicKeyFromHandle rebuilds the curve point from a loaded object's public
// area, so the verification key comes from the device.
func eccPublicKeyFromHandle(
	t *testing.T, h *simHarness, handle tpm2.TPMHandle) *ecdsa.PublicKey {

	t.Helper()
	readResp, err := tpm2.ReadPublic{ObjectHandle: handle}.Execute(h.TPM.Transport())
	require.NoError(t, err)
	outPub, err := readResp.OutPublic.Contents()
	require.NoError(t, err)
	require.Equal(t, tpm2.TPMAlgECC, outPub.Type)

	detail, err := outPub.Parameters.ECCDetail()
	require.NoError(t, err)
	curve, err := detail.CurveID.Curve()
	require.NoError(t, err)
	unique, err := outPub.Unique.ECC()
	require.NoError(t, err)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(unique.X.Buffer),
		Y:     new(big.Int).SetBytes(unique.Y.Buffer),
	}
}

// rsaPublicKeyFromTPM reads an RSA key's public area back out of the TPM.
func rsaPublicKeyFromTPM(
	t *testing.T, h *simHarness, attrs *types.KeyAttributes) *rsa.PublicKey {

	t.Helper()
	loadResp, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err)
	defer h.TPM.Flush(loadResp.ObjectHandle)

	readResp, err := tpm2.ReadPublic{ObjectHandle: loadResp.ObjectHandle}.Execute(h.TPM.Transport())
	require.NoError(t, err)
	outPub, err := readResp.OutPublic.Contents()
	require.NoError(t, err)
	require.Equal(t, tpm2.TPMAlgRSA, outPub.Type)

	detail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)
	unique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	pub, err := tpm2.RSAPub(detail, unique)
	require.NoError(t, err)
	return pub
}

// digestFor hashes a message with the requested algorithm.
func digestFor(hash crypto.Hash, message string) []byte {
	h := hash.New()
	h.Write([]byte(message))
	return h.Sum(nil)
}

// TestAgility_OneECCKeySignsUnderEveryDeviceHash is the decisive test for the
// scheme-hash defect.
//
// ONE key signs under every digest the device implements, and each signature is
// verified with crypto/ecdsa against the public key read out of the TPM. Before
// the templates named TPM_ALG_NULL, a P-256 key could sign under SHA-256 and
// nothing else: SHA-384 and SHA-512 were answered with TPM_RC_SCHEME, because
// TPM2_Sign requires inScheme to match the key's own scheme (TCG TPM 2.0
// Library Part 3, section 12.1) -- not because the TPM was unable to perform
// them.
//
// The curve set comes from TPM_CAP_ECC_CURVES, so the matrix follows the
// device.
func TestAgility_OneECCKeySignsUnderEveryDeviceHash(t *testing.T) {
	h := newSimHarness(t, nil)

	caps, err := h.TPM.Capabilities()
	require.NoError(t, err)
	hashes := deviceHashes(t, h)

	exercised := 0
	for _, candidate := range agilityCurves {
		if !caps.SupportsCurve(candidate.tpm) {
			t.Logf("device does not implement %s; not exercised", candidate.curve.Params().Name)
			continue
		}

		attrs := signingKeyAttrs(t,
			h, fmt.Sprintf("agility-%s", candidate.curve.Params().Name), x509.ECDSA, candidate.curve)
		_, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
		require.NoError(t, err, candidate.curve.Params().Name)

		tpmPub := eccPublicKeyFromTPM(t, h, attrs)
		require.Equal(t, candidate.curve, tpmPub.Curve)

		for _, hash := range hashes {
			digest := digestFor(hash.crypto, "the message under "+hash.crypto.String())

			attrs.Hash = hash.crypto
			signature, err := h.TPM.Sign(rand.Reader, digest, &store.SignerOpts{
				KeyAttributes: attrs,
				Backend:       h.Backend,
			})
			require.NoError(t, err,
				"%s must sign under %s: the key fixes no scheme, so the TPM has no reason to refuse",
				candidate.curve.Params().Name, hash.crypto)

			assert.True(t, ecdsa.VerifyASN1(tpmPub, digest, signature),
				"%s/%s must verify against the public key read out of the TPM",
				candidate.curve.Params().Name, hash.crypto)

			other := digestFor(hash.crypto, "a different message")
			assert.False(t, ecdsa.VerifyASN1(tpmPub, other, signature),
				"%s/%s must not verify against an unrelated digest",
				candidate.curve.Params().Name, hash.crypto)

			exercised++
		}
	}

	require.GreaterOrEqual(t, exercised, 3,
		"the device must have offered at least one curve and three digests to prove agility")
}

// TestAgility_OneECCKeySignsEveryNoneHashDigestLength covers the same key under
// hash NONE -- the sentinel meaning "I already produced the digest", which is
// what every PKCS#11 CKM_ECDSA operation arrives as.
//
// A scheme-less key has no scheme hash to fall back on, so the answer comes
// from the digest's length. The TPM requires the digest to be exactly the size
// of the hash named in inScheme (TPM_RC_SIZE otherwise), which makes the
// length-compatible algorithm the only admissible one; and because the hash
// never enters the ECDSA computation, the signature is over precisely the bytes
// supplied. Both halves are checked here: the operation succeeds, and the
// signature verifies over the caller's own digest.
func TestAgility_OneECCKeySignsEveryNoneHashDigestLength(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "agility-none-hash", x509.ECDSA, elliptic.P256())
	_, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)

	tpmPub := eccPublicKeyFromTPM(t, h, attrs)

	for _, hash := range deviceHashes(t, h) {
		digest := digestFor(hash.crypto, "already hashed by the caller")

		attrs.Hash = crypto.Hash(0)
		signature, err := h.TPM.Sign(rand.Reader, digest, &store.SignerOpts{
			KeyAttributes: attrs,
			Backend:       h.Backend,
		})
		require.NoError(t, err,
			"a %d-byte digest under hash NONE must resolve to %s", len(digest), hash.crypto)

		assert.True(t, ecdsa.VerifyASN1(tpmPub, digest, signature),
			"the signature must be over the digest the caller supplied, under %s", hash.crypto)
	}
}

// TestAgility_NoneHashRefusesUnknownDigestLength is the bad-input case for the
// inference above: a digest whose length matches no supported algorithm cannot
// be resolved, and must be refused rather than padded, truncated or rounded.
func TestAgility_NoneHashRefusesUnknownDigestLength(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "agility-none-badlen", x509.ECDSA, elliptic.P256())
	_, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)

	attrs.Hash = crypto.Hash(0)
	signature, err := h.TPM.Sign(rand.Reader, make([]byte, 20), &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	assert.Empty(t, signature)
	assert.ErrorIs(t, err, ErrSchemeHashUnresolved)
}

// TestAgility_OneRSAKeySignsUnderEveryDeviceHash is the RSA half of the matrix.
//
// One RSA key signs PKCS#1 v1.5 under every digest the device implements, each
// verified with crypto/rsa against the modulus read out of the TPM. The same
// key previously named RSASSA/SHA-256 and refused the other two.
func TestAgility_OneRSAKeySignsUnderEveryDeviceHash(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "agility-rsa", x509.RSA, nil)
	_, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)

	tpmPub := rsaPublicKeyFromTPM(t, h, attrs)

	for _, hash := range deviceHashes(t, h) {
		digest := digestFor(hash.crypto, "the RSA message under "+hash.crypto.String())

		attrs.Hash = hash.crypto
		signature, err := h.TPM.Sign(rand.Reader, digest, &store.SignerOpts{
			KeyAttributes: attrs,
			Backend:       h.Backend,
		})
		require.NoError(t, err, "RSA must sign under %s", hash.crypto)

		assert.NoError(t, rsa.VerifyPKCS1v15(tpmPub, hash.crypto, digest, signature),
			"the RSA signature under %s must verify against the modulus read out of the TPM",
			hash.crypto)

		other := digestFor(hash.crypto, "a different RSA message")
		assert.Error(t, rsa.VerifyPKCS1v15(tpmPub, hash.crypto, other, signature),
			"the signature must not verify against an unrelated digest")
	}
}

// TestAgility_EveryDeviceRSAKeySizeIsUsable proves the modulus size is the
// caller's, not a template constant.
//
// The sizes come from the device: TPM2_TestParms is asked about every size
// TPM 2.0 defines and the ones it accepts are created, signed with, and
// verified against the modulus read back out of the chip. The previous path
// built every RSA key from a template whose KeyBits was hardcoded to 2048, so a
// caller asking for anything else received a 2048-bit key and was told it had
// succeeded.
func TestAgility_EveryDeviceRSAKeySizeIsUsable(t *testing.T) {
	h := newSimHarness(t, nil)

	supported := h.TPM.SupportedRSAKeyBits()
	require.NotEmpty(t, supported, "a TPM that implements RSA must accept at least one modulus size")

	for _, keyBits := range supported {
		attrs := signingKeyAttrs(t, h, fmt.Sprintf("agility-rsa-%d", keyBits), x509.RSA, nil)
		attrs.RSAAttributes = &types.RSAAttributes{KeySize: keyBits}

		_, err := h.TPM.CreateRSA(attrs, h.Backend, true)
		require.NoError(t, err, "the device accepted RSA-%d parameters, so creation must work", keyBits)

		tpmPub := rsaPublicKeyFromTPM(t, h, attrs)
		assert.Equal(t, keyBits, tpmPub.N.BitLen(),
			"the key read back from the TPM must have the modulus size that was requested")

		digest := digestFor(crypto.SHA256, fmt.Sprintf("signed by a %d-bit key", keyBits))
		attrs.Hash = crypto.SHA256
		signature, err := h.TPM.Sign(rand.Reader, digest, &store.SignerOpts{
			KeyAttributes: attrs,
			Backend:       h.Backend,
		})
		require.NoError(t, err, "RSA-%d", keyBits)
		assert.NoError(t, rsa.VerifyPKCS1v15(tpmPub, crypto.SHA256, digest, signature),
			"RSA-%d", keyBits)
	}
}

// TestAgility_UndefinedDeviceRSAKeySizeRefusedByName is the bad-input case for
// the size gate, and it exercises a size the device genuinely declines.
//
// RSA modulus sizes are the one thing TPM2_GetCapability cannot report, so
// TPM2_TestParms is what learns them (TCG TPM 2.0 Library Part 3, section 30.3).
// Without it the refusal arrived as TPM_RC_VALUE or TPM_RC_SIZE from inside
// TPM2_Create, naming a command parameter number rather than the key size, and
// leaving the caller with no way to discover which size would have worked.
func TestAgility_UndefinedDeviceRSAKeySizeRefusedByName(t *testing.T) {
	h := newSimHarness(t, nil)

	supported := h.TPM.SupportedRSAKeyBits()

	var missing int
	for _, keyBits := range []int{4096, 3072, 1024} {
		if !containsInt(supported, keyBits) {
			missing = keyBits
			break
		}
	}
	require.NotZero(t, missing,
		"this TPM accepts every defined RSA size, so the refusal path cannot be exercised here")

	attrs := signingKeyAttrs(t, h, "agility-rsa-unsupported", x509.RSA, nil)
	attrs.RSAAttributes = &types.RSAAttributes{KeySize: missing}

	_, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeySize)

	var sizeErr *KeySizeNotSupportedError
	require.True(t, errors.As(err, &sizeErr))
	assert.Equal(t, missing, sizeErr.Requested)
	assert.Equal(t, supported, sizeErr.Supported,
		"the refusal must name the sizes the device does accept")
	assert.NotContains(t, err.Error(), "TPM_RC_",
		"a TPM response code must not be what the caller is handed")
}

// TestAgility_LegacyFixedSchemeKeyStillSignsUnderItsOwnDigest is the
// compatibility proof, and it is deliberately not an assertion about the
// current templates.
//
// It creates a key from the template shape this package used BEFORE the change
// -- ECDSA/SHA-256 named in the public area -- stores it exactly as CreateECDSA
// would, and then signs with it through the ordinary signing path. A key
// already provisioned on a deployed machine has precisely this public area, and
// it must keep working: the template change alters what NEW keys look like and
// touches nothing that is already on disk.
func TestAgility_LegacyFixedSchemeKeyStillSignsUnderItsOwnDigest(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "agility-legacy-p256", x509.ECDSA, elliptic.P256())
	handle := createLegacyFixedSchemeECCKey(t, h, attrs, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256)
	tpmPub := eccPublicKeyFromHandle(t, h, handle)
	h.TPM.Flush(handle)

	// The digest the key was created with still works.
	digest := digestFor(crypto.SHA256, "signed by a key provisioned before the change")
	attrs.Hash = crypto.SHA256
	signature, err := h.TPM.Sign(rand.Reader, digest, &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err,
		"a key provisioned under the old fixed-scheme template must keep signing under its own digest")
	assert.True(t, ecdsa.VerifyASN1(tpmPub, digest, signature))

	// Hash NONE still resolves to the key's own scheme hash rather than to the
	// digest length, which is what keeps CKM_ECDSA working for these keys.
	attrs.Hash = crypto.Hash(0)
	signature, err = h.TPM.Sign(rand.Reader, digest, &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err, "hash NONE against a fixed-scheme key must use the key's own hash")
	assert.True(t, ecdsa.VerifyASN1(tpmPub, digest, signature))
}

// TestAgility_LegacyFixedSchemeKeyRefusesWrongDigestLength is the case where
// "resolve from the key" and "resolve from the digest length" visibly diverge
// on a real device.
//
// A key provisioned under the old template with ECDSA/SHA-384 cannot sign a
// 32-byte digest at all. Resolving from the key names SHA-384 and reports that
// the digest is the wrong length; resolving from the length would name SHA-256,
// an algorithm this key does not have, and the TPM would answer TPM_RC_SCHEME.
// Both fail, but only one tells the caller what is actually wrong -- which is
// why the compatibility rule is "the key answers", not "the digest answers".
func TestAgility_LegacyFixedSchemeKeyRefusesWrongDigestLength(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "agility-legacy-p384", x509.ECDSA, elliptic.P384())
	handle := createLegacyFixedSchemeECCKey(t, h, attrs, tpm2.TPMECCNistP384, tpm2.TPMAlgSHA384)
	h.TPM.Flush(handle)

	shortDigest := digestFor(crypto.SHA256, "32 bytes for a SHA-384 key")
	attrs.Hash = crypto.Hash(0)
	signature, err := h.TPM.Sign(rand.Reader, shortDigest, &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	assert.Empty(t, signature)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDigestLengthMismatch)
	assert.NotContains(t, err.Error(), "TPM_RC_",
		"a TPM response code must not be what the caller is handed")
}

// TestAgility_LegacyFixedSchemeKeyRefusesOtherDigestByName is the other half of
// the compatibility story, and the part an operator will actually meet.
//
// A pre-existing key genuinely cannot sign under a digest other than the one it
// was created with -- the TPM answers TPM_RC_SCHEME -- so the request must fail.
// What must NOT happen is a raw TPM response code reaching the caller: the
// refusal is reported as ErrSignSchemeMismatch, which says the key fixes a
// scheme, so an application can tell this apart from a device fault and an
// operator knows the remedy is to name the key's digest or rotate the key.
func TestAgility_LegacyFixedSchemeKeyRefusesOtherDigestByName(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "agility-legacy-mismatch", x509.ECDSA, elliptic.P256())
	handle := createLegacyFixedSchemeECCKey(t, h, attrs, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256)
	h.TPM.Flush(handle)

	digest := digestFor(crypto.SHA384, "a SHA-384 digest for a SHA-256 key")
	attrs.Hash = crypto.SHA384
	signature, err := h.TPM.Sign(rand.Reader, digest, &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	assert.Empty(t, signature)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSignSchemeMismatch)
	assert.NotContains(t, err.Error(), "TPM_RC_SCHEME",
		"a TPM response code must not be what the caller is handed")
}

// TestAgility_UnsupportedDeviceAlgorithmRefusedByName proves the capability
// gate refuses what the device does not implement, naming both the request and
// what the device offers.
//
// The algorithm is chosen by asking the device, not by assuming: the candidates
// are algorithms TPM 2.0 defines and that a TPM may or may not implement, and
// the first one this device lacks is the one exercised. Advertising an
// algorithm the chip does not have is the defect this gate exists to prevent.
func TestAgility_UnsupportedDeviceAlgorithmRefusedByName(t *testing.T) {
	h := newSimHarness(t, nil)

	caps, err := h.TPM.Capabilities()
	require.NoError(t, err)

	candidates := []tpm2.TPMIAlgHash{
		tpm2.TPMAlgSM3256,
		tpm2.TPMAlgSHA3256,
		tpm2.TPMAlgSHA3384,
		tpm2.TPMAlgSHA3512,
	}

	var missing tpm2.TPMIAlgHash
	for _, candidate := range candidates {
		if !caps.SupportsAlgorithm(candidate) {
			missing = candidate
			break
		}
	}
	require.NotZero(t, missing,
		"this TPM implements every candidate digest, so the refusal path cannot be exercised; "+
			"add a candidate it lacks rather than weakening the assertion")

	_, err = h.TPM.KeyTemplate(KeyTemplateSpec{
		Algorithm: x509.ECDSA,
		Curve:     elliptic.P256(),
		NameAlg:   missing,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAlgorithmNotSupported)

	var algErr *AlgorithmNotSupportedError
	require.True(t, errors.As(err, &algErr))
	assert.Equal(t, algorithmName(missing), algErr.Requested)
	assert.NotEmpty(t, algErr.Supported,
		"the refusal must name what the device does offer, or an operator cannot act on it")
	assert.Contains(t, algErr.Supported, algorithmName(tpm2.TPMAlgSHA256))
}

// TestAgility_UnsupportedDeviceCurveRefusedByName is the curve counterpart.
//
// Every curve the device implements is exercised by the matrix above; this
// covers a curve it does not. The refusal must name the curve rather than
// substituting one that happens to be available, which is what the create path
// used to do.
func TestAgility_UnsupportedDeviceCurveRefusedByName(t *testing.T) {
	h := newSimHarness(t, nil)

	caps, err := h.TPM.Capabilities()
	require.NoError(t, err)

	var missing elliptic.Curve
	for _, candidate := range agilityCurves {
		if !caps.SupportsCurve(candidate.tpm) {
			missing = candidate.curve
			break
		}
	}

	if missing == nil {
		// The device implements every curve this package can represent, which
		// is the good case. The gate is then proven against a curve no TPM
		// reports, so the test still asserts rather than passing silently.
		_, err := h.TPM.KeyTemplate(KeyTemplateSpec{
			Algorithm: x509.ECDSA,
			Curve:     unsupportedCurve{},
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrCurveNotSupported)
		return
	}

	_, err = h.TPM.KeyTemplate(KeyTemplateSpec{
		Algorithm: x509.ECDSA,
		Curve:     missing,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCurveNotSupported)

	var curveErr *CurveNotSupportedError
	require.True(t, errors.As(err, &curveErr))
	assert.Equal(t, missing.Params().Name, curveErr.Requested)
	assert.NotEmpty(t, curveErr.Supported)
}

// TestAgility_RawRSAStillRefusedUnderNullScheme re-checks the raw-RSA verdict
// against the new template shape.
//
// ErrRawRSASignUnsupported was established against keys that named
// RSASSA/SHA-256. The question TPM_ALG_NULL raises is whether a scheme-less key
// changes it, and it does not: TPM2_Sign still builds the DigestInfo itself, so
// a caller-supplied one is the wrong size, and inScheme may not itself be
// TPM_ALG_NULL when the key names no scheme either. The commands are asked
// directly here so the claim rests on the device.
func TestAgility_RawRSAStillRefusedUnderNullScheme(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "agility-raw-rsa", x509.RSA, nil)
	_, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)

	loadResp, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err)
	defer h.TPM.Flush(loadResp.ObjectHandle)

	readResp, err := tpm2.ReadPublic{ObjectHandle: loadResp.ObjectHandle}.Execute(h.TPM.Transport())
	require.NoError(t, err)
	outPub, err := readResp.OutPublic.Contents()
	require.NoError(t, err)

	// The premise: this key really does name no scheme, and really is
	// sign-only.
	detail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)
	require.Equal(t, tpm2.TPMAlgNull, detail.Scheme.Scheme)
	require.True(t, outPub.ObjectAttributes.SignEncrypt)
	require.False(t, outPub.ObjectAttributes.Decrypt,
		"a signing key must not carry the decrypt attribute; if it did, it would "+
			"double as a raw private-key operation oracle")

	digestInfo := rsaSHA256DigestInfo(sha256Of("payload"))

	// A complete DigestInfo under a named scheme is the wrong size.
	_, err = tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   readResp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digestInfo},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(h.TPM.Transport())
	require.Error(t, err,
		"TPM2_Sign must refuse a caller-built DigestInfo; if it ever accepts one, "+
			"ErrRawRSASignUnsupported is no longer true")

	// And a TPM_ALG_NULL inScheme cannot stand in for one, because the key
	// names no scheme to fall back on.
	_, err = tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   readResp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest:     tpm2.TPM2BDigest{Buffer: digestInfo},
		InScheme:   tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(h.TPM.Transport())
	require.Error(t, err,
		"a TPM_ALG_NULL inScheme against a TPM_ALG_NULL key has no scheme to resolve to")

	// The only command that performs the bare exponentiation still refuses a
	// sign-only key, and making it decrypt-capable would turn every signing key
	// into a forgery oracle.
	_, err = tpm2.RSADecrypt{
		KeyHandle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   readResp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)},
		InScheme:   tpm2.TPMTRSADecrypt{Scheme: tpm2.TPMAlgNull},
	}.Execute(h.TPM.Transport())
	require.Error(t, err, "TPM2_RSA_Decrypt must refuse a sign-only key")

	// So the package-level refusal stands, and reports the capability boundary.
	attrs.Hash = crypto.Hash(0)
	signature, err := h.TPM.Sign(rand.Reader, digestInfo, &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	assert.Empty(t, signature)
	assert.ErrorIs(t, err, ErrRawRSASignUnsupported)
}

// TestAgility_PSSOverLargerDigestPassesTheSaltLengthCheck covers the RSA-PSS
// path's own hardcoded digest.
//
// After the TPM produces a PSS signature this package verifies it locally to
// establish that the TPM used a salt the length of the hash, which is what TLS
// 1.3 and FIPS 140-2 require. That check named crypto.SHA256 outright, so a PSS
// signature over a SHA-384 or SHA-512 digest failed it -- not because the
// signature was wrong but because it was being checked under the wrong
// algorithm. It now uses the digest the caller asked for.
//
// A TPM that is not in FIPS 140-2 mode is then refused by the gate that follows,
// and that is the error this test asserts: reaching ErrRSAPSSNotSupported proves
// the salt-length check passed, because it is the only way past it.
func TestAgility_PSSOverLargerDigestPassesTheSaltLengthCheck(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "agility-pss-sha384", x509.RSA, nil)
	_, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)

	fips, err := h.TPM.IsFIPS140_2()
	require.NoError(t, err)

	digest := digestFor(crypto.SHA384, "a PSS message under SHA-384")
	attrs.Hash = crypto.SHA384

	signature, err := h.TPM.Sign(rand.Reader, digest, &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
		PSSOptions:    &rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: rsa.PSSSaltLengthEqualsHash},
	})

	if fips {
		// A FIPS 140-2 TPM salts to the hash length, so the signature is
		// returned and must verify under SHA-384 outside the TPM.
		require.NoError(t, err)
		tpmPub := rsaPublicKeyFromTPM(t, h, attrs)
		assert.NoError(t, rsa.VerifyPSS(tpmPub, crypto.SHA384, digest, signature,
			&rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: rsa.PSSSaltLengthEqualsHash}))
		return
	}

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRSAPSSNotSupported,
		"the only way to reach the FIPS gate is through the salt-length check, so this "+
			"proves the check ran under SHA-384 rather than under a hardcoded SHA-256")
	assert.Empty(t, signature)
}

// createLegacyFixedSchemeECCKey provisions a key exactly as this package did
// before the templates moved to TPM_ALG_NULL: with the signing scheme named in
// the public area.
//
// It goes through TPM2_CreateLoaded and SaveKeyPair, so the blobs on disk are
// indistinguishable from a key created by the old CreateECDSA -- which is the
// point. It returns the loaded handle so the caller can read the public area
// before flushing it.
func createLegacyFixedSchemeECCKey(
	t *testing.T,
	h *simHarness,
	attrs *types.KeyAttributes,
	curveID tpm2.TPMECCCurve,
	schemeHash tpm2.TPMIAlgHash) tpm2.TPMHandle {

	t.Helper()

	legacy := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: curveID,
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSigSchemeECDSA{HashAlg: schemeHash},
				),
			},
		}),
	}

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)
	srkHandle := srkAttrs.TPMAttributes.Handle
	srkName, _, err := h.TPM.ReadHandle(srkHandle)
	require.NoError(t, err)

	resp, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&legacy),
	}.Execute(h.TPM.Transport())
	require.NoError(t, err)

	if attrs.TPMAttributes == nil {
		attrs.TPMAttributes = &types.TPMAttributes{}
	}
	attrs.TPMAttributes.Name = resp.Name
	attrs.TPMAttributes.Handle = resp.ObjectHandle

	require.NoError(t, h.TPM.SaveKeyPair(attrs, resp.OutPrivate, resp.OutPublic, h.Backend, true))

	return resp.ObjectHandle
}

// sha256Of is a small convenience for the DigestInfo fixture.
func sha256Of(message string) [32]byte {
	var digest [32]byte
	copy(digest[:], digestFor(crypto.SHA256, message))
	return digest
}
