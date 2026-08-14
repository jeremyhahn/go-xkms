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
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyAttrsWithHash builds the minimal key attributes store.SignerOpts reads its
// hash from, so a test can express "the caller asked for this digest".
func keyAttrsWithHash(h crypto.Hash) *types.KeyAttributes {
	return &types.KeyAttributes{Hash: h}
}

// ecdsaScheme builds a TPMT_ECC_SCHEME naming ECDSA over the supplied hash,
// which is the shape every ECC key created before this package moved to
// TPM_ALG_NULL templates carries.
func ecdsaScheme(hashAlg tpm2.TPMIAlgHash) tpm2.TPMTECCScheme {
	return tpm2.TPMTECCScheme{
		Scheme: tpm2.TPMAlgECDSA,
		Details: tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgECDSA,
			&tpm2.TPMSSigSchemeECDSA{HashAlg: hashAlg},
		),
	}
}

// nullECCScheme is the scheme a key created from the current ECC templates
// carries: none at all.
func nullECCScheme() tpm2.TPMTECCScheme {
	return tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull}
}

// rsassaScheme builds a TPMT_RSA_SCHEME naming RSASSA over the supplied hash.
func rsassaScheme(hashAlg tpm2.TPMIAlgHash) tpm2.TPMTRSAScheme {
	return tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSigSchemeRSASSA{HashAlg: hashAlg},
		),
	}
}

// rsapssScheme builds a TPMT_RSA_SCHEME naming RSAPSS over the supplied hash.
func rsapssScheme(hashAlg tpm2.TPMIAlgHash) tpm2.TPMTRSAScheme {
	return tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgRSAPSS,
		Details: tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgRSAPSS,
			&tpm2.TPMSSigSchemeRSAPSS{HashAlg: hashAlg},
		),
	}
}

// nullRSAScheme is the scheme a key created from RSASSATemplate carries.
func nullRSAScheme() tpm2.TPMTRSAScheme {
	return tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull}
}

// TestRequestedSignHash_NilOptsSelectsSHA256 pins the one place a default is
// allowed. A nil crypto.SignerOpts means the caller named no digest at all, and
// SHA-256 is the same answer xkms.ResolveHash gives an unspecified hash name --
// if the two disagreed, the same request would be signed under different
// schemes depending on which entry point it arrived through.
func TestRequestedSignHash_NilOptsSelectsSHA256(t *testing.T) {
	assert.Equal(t, crypto.SHA256, requestedSignHash(nil))
}

// TestRequestedSignHash_PassesCallerHashThrough proves a hash the caller DID
// name is never substituted, including the crypto.Hash(0) "NONE" sentinel,
// which has to survive intact to reach the per-key-type resolution.
func TestRequestedSignHash_PassesCallerHashThrough(t *testing.T) {
	for _, h := range []crypto.Hash{crypto.Hash(0), crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA1} {
		opts := &store.SignerOpts{KeyAttributes: keyAttrsWithHash(h)}
		assert.Equal(t, h, requestedSignHash(opts), "hash %v must pass through unchanged", h)
	}
}

// TestECCSchemeHash_SchemelessKeyHonoursEveryNamedHash is the core of the fix.
//
// A key created from the current ECC templates names TPM_ALG_NULL, so it
// constrains nothing and the caller's digest is passed straight through. Before
// the templates changed, the key named one hash and every other digest was
// answered by the TPM with TPM_RC_SCHEME.
func TestECCSchemeHash_SchemelessKeyHonoursEveryNamedHash(t *testing.T) {
	for requested, want := range map[crypto.Hash]tpm2.TPMIAlgHash{
		crypto.SHA256: tpm2.TPMAlgSHA256,
		crypto.SHA384: tpm2.TPMAlgSHA384,
		crypto.SHA512: tpm2.TPMAlgSHA512,
	} {
		got, err := eccSchemeHash(requested, nullECCScheme(), requested.Size())
		require.NoError(t, err, "hash %v", requested)
		assert.Equal(t, want, got, "hash %v", requested)
	}
}

// TestECCSchemeHash_SchemelessKeyResolvesNoneFromDigestLength defines what hash
// "NONE" means for a key that names no scheme.
//
// The TPM requires the digest handed to TPM2_Sign to be exactly the size of the
// hash named in inScheme, answering anything else with TPM_RC_SIZE (TCG TPM 2.0
// Library Part 3, section 12.1). For a scheme-less key that makes the digest's
// own length the only admissible answer -- every other choice is a guaranteed
// failure, not a different signature -- and because the hash algorithm is not an
// input to the ECDSA computation, the signature is over precisely the bytes the
// caller supplied.
func TestECCSchemeHash_SchemelessKeyResolvesNoneFromDigestLength(t *testing.T) {
	for digestLen, want := range map[int]tpm2.TPMIAlgHash{
		32: tpm2.TPMAlgSHA256,
		48: tpm2.TPMAlgSHA384,
		64: tpm2.TPMAlgSHA512,
	} {
		got, err := eccSchemeHash(crypto.Hash(0), nullECCScheme(), digestLen)
		require.NoError(t, err, "digest length %d", digestLen)
		assert.Equal(t, want, got, "digest length %d", digestLen)
	}
}

// TestECCSchemeHash_SchemelessKeyRefusesUnknownDigestLength is the bad-input
// case for the inference above. A digest of a length no supported algorithm
// produces cannot be resolved, and must be refused rather than rounded to the
// nearest algorithm -- which would hand the TPM a digest it answers with
// TPM_RC_SIZE, and would be a silent choice either way.
func TestECCSchemeHash_SchemelessKeyRefusesUnknownDigestLength(t *testing.T) {
	for _, digestLen := range []int{0, 20, 31, 33, 47, 65, 128} {
		got, err := eccSchemeHash(crypto.Hash(0), nullECCScheme(), digestLen)
		assert.Zero(t, got, "digest length %d", digestLen)
		assert.ErrorIs(t, err, ErrSchemeHashUnresolved, "digest length %d", digestLen)
	}
}

// TestECCSchemeHash_FixedKeyResolvesNoneToItsOwnHash covers the compatibility
// half: a key provisioned before the template change names a scheme, and hash
// NONE against it can only mean that scheme's hash, because the TPM requires
// inScheme to match the key (Part 3, section 12.1).
func TestECCSchemeHash_FixedKeyResolvesNoneToItsOwnHash(t *testing.T) {
	for keyHash, digestLen := range map[tpm2.TPMIAlgHash]int{
		tpm2.TPMAlgSHA256: 32,
		tpm2.TPMAlgSHA384: 48,
		tpm2.TPMAlgSHA512: 64,
	} {
		got, err := eccSchemeHash(crypto.Hash(0), ecdsaScheme(keyHash), digestLen)
		require.NoError(t, err, "key scheme hash %v", keyHash)
		assert.Equal(t, keyHash, got,
			"hash NONE must resolve to the key's own scheme hash")
	}
}

// TestECCSchemeHash_FixedKeyRefusesWrongDigestLength is where resolving from
// the key and resolving from the digest length visibly disagree, and it is the
// case that proves the key is what answers.
//
// A key naming ECDSA/SHA-384 handed a 32-byte digest cannot sign it: the only
// hash inScheme may carry is SHA-384, and the TPM requires the digest to be 48
// bytes. Inferring SHA-256 from the length instead would name an algorithm the
// key does not have, so the TPM would answer TPM_RC_SCHEME -- an error either
// way, but one that reports the wrong cause. The refusal names the real one.
func TestECCSchemeHash_FixedKeyRefusesWrongDigestLength(t *testing.T) {
	got, err := eccSchemeHash(crypto.Hash(0), ecdsaScheme(tpm2.TPMAlgSHA384), 32)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrDigestLengthMismatch)

	got, err = eccSchemeHash(crypto.Hash(0), ecdsaScheme(tpm2.TPMAlgSHA256), 64)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrDigestLengthMismatch)
}

// TestSchemeHash_NamedHashRefusesWrongDigestLength covers the same check on the
// named-hash path, for both key types. A caller that names SHA-384 and supplies
// 32 bytes has made a mistake the TPM would report only as TPM_RC_SIZE.
func TestSchemeHash_NamedHashRefusesWrongDigestLength(t *testing.T) {
	got, err := eccSchemeHash(crypto.SHA384, nullECCScheme(), 32)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrDigestLengthMismatch)

	gotRSA, err := rsaSchemeHash(crypto.SHA512, nullRSAScheme(), 32)
	assert.Zero(t, gotRSA)
	assert.ErrorIs(t, err, ErrDigestLengthMismatch)
}

// TestECCSchemeHash_FixedKeyHonoursItsOwnHash proves a pre-existing key still
// signs under the one digest it supports, which is the whole compatibility
// claim of the template change.
func TestECCSchemeHash_FixedKeyHonoursItsOwnHash(t *testing.T) {
	for requested, keyHash := range map[crypto.Hash]tpm2.TPMIAlgHash{
		crypto.SHA256: tpm2.TPMAlgSHA256,
		crypto.SHA384: tpm2.TPMAlgSHA384,
		crypto.SHA512: tpm2.TPMAlgSHA512,
	} {
		got, err := eccSchemeHash(requested, ecdsaScheme(keyHash), requested.Size())
		require.NoError(t, err, "hash %v", requested)
		assert.Equal(t, keyHash, got)
	}
}

// TestECCSchemeHash_FixedKeyRefusesOtherHash is the bad-input case that keeps a
// TPM response code from leaking.
//
// A key with a fixed scheme genuinely cannot sign under another digest, but the
// caller has to be told that in terms it can act on. Sending the request anyway
// produced TPM_RC_SCHEME from inside TPM2_Sign, which says nothing about which
// digest would have worked.
func TestECCSchemeHash_FixedKeyRefusesOtherHash(t *testing.T) {
	got, err := eccSchemeHash(crypto.SHA384, ecdsaScheme(tpm2.TPMAlgSHA256), 48)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrSignSchemeMismatch)

	got, err = eccSchemeHash(crypto.SHA256, ecdsaScheme(tpm2.TPMAlgSHA512), 32)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrSignSchemeMismatch)
}

// TestECCSchemeHash_UnsupportedHashRefused proves an unmappable digest is
// refused rather than quietly defaulted. Substituting SHA-256 for a SHA-1
// request would report success for a signature the caller cannot use.
func TestECCSchemeHash_UnsupportedHashRefused(t *testing.T) {
	got, err := eccSchemeHash(crypto.SHA1, nullECCScheme(), 20)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, store.ErrInvalidHashFunction)

	got, err = eccSchemeHash(crypto.MD5, nullECCScheme(), 16)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, store.ErrInvalidHashFunction)
}

// TestECCSchemeHash_NonSigningSchemeRefused covers a key whose scheme is a
// key-agreement scheme. It cannot satisfy the ECDSA command this package
// issues under any digest, so it is a scheme mismatch rather than an
// unresolvable hash.
func TestECCSchemeHash_NonSigningSchemeRefused(t *testing.T) {
	ecdh := tpm2.TPMTECCScheme{
		Scheme: tpm2.TPMAlgECDH,
		Details: tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgECDH,
			&tpm2.TPMSKeySchemeECDH{HashAlg: tpm2.TPMAlgSHA256},
		),
	}
	got, err := eccSchemeHash(crypto.SHA256, ecdh, 32)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrSignSchemeMismatch)

	got, err = eccSchemeHash(crypto.Hash(0), ecdh, 32)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrSignSchemeMismatch)
}

// TestECCSchemeHash_MalformedSchemeHashRefused covers a public area whose
// scheme names ECDSA but no hash algorithm. There is nothing to resolve to and
// nothing to check against, so it is refused.
func TestECCSchemeHash_MalformedSchemeHashRefused(t *testing.T) {
	got, err := eccSchemeHash(crypto.Hash(0), ecdsaScheme(tpm2.TPMAlgNull), 32)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrSchemeHashUnresolved)

	got, err = eccSchemeHash(crypto.SHA256, ecdsaScheme(tpm2.TPMAlgNull), 32)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrSchemeHashUnresolved)
}

// TestRSASchemeHash_SchemelessKeyHonoursEveryNamedHash covers the RSA half of
// the digest-agility fix.
func TestRSASchemeHash_SchemelessKeyHonoursEveryNamedHash(t *testing.T) {
	for requested, want := range map[crypto.Hash]tpm2.TPMIAlgHash{
		crypto.SHA256: tpm2.TPMAlgSHA256,
		crypto.SHA384: tpm2.TPMAlgSHA384,
		crypto.SHA512: tpm2.TPMAlgSHA512,
	} {
		got, err := rsaSchemeHash(requested, nullRSAScheme(), requested.Size())
		require.NoError(t, err, "hash %v", requested)
		assert.Equal(t, want, got, "hash %v", requested)
	}
}

// TestRSASchemeHash_FixedKeyRefusesOtherHash proves a pre-existing RSA key
// keeps its one digest and reports any other as a typed mismatch.
func TestRSASchemeHash_FixedKeyRefusesOtherHash(t *testing.T) {
	got, err := rsaSchemeHash(crypto.SHA256, rsassaScheme(tpm2.TPMAlgSHA256), 32)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgSHA256, got)

	got, err = rsaSchemeHash(crypto.SHA384, rsassaScheme(tpm2.TPMAlgSHA256), 48)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrSignSchemeMismatch)

	got, err = rsaSchemeHash(crypto.SHA512, rsapssScheme(tpm2.TPMAlgSHA256), 64)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrSignSchemeMismatch)
}

// TestRSASchemeHash_NoneRefusedAsUnsupported is the RSA half of the NONE
// question, and its answer is deliberately different from ECDSA's -- including
// for a key that names no scheme at all.
//
// For an RSASSA scheme TPM2_Sign builds the PKCS#1 v1.5 DigestInfo itself and
// requires the digest to be exactly the scheme hash's size, so a caller-built
// DigestInfo cannot be signed verbatim. Inferring the hash from the digest's
// length -- the ECDSA answer -- would silently sign a DIFFERENT message: the
// TPM would wrap the caller's bytes in a second DigestInfo. The refusal is
// therefore load-bearing whatever the key's scheme, and it carries its own
// sentinel so callers can tell "this token cannot do raw RSA" from a fault.
func TestRSASchemeHash_NoneRefusedAsUnsupported(t *testing.T) {
	for _, keyScheme := range []tpm2.TPMTRSAScheme{
		nullRSAScheme(),
		rsassaScheme(tpm2.TPMAlgSHA256),
		rsapssScheme(tpm2.TPMAlgSHA256),
	} {
		got, err := rsaSchemeHash(crypto.Hash(0), keyScheme, 51)
		assert.Zero(t, got)
		assert.ErrorIs(t, err, ErrRawRSASignUnsupported)
		assert.NotErrorIs(t, err, store.ErrInvalidHashFunction,
			"a capability boundary must not be reported as a malformed request")
	}
}

// TestRSASchemeHash_UnsupportedHashRefused is the bad-input counterpart, and it
// must report a different sentinel from the NONE refusal above: one says the
// request was malformed, the other says the token cannot do it.
func TestRSASchemeHash_UnsupportedHashRefused(t *testing.T) {
	got, err := rsaSchemeHash(crypto.SHA1, nullRSAScheme(), 20)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, store.ErrInvalidHashFunction)
	assert.NotErrorIs(t, err, ErrRawRSASignUnsupported)
}

// TestRSASchemeHash_NonSigningSchemeRefused covers a key whose scheme is an
// encryption scheme: it cannot be signed with at all.
func TestRSASchemeHash_NonSigningSchemeRefused(t *testing.T) {
	oaep := tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgOAEP,
		Details: tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgOAEP,
			&tpm2.TPMSEncSchemeOAEP{HashAlg: tpm2.TPMAlgSHA256},
		),
	}
	got, err := rsaSchemeHash(crypto.SHA256, oaep, 32)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrSignSchemeMismatch)
}

// TestRSASignScheme_SchemelessKeyFollowsTheCaller proves a key created with
// TPM_ALG_NULL can produce either padding, which is what lets one RSA key serve
// a v1.5-signed certificate and a TLS 1.3 handshake that requires PSS.
func TestRSASignScheme_SchemelessKeyFollowsTheCaller(t *testing.T) {
	got, err := rsaSignScheme(nullRSAScheme(), false)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMIAlgSigScheme(tpm2.TPMAlgRSASSA), got)

	got, err = rsaSignScheme(nullRSAScheme(), true)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMIAlgSigScheme(tpm2.TPMAlgRSAPSS), got)
}

// TestRSASignScheme_FixedKeyAnswersForItself proves a key that pins its padding
// keeps it, and refuses the other one by name rather than producing a signature
// of a shape the caller did not ask for.
func TestRSASignScheme_FixedKeyAnswersForItself(t *testing.T) {
	got, err := rsaSignScheme(rsassaScheme(tpm2.TPMAlgSHA256), false)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMIAlgSigScheme(tpm2.TPMAlgRSASSA), got)

	got, err = rsaSignScheme(rsassaScheme(tpm2.TPMAlgSHA256), true)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrSignSchemeMismatch)

	got, err = rsaSignScheme(rsapssScheme(tpm2.TPMAlgSHA256), true)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMIAlgSigScheme(tpm2.TPMAlgRSAPSS), got)

	got, err = rsaSignScheme(rsapssScheme(tpm2.TPMAlgSHA256), false)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrSignSchemeMismatch)
}

// TestRSASignScheme_NonSigningSchemeRefused covers an encryption key, which has
// no signature scheme to offer.
func TestRSASignScheme_NonSigningSchemeRefused(t *testing.T) {
	oaep := tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgOAEP,
		Details: tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgOAEP,
			&tpm2.TPMSEncSchemeOAEP{HashAlg: tpm2.TPMAlgSHA256},
		),
	}
	got, err := rsaSignScheme(oaep, false)
	assert.Zero(t, got)
	assert.ErrorIs(t, err, ErrSignSchemeMismatch)
}

// TestIsPSSRequest_BothSourcesAreSufficient proves either way of asking for PSS
// is honoured, so the scheme sent to the TPM and the branch that unpacks the
// signature cannot disagree.
func TestIsPSSRequest_BothSourcesAreSufficient(t *testing.T) {
	pssAttrs := &types.KeyAttributes{SignatureAlgorithm: x509.SHA256WithRSAPSS}
	assert.True(t, isPSSRequest(pssAttrs, &store.SignerOpts{}))

	ssaAttrs := &types.KeyAttributes{SignatureAlgorithm: x509.SHA256WithRSA}
	assert.True(t, isPSSRequest(ssaAttrs, &store.SignerOpts{
		PSSOptions: &rsa.PSSOptions{Hash: crypto.SHA256},
	}))
}

// TestIsPSSRequest_NeitherSourceMeansPKCS1 is the negative case: a caller that
// asked for neither must not be handed a PSS signature.
func TestIsPSSRequest_NeitherSourceMeansPKCS1(t *testing.T) {
	ssaAttrs := &types.KeyAttributes{SignatureAlgorithm: x509.SHA256WithRSA}
	assert.False(t, isPSSRequest(ssaAttrs, &store.SignerOpts{}))
	assert.False(t, isPSSRequest(nil, nil))
	assert.False(t, isPSSRequest(ssaAttrs, nil))
	assert.False(t, isPSSRequest(nil, &store.SignerOpts{}))
}
