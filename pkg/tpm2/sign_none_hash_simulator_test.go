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
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecpoint"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers signing with hash "NONE" -- crypto.Hash(0), the sentinel the
// whole stack uses for "the caller already produced the digest; sign it as-is".
// The PKCS#11 module maps CKM_ECDSA and CKM_RSA_PKCS onto it, so every OpenSSL
// operation that hands a token a finished digest arrives here.
//
// Each test owns one simulator via newSimHarness; the go-tpm-tools simulator is
// a process-global singleton, so only one may be live at a time.

// signingKeyAttrs builds child-key attributes under the SSRK for the requested
// algorithm and curve. The SSRK carries no platform policy, so parent
// authorization is a plain password session and the test isolates the signing
// behaviour under test.
func signingKeyAttrs(
	t *testing.T,
	h *simHarness,
	cn string,
	algorithm x509.PublicKeyAlgorithm,
	curve elliptic.Curve,
) *types.KeyAttributes {
	t.Helper()

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:                 cn,
		Hash:               crypto.SHA256,
		KeyAlgorithm:       algorithm,
		KeyType:            types.KeyTypeSigning,
		Parent:             srkAttrs,
		StoreType:          types.StoreTPM2,
		SignatureAlgorithm: x509.SHA256WithRSA,
		TPMAttributes:      &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}
	switch algorithm {
	case x509.RSA:
		attrs.RSAAttributes = &types.RSAAttributes{KeySize: 2048}
	case x509.ECDSA:
		attrs.ECCAttributes = &types.ECCAttributes{Curve: curve}
		attrs.SignatureAlgorithm = x509.ECDSAWithSHA256
		if curve == elliptic.P384() {
			attrs.SignatureAlgorithm = x509.ECDSAWithSHA384
		}
	}
	return attrs
}

// eccPublicKeyFromTPM reads the key's public area back out of the TPM with
// TPM2_ReadPublic and rebuilds the curve point from it.
//
// This is deliberately NOT the *ecdsa.PublicKey CreateECDSA returned. A test
// that verifies a TPM signature against a public key this package computed
// would pass even if both halves shared a bug; reading the point out of the
// device makes the TPM the only source of the verification key, so the
// signature is checked against what the hardware actually holds.
func eccPublicKeyFromTPM(
	t *testing.T,
	h *simHarness,
	attrs *types.KeyAttributes,
) *ecdsa.PublicKey {
	t.Helper()

	loadResp, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err)
	defer h.TPM.Flush(loadResp.ObjectHandle)

	readResp, err := tpm2.ReadPublic{ObjectHandle: loadResp.ObjectHandle}.Execute(h.TPM.Transport())
	require.NoError(t, err)

	outPub, err := readResp.OutPublic.Contents()
	require.NoError(t, err)
	require.Equal(t, tpm2.TPMAlgECC, outPub.Type)

	eccDetail, err := outPub.Parameters.ECCDetail()
	require.NoError(t, err)
	curve, err := eccDetail.CurveID.Curve()
	require.NoError(t, err)
	unique, err := outPub.Unique.ECC()
	require.NoError(t, err)

	key, err := ecpoint.PublicKey(curve, unique.X.Buffer, unique.Y.Buffer)
	require.NoError(t, err, "the point the TPM reported must lie on the curve")
	return key
}

// TestSign_NoneHash_ECDSA_P256_ProducesVerifiableSignature is the primary
// regression test for the ECDSA half of the NONE-hash defect.
//
// TPM2_Sign over a caller-supplied digest is an entirely ordinary operation
// (TCG TPM 2.0 Library Part 3, section 12.1) -- the TPM never hashes for you --
// so refusing crypto.Hash(0) here was our gap, not a TPM limit. Every
// CKM_ECDSA operation an application performs through the PKCS#11 module
// arrives with exactly this shape.
func TestSign_NoneHash_ECDSA_P256_ProducesVerifiableSignature(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "none-hash-p256", x509.ECDSA, elliptic.P256())
	_, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)

	tpmPub := eccPublicKeyFromTPM(t, h, attrs)
	require.Equal(t, elliptic.P256(), tpmPub.Curve)

	digest := sha256.Sum256([]byte("the caller already hashed this"))

	attrs.Hash = crypto.Hash(0)
	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err, "hash NONE over a P-256 key must be signed, not refused")
	require.NotEmpty(t, signature)

	assert.True(t, ecdsa.VerifyASN1(tpmPub, digest[:], signature),
		"the signature must verify against the public key read out of the TPM")

	// The verification above must actually be checking the message.
	other := sha256.Sum256([]byte("a different message"))
	assert.False(t, ecdsa.VerifyASN1(tpmPub, other[:], signature),
		"the signature must not verify against an unrelated digest")
}

// TestSign_NoneHash_ECDSA_P384_ProducesVerifiableSignature covers P-384, and it
// is the case that pins the resolution rule.
//
// Resolving hash NONE to a fixed SHA-256 would break this key while appearing
// to work for P-256: the TPM requires the digest handed to TPM2_Sign to be the
// size of the hash named in inScheme and answers anything else with
// TPM_RC_SIZE, so a 48-byte digest can only be signed under SHA-384. The
// resolution therefore follows the digest the caller actually supplied, which
// makes both curves work under every digest.
func TestSign_NoneHash_ECDSA_P384_ProducesVerifiableSignature(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "none-hash-p384", x509.ECDSA, elliptic.P384())
	_, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)

	tpmPub := eccPublicKeyFromTPM(t, h, attrs)
	require.Equal(t, elliptic.P384(), tpmPub.Curve)

	digest := sha512.Sum384([]byte("the caller already hashed this with SHA-384"))

	attrs.Hash = crypto.Hash(0)
	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err, "hash NONE over a P-384 key must be signed, not refused")

	assert.True(t, ecdsa.VerifyASN1(tpmPub, digest[:], signature),
		"the signature must verify against the public key read out of the TPM")

	other := sha512.Sum384([]byte("a different message"))
	assert.False(t, ecdsa.VerifyASN1(tpmPub, other[:], signature),
		"the signature must not verify against an unrelated digest")
}

// TestSign_NoneHash_ECDSA_ShorterDigestOnLargerCurveIsSigned records a
// behaviour change that the template move to TPM_ALG_NULL makes correct.
//
// A P-384 key created from the current template names no scheme, so a 32-byte
// digest under hash NONE resolves to SHA-256 and is signed. That is a valid
// ECDSA signature over exactly the bytes the caller supplied -- the digest is
// truncated to the order of the curve, and the scheme's hash never enters the
// computation (TCG TPM 2.0 Library Part 4, CryptEccSign) -- and it is what
// PKCS#11 CKM_ECDSA means. While the key named ECDSA/SHA-384 the same request
// was answered with TPM_RC_SCHEME.
//
// The signature is verified against the public key read out of the TPM, so the
// claim "signed over the caller's bytes" is checked rather than assumed.
func TestSign_NoneHash_ECDSA_ShorterDigestOnLargerCurveIsSigned(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "none-hash-shortdigest", x509.ECDSA, elliptic.P384())
	_, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)

	tpmPub := eccPublicKeyFromTPM(t, h, attrs)
	shortDigest := sha256.Sum256([]byte("only 32 bytes, on a P-384 key"))

	attrs.Hash = crypto.Hash(0)
	signature, err := h.TPM.Sign(rand.Reader, shortDigest[:], &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(tpmPub, shortDigest[:], signature),
		"the signature must be over the digest the caller supplied")

	other := sha256.Sum256([]byte("a different message"))
	assert.False(t, ecdsa.VerifyASN1(tpmPub, other[:], signature))
}

// TestSign_NoneHash_ECDSA_UnknownDigestLengthRejected is the bad-input case
// that survives the change.
//
// A digest whose length matches no digest algorithm this package supports
// cannot be resolved to a scheme hash at all, and the TPM would answer every
// possible choice with TPM_RC_SIZE. It must be refused rather than padded,
// truncated or signed -- a caller must not receive a signature over bytes it
// did not supply.
func TestSign_NoneHash_ECDSA_UnknownDigestLengthRejected(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "none-hash-oddlen", x509.ECDSA, elliptic.P384())
	_, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)

	attrs.Hash = crypto.Hash(0)
	signature, err := h.TPM.Sign(rand.Reader, make([]byte, 20), &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	assert.ErrorIs(t, err, ErrSchemeHashUnresolved,
		"a digest length that resolves to no supported algorithm must be refused")
	assert.Empty(t, signature)
}

// TestSign_NoneHash_RSA_RefusedWithCapabilitySentinel proves the RSA half is a
// refusal rather than a wrong answer, and that the refusal is distinguishable.
//
// An application has to be able to tell "this token cannot do raw RSA" from
// "something broke", so the error carries ErrRawRSASignUnsupported and
// deliberately does NOT carry the malformed-request sentinel.
func TestSign_NoneHash_RSA_RefusedWithCapabilitySentinel(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "none-hash-rsa", x509.RSA, nil)
	_, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)

	// A complete PKCS#1 v1.5 DigestInfo for SHA-256 (RFC 8017 A.2.4): what
	// libp11 and OpenSSL hand a token for raw CKM_RSA_PKCS.
	digestInfo := rsaSHA256DigestInfo(sha256.Sum256([]byte("payload")))

	attrs.Hash = crypto.Hash(0)
	signature, err := h.TPM.Sign(rand.Reader, digestInfo, &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	assert.Empty(t, signature)
	assert.ErrorIs(t, err, ErrRawRSASignUnsupported)
	assert.NotErrorIs(t, err, store.ErrInvalidHashFunction,
		"a capability boundary must not be reported as a malformed request")
}

// TestSign_NamedHash_RSA_StillSigns guards the refusal above from becoming a
// blanket one: naming the digest lets the TPM build the DigestInfo itself, and
// that path must keep working.
func TestSign_NamedHash_RSA_StillSigns(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "named-hash-rsa", x509.RSA, nil)
	pub, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("payload"))
	attrs.Hash = crypto.SHA256
	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature))
}

// TestRawRSA_TPMCommandsGenuinelyRefuse is the evidence behind
// ErrRawRSASignUnsupported. It does not exercise this package's code at all: it
// asks the TPM directly, so the claim "this is a TPM limit, not our gap" is
// backed by the device rather than by a comment.
//
// Two commands could conceivably produce a signature over caller-supplied
// bytes, and both refuse:
//
//   - TPM2_Sign (Part 3, section 12.1) builds the PKCS#1 v1.5 DigestInfo itself
//     and requires the digest to be exactly the scheme hash's size, so a
//     51-byte DigestInfo is answered with TPM_RC_SIZE.
//   - TPM2_RSA_Decrypt with a TPM_ALG_NULL scheme (Part 3, section 14.3) is the
//     bare private-key exponentiation, but it requires the decrypt attribute to
//     be SET. A signing key has it CLEAR, so the TPM answers TPM_RC_ATTRIBUTES.
//     Setting it would make every signing key a raw private-key oracle, which is
//     a signature forgery primitive, so it is not done.
func TestRawRSA_TPMCommandsGenuinelyRefuse(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "raw-rsa-evidence", x509.RSA, nil)
	_, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)

	loadResp, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err)
	defer h.TPM.Flush(loadResp.ObjectHandle)

	readResp, err := tpm2.ReadPublic{ObjectHandle: loadResp.ObjectHandle}.Execute(h.TPM.Transport())
	require.NoError(t, err)
	outPub, err := readResp.OutPublic.Contents()
	require.NoError(t, err)

	// The premise of the TPM2_RSA_Decrypt refusal: the key is sign-only.
	require.True(t, outPub.ObjectAttributes.SignEncrypt)
	require.False(t, outPub.ObjectAttributes.Decrypt,
		"a signing key must not carry the decrypt attribute; if it did, it would "+
			"double as a raw private-key operation oracle")

	digestInfo := rsaSHA256DigestInfo(sha256.Sum256([]byte("payload")))

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
		"TPM2_Sign must refuse a caller-built DigestInfo; if it ever accepts one, "+
			"ErrRawRSASignUnsupported is no longer true and this package should honour raw RSA")

	_, err = tpm2.RSADecrypt{
		KeyHandle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   readResp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)},
		InScheme:   tpm2.TPMTRSADecrypt{Scheme: tpm2.TPMAlgNull},
	}.Execute(h.TPM.Transport())
	require.Error(t, err,
		"TPM2_RSA_Decrypt must refuse a sign-only key; accepting it would make the "+
			"key a raw private-key operation oracle")
}

// rsaSHA256DigestInfo builds the complete PKCS#1 v1.5 DigestInfo for a SHA-256
// digest (RFC 8017 A.2.4) -- the 51-byte structure a PKCS#11 caller hands a
// token for raw CKM_RSA_PKCS.
func rsaSHA256DigestInfo(digest [32]byte) []byte {
	prefix := []byte{
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
	}
	return append(prefix, digest[:]...)
}
