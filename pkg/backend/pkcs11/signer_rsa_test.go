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

//go:build pkcs11

package pkcs11

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

// rsaTestKeySize is the modulus size used by the RSA signer tests. 2048 bits is
// the smallest size that leaves room for a SHA-512 PSS salt (512 bits of hash
// plus salt plus 2 bytes must fit in the modulus) while keeping SoftHSM key
// generation fast enough for a unit test.
const rsaTestKeySize = 2048

// newRSATestSigner generates a fresh RSA key pair on the backend's token and
// returns the concrete signer type. The concrete type is required because the
// tests exercise the unexported signing helpers directly, not only the
// crypto.Signer facade.
func newRSATestSigner(t *testing.T, b *Backend, cn string) *pkcs11RSASigner {
	t.Helper()

	id := []byte(cn)
	signer, err := generateRSAKeyPair(b.pool, id, id, rsaTestKeySize, false, "", "")
	require.NoError(t, err, "RSA key generation on the provisioned token must succeed")
	require.NotNil(t, signer)

	return signer
}

// digestFor hashes msg with h and returns the digest. PKCS#11 CKM_RSA_PKCS and
// CKM_RSA_PKCS_PSS both operate on a caller-supplied hash (PKCS#11 v3.2
// §6.1.10: the mechanism "does not compute a hash value on the message"), so
// every signing test must hash on the host.
func digestFor(t *testing.T, h crypto.Hash, msg []byte) []byte {
	t.Helper()

	switch h {
	case crypto.SHA1:
		sum := sha1.Sum(msg)
		return sum[:]
	case crypto.SHA224:
		sum := sha256.Sum224(msg)
		return sum[:]
	case crypto.SHA256:
		sum := sha256.Sum256(msg)
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(msg)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(msg)
		return sum[:]
	default:
		t.Fatalf("digestFor: unhandled hash %v", h)
		return nil
	}
}

// TestRSASigner_PublicMatchesTokenAttributes verifies that Public() returns the
// same modulus and exponent the token itself reports through CKA_MODULUS and
// CKA_PUBLIC_EXPONENT. SoftHSM is the oracle: the public key is read a second
// time over an independent introspection session so a bug in exportRSAPublicKey
// (byte order, truncated exponent, wrong attribute) cannot hide behind the
// value the signer cached at generation time.
func TestRSASigner_PublicMatchesTokenAttributes(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-public")
	signer := newRSATestSigner(t, b, "rsa-public")

	pub, ok := signer.Public().(*rsa.PublicKey)
	require.True(t, ok, "Public must return *rsa.PublicKey")
	require.Equal(t, rsaTestKeySize, pub.N.BitLen(), "modulus must have the requested bit length")
	require.Equal(t, 65537, pub.E, "the generator template pins the public exponent to 65537")

	session := openIntrospectionSession(t, b)
	handle := findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("rsa-public")),
	})

	attrs, err := b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	require.NoError(t, err)

	require.Equal(t, 0, pub.N.Cmp(new(big.Int).SetBytes(attrs[0].Value)),
		"exported modulus must equal CKA_MODULUS on the token")
	require.Equal(t, int64(pub.E), new(big.Int).SetBytes(attrs[1].Value).Int64(),
		"exported exponent must equal CKA_PUBLIC_EXPONENT on the token")
}

// TestRSASigner_SignPKCS1v15_VerifiesUnderRequestedHash signs with each
// supported hash and verifies the result outside the signer with
// crypto/rsa.VerifyPKCS1v15.
//
// Two negative halves guard against a silently substituted scheme:
//   - the signature must NOT verify as PSS, which would mean the PSS branch ran;
//   - the signature must NOT verify under a different hash, which would mean the
//     DigestInfo prefix (RFC 8017 §9.2 note 1) was taken from the wrong entry.
//
// A well-formed signature is not the same as the requested signature, so
// asserting only err == nil would let both substitutions through.
func TestRSASigner_SignPKCS1v15_VerifiesUnderRequestedHash(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-v15")
	signer := newRSATestSigner(t, b, "rsa-v15")
	pub := signer.Public().(*rsa.PublicKey)

	msg := []byte("pkcs1 v1.5 payload")

	for _, tc := range []struct {
		name      string
		hash      crypto.Hash
		otherHash crypto.Hash
	}{
		{"SHA1", crypto.SHA1, crypto.SHA256},
		{"SHA224", crypto.SHA224, crypto.SHA256},
		{"SHA256", crypto.SHA256, crypto.SHA384},
		{"SHA384", crypto.SHA384, crypto.SHA256},
		{"SHA512", crypto.SHA512, crypto.SHA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			digest := digestFor(t, tc.hash, msg)

			sig, err := signer.Sign(rand.Reader, digest, tc.hash)
			require.NoError(t, err)
			require.Len(t, sig, rsaTestKeySize/8, "an RSA signature is exactly one modulus wide")

			require.NoError(t, rsa.VerifyPKCS1v15(pub, tc.hash, digest, sig),
				"signature must verify as PKCS#1 v1.5 under the requested hash")

			require.ErrorIs(t,
				rsa.VerifyPSS(pub, tc.hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}),
				rsa.ErrVerification,
				"a PKCS#1 v1.5 signature must not verify as PSS")

			otherDigest := digestFor(t, tc.otherHash, msg)
			require.ErrorIs(t, rsa.VerifyPKCS1v15(pub, tc.otherHash, otherDigest, sig), rsa.ErrVerification,
				"the DigestInfo prefix must identify the hash that was requested")
		})
	}
}

// TestRSASigner_Sign_NilOptsDefaultsToSHA256 documents the contract that a nil
// crypto.SignerOpts selects PKCS#1 v1.5 with SHA-256, and proves it by
// verifying under SHA-256 only.
func TestRSASigner_Sign_NilOptsDefaultsToSHA256(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-nilopts")
	signer := newRSATestSigner(t, b, "rsa-nilopts")
	pub := signer.Public().(*rsa.PublicKey)

	msg := []byte("default options payload")
	digest := digestFor(t, crypto.SHA256, msg)

	sig, err := signer.Sign(rand.Reader, digest, nil)
	require.NoError(t, err)

	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig),
		"nil opts must produce a SHA-256 PKCS#1 v1.5 signature")
	require.ErrorIs(t,
		rsa.VerifyPKCS1v15(pub, crypto.SHA512, digestFor(t, crypto.SHA512, msg), sig),
		rsa.ErrVerification)
}

// TestRSASigner_SignPKCS1v15_NoneHashSignsVerbatim is the regression guard for
// the raw CKM_RSA_PKCS mechanism.
//
// crypto.Hash(0) is what xkms.ResolveHash returns for the wire sentinel "NONE",
// and it means the caller already built the bytes to pad and sign. libp11 and a
// TLS 1.3 CertificateVerify both arrive this way, carrying a complete
// DigestInfo. The backend previously prepended a second DigestInfo, so the
// token signed bytes nobody chose.
//
// Two independent oracles pin the behaviour, neither of them the module's own
// inverse: the signature must verify under crypto/rsa's own prefix table, and
// it must be byte-identical to the signature the same key produces for the bare
// digest under crypto.SHA256 — one padded block, reached two ways. A re-prefix
// breaks both.
func TestRSASigner_SignPKCS1v15_NoneHashSignsVerbatim(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-nonehash")
	signer := newRSATestSigner(t, b, "rsa-nonehash")
	pub := signer.Public().(*rsa.PublicKey)

	msg := []byte("raw CKM_RSA_PKCS payload")

	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		t.Run(h.String(), func(t *testing.T) {
			digest := digestFor(t, h, msg)
			prefix, ok := digestInfoPrefix[h]
			require.True(t, ok)

			// The DigestInfo the caller builds, exactly as libp11 hands it over.
			info := append(append([]byte{}, prefix...), digest...)

			sig, err := signer.Sign(rand.Reader, info, crypto.Hash(0))
			require.NoError(t, err, "the token must accept a caller-built DigestInfo")

			require.NoError(t, rsa.VerifyPKCS1v15(pub, h, digest, sig),
				"a signature over a caller-built %v DigestInfo must verify under %v", h, h)

			// The same padded block reached through the backend's own prefix
			// table. Any extra prefixing on the crypto.Hash(0) path changes the
			// block and breaks this equality.
			viaHash, err := signer.Sign(rand.Reader, digest, h)
			require.NoError(t, err)
			require.Equal(t, viaHash, sig,
				"signing a %v DigestInfo verbatim must equal signing its digest under %v", h, h)
		})
	}
}

// TestRSASigner_SignPKCS1v15_NoneHashRejectsOversizedInput verifies the
// bad-input side of the verbatim path: crypto.Hash(0) hands the token whatever
// it is given, so a payload that cannot fit in the modulus once PKCS#1 v1.5
// padding is added must surface the token's CKR value rather than produce a
// truncated block.
//
// The verbatim path does no length checking of its own — that is the point of
// it — which is exactly why the refusal has to be proven rather than assumed.
func TestRSASigner_SignPKCS1v15_NoneHashRejectsOversizedInput(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-nonehash-big")
	signer := newRSATestSigner(t, b, "rsa-nonehash-big")

	// A full modulus-width input leaves no room for the 0x00 0x01 ... 0x00
	// padding PKCS#1 v1.5 requires.
	oversized := make([]byte, rsaTestKeySize/8)

	sig, err := signer.Sign(rand.Reader, oversized, crypto.Hash(0))
	require.Nil(t, sig)
	require.Error(t, err, "an input too large for the modulus must not be signed")

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: RSA PKCS1v15 Sign", wrapped.Msg)

	var ckr pkcs11.Error
	require.True(t, errors.As(err, &ckr), "the token's CKR value must reach the caller")
}

// TestRSASigner_SignPSS_IsPSSNotPKCS1v15 is the regression guard for silently
// dropped mechanism parameters. CKM_RSA_PKCS_PSS carries a
// CK_RSA_PKCS_PSS_PARAMS structure (PKCS#11 v3.2 §6.1.9); if those parameters
// are lost between SignInit and the terminal Sign call the token falls back to
// a scheme the caller did not ask for. The resulting signature is still
// well-formed, so only verifying under PSS *and* refuting PKCS#1 v1.5 detects
// the downgrade.
func TestRSASigner_SignPSS_IsPSSNotPKCS1v15(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-pss")
	signer := newRSATestSigner(t, b, "rsa-pss")
	pub := signer.Public().(*rsa.PublicKey)

	msg := []byte("pss payload")

	for _, tc := range []struct {
		name      string
		hash      crypto.Hash
		otherHash crypto.Hash
	}{
		{"SHA1", crypto.SHA1, crypto.SHA256},
		{"SHA224", crypto.SHA224, crypto.SHA256},
		{"SHA256", crypto.SHA256, crypto.SHA384},
		{"SHA384", crypto.SHA384, crypto.SHA256},
		{"SHA512", crypto.SHA512, crypto.SHA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			digest := digestFor(t, tc.hash, msg)
			opts := &rsa.PSSOptions{Hash: tc.hash, SaltLength: rsa.PSSSaltLengthEqualsHash}

			sig, err := signer.Sign(rand.Reader, digest, opts)
			require.NoError(t, err)
			require.Len(t, sig, rsaTestKeySize/8)

			require.NoError(t, rsa.VerifyPSS(pub, tc.hash, digest, sig, opts),
				"signature must verify as PSS with the requested hash and salt length")

			require.ErrorIs(t, rsa.VerifyPKCS1v15(pub, tc.hash, digest, sig), rsa.ErrVerification,
				"a PSS request must not yield a PKCS#1 v1.5 signature")

			// The PSS hashAlg/mgf parameters must reach the token: verifying
			// under a different hash has to fail.
			otherDigest := digestFor(t, tc.otherHash, msg)
			require.ErrorIs(t,
				rsa.VerifyPSS(pub, tc.otherHash, otherDigest, sig, &rsa.PSSOptions{Hash: tc.otherHash, SaltLength: rsa.PSSSaltLengthEqualsHash}),
				rsa.ErrVerification,
				"PSS hashAlg must match the hash the caller requested")
		})
	}
}

// TestRSASigner_SignPSS_SaltLengthReachesToken proves the sLen field of
// CK_RSA_PKCS_PSS_PARAMS is transmitted rather than defaulted. Verification is
// performed with an explicit rsa.PSSOptions.SaltLength, which crypto/rsa checks
// exactly, so a signature produced with a different salt length is rejected.
func TestRSASigner_SignPSS_SaltLengthReachesToken(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-pss-salt")
	signer := newRSATestSigner(t, b, "rsa-pss-salt")
	pub := signer.Public().(*rsa.PublicKey)

	digest := digestFor(t, crypto.SHA256, []byte("salt length payload"))

	for _, saltLen := range []int{0 + 20, 32, 64} {
		sig, err := signer.Sign(rand.Reader, digest, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: saltLen})
		require.NoError(t, err)

		require.NoError(t,
			rsa.VerifyPSS(pub, crypto.SHA256, digest, sig, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: saltLen}),
			"signature must verify with the exact salt length requested (%d)", saltLen)

		wrongSalt := saltLen + 8
		require.ErrorIs(t,
			rsa.VerifyPSS(pub, crypto.SHA256, digest, sig, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: wrongSalt}),
			rsa.ErrVerification,
			"the salt length must not silently default away from %d", saltLen)
	}
}

// TestRSASigner_SignPSS_EqualsHashSaltLength verifies that
// rsa.PSSSaltLengthEqualsHash is translated into the hash output length in
// bytes, per the hashLen column of hashMap.
func TestRSASigner_SignPSS_EqualsHashSaltLength(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-pss-eqhash")
	signer := newRSATestSigner(t, b, "rsa-pss-eqhash")
	pub := signer.Public().(*rsa.PublicKey)

	digest := digestFor(t, crypto.SHA384, []byte("equals-hash payload"))

	sig, err := signer.Sign(rand.Reader, digest, &rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: rsa.PSSSaltLengthEqualsHash})
	require.NoError(t, err)

	require.NoError(t,
		rsa.VerifyPSS(pub, crypto.SHA384, digest, sig, &rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: 48}),
		"PSSSaltLengthEqualsHash for SHA-384 must produce a 48-byte salt")
	require.ErrorIs(t,
		rsa.VerifyPSS(pub, crypto.SHA384, digest, sig, &rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: 32}),
		rsa.ErrVerification)
}

// TestRSASigner_SignPSS_NegativeSaltLengthFallsBackToHashLength covers the
// defensive branch that maps any remaining negative salt length (a value other
// than the two documented crypto/rsa sentinels) onto the hash length.
func TestRSASigner_SignPSS_NegativeSaltLengthFallsBackToHashLength(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-pss-negsalt")
	signer := newRSATestSigner(t, b, "rsa-pss-negsalt")
	pub := signer.Public().(*rsa.PublicKey)

	digest := digestFor(t, crypto.SHA256, []byte("negative salt payload"))

	sig, err := signer.Sign(rand.Reader, digest, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: -7})
	require.NoError(t, err)

	require.NoError(t,
		rsa.VerifyPSS(pub, crypto.SHA256, digest, sig, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}),
		"an unrecognised negative salt length must fall back to the hash length")
}

// TestRSASigner_SignPSS_SaltLengthAutoRejected pins the documented refusal of
// rsa.PSSSaltLengthAuto. PKCS#11 requires an explicit sLen in
// CK_RSA_PKCS_PSS_PARAMS, so "auto" cannot be expressed; the signer must say so
// rather than silently pick a length the verifier will not expect.
//
// Note that rsa.PSSSaltLengthAuto is zero, so this is also the behaviour for a
// caller that leaves PSSOptions.SaltLength unset.
func TestRSASigner_SignPSS_SaltLengthAutoRejected(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-pss-auto")
	signer := newRSATestSigner(t, b, "rsa-pss-auto")

	digest := digestFor(t, crypto.SHA256, []byte("auto salt payload"))

	_, err := signer.Sign(rand.Reader, digest, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthAuto})
	require.ErrorIs(t, err, ErrUnsupportedOperation)

	var detail *errs.Detail
	require.True(t, errors.As(err, &detail), "the refusal must carry actionable detail")
	require.Equal(t, "PSSSaltLengthAuto not supported by PKCS#11", detail.Detail)
}

// TestRSASigner_Sign_UnsupportedHashRejected verifies that a hash outside
// hashMap/digestInfoPrefix is refused for both schemes instead of producing a
// signature over an unidentified digest.
func TestRSASigner_Sign_UnsupportedHashRejected(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-badhash")
	signer := newRSATestSigner(t, b, "rsa-badhash")

	digest := make([]byte, 16) // MD5-sized

	t.Run("PKCS1v15", func(t *testing.T) {
		_, err := signer.Sign(rand.Reader, digest, crypto.MD5)
		require.ErrorIs(t, err, ErrUnsupportedOperation)

		var detail *errs.Detail
		require.True(t, errors.As(err, &detail))
		require.Contains(t, detail.Detail, "unsupported hash for PKCS1v15")
	})

	t.Run("PSS", func(t *testing.T) {
		_, err := signer.Sign(rand.Reader, digest, &rsa.PSSOptions{Hash: crypto.MD5, SaltLength: rsa.PSSSaltLengthEqualsHash})
		require.ErrorIs(t, err, ErrUnsupportedOperation)

		var detail *errs.Detail
		require.True(t, errors.As(err, &detail))
		require.Contains(t, detail.Detail, "unsupported hash for PSS")
	})
}

// TestRSASigner_SignPSS_ZeroHashDefaultsToSHA256 covers the branch where
// PSSOptions.Hash is left at its zero value: the signer substitutes SHA-256,
// and the signature must verify under SHA-256.
func TestRSASigner_SignPSS_ZeroHashDefaultsToSHA256(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-pss-zerohash")
	signer := newRSATestSigner(t, b, "rsa-pss-zerohash")
	pub := signer.Public().(*rsa.PublicKey)

	digest := digestFor(t, crypto.SHA256, []byte("zero hash payload"))

	sig, err := signer.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: 32})
	require.NoError(t, err)
	require.NoError(t,
		rsa.VerifyPSS(pub, crypto.SHA256, digest, sig, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}))
}

// TestRSASigner_Sign_ClosedPool verifies that signing through a closed session
// pool fails with ErrSessionPoolClosed rather than blocking or panicking. A
// dedicated pool is used so the backend's own pool stays usable for cleanup.
func TestRSASigner_Sign_ClosedPool(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-signer-closedpool")
	signer := newRSATestSigner(t, b, "rsa-closedpool")

	slot, err := b.resolveSlot()
	require.NoError(t, err)
	pool, err := NewSessionPool(b.p11ctx, slot, b.config.PIN, 2)
	require.NoError(t, err)

	closedSigner := &pkcs11RSASigner{
		pool:          pool,
		privateHandle: signer.privateHandle,
		publicKey:     signer.publicKey,
		label:         signer.label,
	}
	pool.Close()

	digest := digestFor(t, crypto.SHA256, []byte("closed pool payload"))

	_, err = closedSigner.Sign(rand.Reader, digest, crypto.SHA256)
	require.ErrorIs(t, err, ErrSessionPoolClosed)

	_, err = closedSigner.Sign(rand.Reader, digest, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32})
	require.ErrorIs(t, err, ErrSessionPoolClosed)

	_, err = closedSigner.Decrypt(rand.Reader, make([]byte, rsaTestKeySize/8), nil)
	require.ErrorIs(t, err, ErrSessionPoolClosed)
}

// TestRSASigner_DecryptPKCS1v15_RoundTrip encrypts on the host with the
// exported public key and decrypts on the token, which proves the exported key
// and the on-token private key are a pair.
func TestRSASigner_DecryptPKCS1v15_RoundTrip(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-decrypt-v15")
	signer := newRSATestSigner(t, b, "rsa-dec-v15")
	pub := signer.Public().(*rsa.PublicKey)

	plaintext := []byte("pkcs1 v1.5 secret")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
	require.NoError(t, err)

	t.Run("nil opts", func(t *testing.T) {
		got, err := signer.Decrypt(rand.Reader, ciphertext, nil)
		require.NoError(t, err)
		require.Equal(t, plaintext, got)
	})

	t.Run("explicit PKCS1v15 opts", func(t *testing.T) {
		got, err := signer.Decrypt(rand.Reader, ciphertext, &rsa.PKCS1v15DecryptOptions{})
		require.NoError(t, err)
		require.Equal(t, plaintext, got)
	})
}

// TestRSASigner_DecryptPKCS1v15_MalformedCiphertext verifies that a ciphertext
// the token cannot even attempt to decrypt is reported as an error carrying the
// decrypt call site, rather than being swallowed.
//
// The input is longer than the modulus, which C_Decrypt must reject outright.
// The specific CKR code is deliberately not pinned: PKCS#11 v3.2 leaves the
// choice between CKR_ENCRYPTED_DATA_LEN_RANGE and a general failure to the
// module (SoftHSM returns CKR_GENERAL_ERROR here), so the assertion is that the
// token's own CKR value reaches the caller under the right message.
//
// A ciphertext of the right length but invalid padding is NOT usable as a
// negative case: OpenSSL 3.2+ implements implicit rejection for
// EME-PKCS1-v1_5, so SoftHSM returns pseudo-random plaintext and no error.
// Callers of PKCS#1 v1.5 decryption must therefore authenticate the plaintext
// themselves; the backend cannot detect the failure.
func TestRSASigner_DecryptPKCS1v15_MalformedCiphertext(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-decrypt-v15-bad")
	signer := newRSATestSigner(t, b, "rsa-dec-v15-bad")

	oversized := make([]byte, rsaTestKeySize/8+44)

	_, err := signer.Decrypt(rand.Reader, oversized, nil)
	require.Error(t, err)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: RSA PKCS1v15 Decrypt", wrapped.Msg)

	var ckr pkcs11.Error
	require.True(t, errors.As(err, &ckr), "the token's CKR value must reach the caller")
}

// TestRSASigner_DecryptOAEP_RoundTrip proves both halves of the OAEP contract
// against SoftHSM:
//
//   - positive: a ciphertext produced on the host with OAEP-SHA-1 decrypts on
//     the token when SHA-1 is requested;
//   - negative: the same ciphertext must NOT decrypt when SHA-256 is requested.
//
// The negative half is what catches a dropped CK_RSA_PKCS_OAEP_PARAMS.hashAlg.
// If opts.Hash were ignored and the mechanism always used SHA-1, the second
// call would happily return the plaintext.
//
// SHA-1 is the encryption hash because SoftHSM2 implements CKM_RSA_PKCS_OAEP
// with MGF1-SHA-1 only and answers any other hashAlg with CKR_ARGUMENTS_BAD
// from C_DecryptInit.
func TestRSASigner_DecryptOAEP_RoundTrip(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-decrypt-oaep")
	signer := newRSATestSigner(t, b, "rsa-dec-oaep")
	pub := signer.Public().(*rsa.PublicKey)

	plaintext := []byte("oaep secret")

	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plaintext, nil)
	require.NoError(t, err)

	got, err := signer.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA1})
	require.NoError(t, err)
	require.Equal(t, plaintext, got)

	wrongHash, err := signer.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
	require.Error(t, err, "OAEP must not decrypt under a hash the caller did not request")
	require.NotEqual(t, plaintext, wrongHash)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.True(t, strings.HasPrefix(wrapped.Msg, "pkcs11: RSA OAEP Decrypt"),
		"failure must be attributed to the OAEP decrypt path, got %q", wrapped.Msg)
}

// TestRSASigner_DecryptOAEP_ZeroHashDefaultsToSHA256 covers the branch where
// OAEPOptions.Hash is left at its zero value. SoftHSM only implements
// MGF1-SHA-1 OAEP, so the observable proof that the default is SHA-256 is that
// the token rejects the mechanism parameters at C_DecryptInit exactly as it
// does for an explicit SHA-256 request. Were the default silently SHA-1, the
// call would succeed and this assertion would fail.
func TestRSASigner_DecryptOAEP_ZeroHashDefaultsToSHA256(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-decrypt-oaep-zero")
	signer := newRSATestSigner(t, b, "rsa-dec-oaep-zero")
	pub := signer.Public().(*rsa.PublicKey)

	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, []byte("default oaep hash"), nil)
	require.NoError(t, err)

	_, errZero := signer.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{})
	require.Error(t, errZero)

	_, errSHA256 := signer.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
	require.Error(t, errSHA256)

	require.Equal(t, errSHA256.Error(), errZero.Error(),
		"a zero OAEPOptions.Hash must behave exactly like an explicit SHA-256")
}

// TestRSASigner_DecryptOAEP_UnsupportedHashRejected verifies the OAEP hash is
// validated against hashMap before any token call.
func TestRSASigner_DecryptOAEP_UnsupportedHashRejected(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-decrypt-oaep-badhash")
	signer := newRSATestSigner(t, b, "rsa-dec-oaep-badhash")

	_, err := signer.Decrypt(rand.Reader, make([]byte, rsaTestKeySize/8), &rsa.OAEPOptions{Hash: crypto.MD5})
	require.ErrorIs(t, err, ErrUnsupportedOperation)

	var detail *errs.Detail
	require.True(t, errors.As(err, &detail))
	require.Contains(t, detail.Detail, "unsupported hash for OAEP")
}

// TestExportRSAPublicKey_InvalidHandle verifies the failure path of
// exportRSAPublicKey: an object handle the token does not know must produce a
// wrapped CKR_OBJECT_HANDLE_INVALID, not a nil public key with a nil error.
func TestExportRSAPublicKey_InvalidHandle(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-export-badhandle")

	pub, err := exportRSAPublicKey(b.pool, pkcs11.ObjectHandle(0xdeadbeef))
	require.Nil(t, pub)
	require.Error(t, err)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: get RSA public key attributes", wrapped.Msg)
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID))
}

// TestExportRSAPublicKey_NonRSAHandle verifies that pointing exportRSAPublicKey
// at an EC public key reports the missing-attribute condition rather than
// constructing an RSA key from empty bytes.
func TestExportRSAPublicKey_NonRSAHandle(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-export-nonrsa")

	id := []byte("ec-for-rsa-export")
	_, err := generateECDSAKeyPair(b.pool, id, id, elliptic.P256(), false, "", "")
	require.NoError(t, err)

	session := openIntrospectionSession(t, b)
	handle := findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	})

	pub, err := exportRSAPublicKey(b.pool, handle)
	require.Nil(t, pub)
	require.Error(t, err, "an EC object has neither CKA_MODULUS nor CKA_PUBLIC_EXPONENT")
}

// TestGenerateRSAKeyPair_YubiKeyPIVRequiresSOPIN verifies the guard that
// converts the token's opaque CKR_USER_TYPE_INVALID into an actionable error
// when a PIV key generation is attempted without the management key.
func TestGenerateRSAKeyPair_YubiKeyPIVRequiresSOPIN(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-gen-nosopin")

	id := []byte{0x9a}
	signer, err := generateRSAKeyPair(b.pool, id, id, rsaTestKeySize, true, "", "1234")
	require.Nil(t, signer)
	require.ErrorIs(t, err, ErrSOPINRequired)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: generate RSA key pair", wrapped.Msg)
}

// TestGenerateRSAKeyPair_InvalidKeySize verifies that a modulus size the token
// refuses is reported as a wrapped generation failure carrying the token's own
// return value.
func TestGenerateRSAKeyPair_InvalidKeySize(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-gen-badsize")

	id := []byte("rsa-badsize")
	signer, err := generateRSAKeyPair(b.pool, id, id, 7, false, "", "")
	require.Nil(t, signer)
	require.Error(t, err)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: generate RSA key pair", wrapped.Msg)
}

// TestGenerateRSAWrappingKeyPair_UsableForWrapping verifies the wrapping key
// generator produces a key whose exported public half round-trips a payload
// through the on-token private half, which is the property key import depends
// on.
func TestGenerateRSAWrappingKeyPair_UsableForWrapping(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-wrapkey")

	signer, err := generateRSAWrappingKeyPair(b.pool, []byte("wrap-key"), rsaTestKeySize)
	require.NoError(t, err)
	require.NotNil(t, signer)

	pub := signer.Public().(*rsa.PublicKey)
	require.Equal(t, rsaTestKeySize, pub.N.BitLen())

	// OAEP-SHA-1 is used because SoftHSM implements CKM_RSA_PKCS_OAEP with
	// MGF1-SHA-1 only; the property under test is that the generated pair is a
	// real pair, not which digest the token supports.
	secret := []byte("wrapped material")
	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, secret, nil)
	require.NoError(t, err)

	got, err := signer.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA1})
	require.NoError(t, err)
	require.Equal(t, secret, got)
}

// TestGenerateRSAWrappingKeyPair_InvalidKeySize verifies the error path of the
// wrapping key generator.
func TestGenerateRSAWrappingKeyPair_InvalidKeySize(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-wrapkey-bad")

	signer, err := generateRSAWrappingKeyPair(b.pool, []byte("wrap-bad"), 7)
	require.Nil(t, signer)
	require.Error(t, err)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: generate RSA wrapping key pair", wrapped.Msg)
}

// TestFindRSASigner_RoundTrip verifies that a key located by CKA_ID after
// generation is the same key: the public half must match and a signature made
// through the found signer must verify against the generated signer's public
// key.
func TestFindRSASigner_RoundTrip(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-find")

	id := []byte("rsa-find-me")
	generated := newRSATestSigner(t, b, string(id))

	found, err := findRSASigner(b.pool, id)
	require.NoError(t, err)
	require.NotNil(t, found, "a key generated moments ago must be findable by CKA_ID")

	generatedPub := generated.Public().(*rsa.PublicKey)
	foundPub := found.Public().(*rsa.PublicKey)
	require.Equal(t, 0, generatedPub.N.Cmp(foundPub.N))
	require.Equal(t, generatedPub.E, foundPub.E)

	digest := digestFor(t, crypto.SHA256, []byte("found signer payload"))
	sig, err := found.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(generatedPub, crypto.SHA256, digest, sig),
		"the found handle must belong to the generated key pair")
}

// TestFindRSASigner_NotFound verifies the documented (nil, nil) result for an
// absent key. Callers distinguish "no such key" from "lookup failed" by that
// contract, so a non-nil error here would be a behavioural break.
func TestFindRSASigner_NotFound(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-find-missing")

	found, err := findRSASigner(b.pool, []byte("no-such-rsa-key"))
	require.NoError(t, err, "an absent key is not an error")
	require.Nil(t, found)
}

// TestFindRSASigner_ClosedPool verifies the lookup surfaces the pool state
// instead of panicking on a nil session.
func TestFindRSASigner_ClosedPool(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-find-closed")

	slot, err := b.resolveSlot()
	require.NoError(t, err)
	pool, err := NewSessionPool(b.p11ctx, slot, b.config.PIN, 1)
	require.NoError(t, err)
	pool.Close()

	found, err := findRSASigner(pool, []byte("anything"))
	require.Nil(t, found)
	require.ErrorIs(t, err, ErrSessionPoolClosed)
}

// TestDigestInfoPrefixes verifies the DER DigestInfo prefixes against
// RFC 8017 §9.2 note 1 by cross-checking each prefix with a signature produced
// by crypto/rsa on a host key. A wrong prefix byte would make every PKCS#1
// v1.5 signature from this backend unverifiable by standards-compliant peers,
// and no token-side test would notice because the token signs whatever it is
// handed.
func TestDigestInfoPrefixes(t *testing.T) {
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	msg := []byte("digest info prefix check")

	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		digest := digestFor(t, h, msg)
		prefix, ok := digestInfoPrefix[h]
		require.True(t, ok, "hash %v must have a DigestInfo prefix", h)

		info := append(append([]byte{}, prefix...), digest...)

		// crypto.Hash(0) means "sign this DigestInfo verbatim", so the
		// signature is produced from our prefix but verified with the
		// standard library's own prefix table.
		sig, err := rsa.SignPKCS1v15(rand.Reader, hostKey, crypto.Hash(0), info)
		require.NoError(t, err)
		require.NoError(t, rsa.VerifyPKCS1v15(&hostKey.PublicKey, h, digest, sig),
			"DigestInfo prefix for %v does not match RFC 8017", h)
	}
}

// TestHashMap_LengthsMatchGo verifies the hashLen column of hashMap against
// crypto.Hash.Size. hashLen feeds the PSS salt length, so a wrong entry would
// produce signatures no verifier accepts.
func TestHashMap_LengthsMatchGo(t *testing.T) {
	for h, info := range hashMap {
		require.Equal(t, uint(h.Size()), info.hashLen, "hashMap length for %v", h)
	}
}

// TestRSASigner_SignPKCS1v15_DigestTooLargeForModulus verifies that a digest
// which cannot fit in the modulus once the DigestInfo prefix and padding are
// added is rejected by the token at C_Sign, with the signing call site in the
// message.
//
// This is the failure the caller sees when a hash is paired with an
// undersized key, and it must surface rather than produce a truncated block.
func TestRSASigner_SignPKCS1v15_DigestTooLargeForModulus(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-sign-toolong")
	signer := newRSATestSigner(t, b, "rsa-sign-toolong")

	oversized := make([]byte, rsaTestKeySize/8)

	sig, err := signer.Sign(rand.Reader, oversized, crypto.SHA256)
	require.Nil(t, sig)
	require.Error(t, err)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: RSA PKCS1v15 Sign", wrapped.Msg)

	var ckr pkcs11.Error
	require.True(t, errors.As(err, &ckr), "the token's CKR value must reach the caller")
}

// TestRSASigner_SignPSS_DigestLengthMustMatchHash verifies that the token
// enforces the agreement between the digest the caller supplies and the hashAlg
// declared in CK_RSA_PKCS_PSS_PARAMS. PKCS#11 v3.2 §6.1.9 requires hashAlg to
// be "the mechanism used by the application to generate the message hash"; a
// 20-byte digest presented under SHA-256 parameters violates that and must not
// be signed.
func TestRSASigner_SignPSS_DigestLengthMustMatchHash(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-sign-pss-mismatch")
	signer := newRSATestSigner(t, b, "rsa-pss-mismatch")

	shortDigest := digestFor(t, crypto.SHA1, []byte("mismatched digest"))
	require.Len(t, shortDigest, 20)

	sig, err := signer.Sign(rand.Reader, shortDigest, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32})
	require.Nil(t, sig)
	require.Error(t, err, "a digest that does not match the declared PSS hash must be refused")

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: RSA PSS Sign", wrapped.Msg)
}

// TestRSASigner_Decrypt_InvalidHandle verifies that decryption with a handle
// the token does not recognise fails at DecryptInit for both schemes, instead
// of returning empty plaintext.
func TestRSASigner_Decrypt_InvalidHandle(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-decrypt-badhandle")
	signer := newRSATestSigner(t, b, "rsa-dec-badhandle")

	broken := &pkcs11RSASigner{
		pool:          b.pool,
		privateHandle: pkcs11.ObjectHandle(0xdeadbeef),
		publicKey:     signer.publicKey,
		label:         signer.label,
	}

	ciphertext := make([]byte, rsaTestKeySize/8)

	t.Run("PKCS1v15", func(t *testing.T) {
		plaintext, err := broken.Decrypt(rand.Reader, ciphertext, nil)
		require.Nil(t, plaintext)
		require.Error(t, err)

		var wrapped *errs.Wrapped
		require.True(t, errors.As(err, &wrapped))
		require.Equal(t, "pkcs11: RSA PKCS1v15 DecryptInit", wrapped.Msg)
	})

	t.Run("OAEP", func(t *testing.T) {
		plaintext, err := broken.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA1})
		require.Nil(t, plaintext)
		require.Error(t, err)

		var wrapped *errs.Wrapped
		require.True(t, errors.As(err, &wrapped))
		require.Equal(t, "pkcs11: RSA OAEP DecryptInit", wrapped.Msg)
	})
}

// TestFindRSASigner_PrivateKeyWithoutPublicKey documents the lookup contract
// when the public half is absent: no signer is returned, because a signer whose
// Public() is nil would fail far away from the cause.
func TestFindRSASigner_PrivateKeyWithoutPublicKey(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-find-no-public")

	id := []byte("rsa-orphan")
	newRSATestSigner(t, b, string(id))

	require.NoError(t, b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := b.p11ctx.FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}); err != nil {
			return err
		}
		handles, _, err := b.p11ctx.FindObjects(session, 1)
		if err != nil {
			return err
		}
		if err := b.p11ctx.FindObjectsFinal(session); err != nil {
			return err
		}
		require.Len(t, handles, 1)
		return b.p11ctx.DestroyObject(session, handles[0])
	}))

	found, err := findRSASigner(b.pool, id)
	require.NoError(t, err, "a missing public half is not a lookup failure")
	require.Nil(t, found)
}

// TestGenerateRSAKeyPair_YubiKeyPIVUsesSOAuthentication verifies that the PIV
// branch runs key generation under Security Officer authentication rather than
// the user session.
//
// SoftHSM is the oracle in the negative direction: a Security Officer may not
// create private objects, so generation must fail on this token. The value of
// the test is that it proves the SO escalation path is taken at all — if the
// PIV branch quietly used the user session, generation would succeed here.
// It also proves the user login is restored afterwards, which is what keeps the
// rest of the token usable after a failed PIV operation.
func TestGenerateRSAKeyPair_YubiKeyPIVUsesSOAuthentication(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-gen-so-path")
	pool := newTestPool(t, b, 2)

	id := []byte{0x9a}
	signer, err := generateRSAKeyPair(pool, id, id, rsaTestKeySize, true, b.config.SOPIN, b.config.PIN)
	require.Nil(t, signer)
	require.Error(t, err, "a Security Officer cannot create private key objects on this token")

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: generate RSA key pair", wrapped.Msg)

	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		info, infoErr := b.p11ctx.GetSessionInfo(session)
		if infoErr != nil {
			return infoErr
		}
		require.Equal(t, uint(pkcs11.CKS_RW_USER_FUNCTIONS), info.State,
			"the user login must be restored after the SO-authenticated attempt")
		return nil
	}))
}

// TestFindRSASigner_DeadSession verifies that an unusable session produces an
// error rather than the (nil, nil) "not found" result. Conflating the two would
// let a caller conclude a key had been deleted when in fact the module lost the
// session.
func TestFindRSASigner_DeadSession(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-find-dead-session")
	pool := newTestPool(t, b, 1)

	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		return b.p11ctx.CloseSession(session)
	}))

	found, err := findRSASigner(pool, []byte("anything"))
	require.Nil(t, found)
	require.Error(t, err, "a broken session must not be reported as a missing key")

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: FindObjectsInit for RSA private key", wrapped.Msg)
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID))
}

// TestGenerateRSAKeyPair_PrivateKeyProtectionIsExplicit asserts the protection
// and usage attributes of a generated RSA private key.
//
// CKA_SENSITIVE and CKA_EXTRACTABLE are written into the template rather than
// left to the token: PKCS#11 3.2 §4.9 makes both defaults token-specific for a
// generated private key, so a template that omits them protects the key
// differently on every module. SoftHSM2 chooses the same values this backend
// asks for, so what these assertions pin down is the contract other modules
// must meet, not a behaviour change on this one.
//
// CKA_DERIVE must stay false. It is the flag C_DeriveKey tests on its base key,
// and no derive mechanism here takes an RSA base key, so granting it would hand
// the key a permission it can never use. This is where the RSA template
// deliberately differs from the EC one.
func TestGenerateRSAKeyPair_PrivateKeyProtectionIsExplicit(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-protection")

	id := []byte("rsa-protection-key")
	_, err := generateRSAKeyPair(b.pool, id, id, rsaTestKeySize, false, "", "")
	require.NoError(t, err)

	session := openIntrospectionSession(t, b)
	handle := findGeneratedPrivateKey(t, b, session, id)

	flags := readBoolAttributes(t, b, session, handle,
		pkcs11.CKA_SENSITIVE, pkcs11.CKA_EXTRACTABLE, pkcs11.CKA_DERIVE,
		pkcs11.CKA_SIGN, pkcs11.CKA_DECRYPT, pkcs11.CKA_UNWRAP)

	require.True(t, flags[0], "CKA_SENSITIVE must be true: the private key is never disclosed in plaintext")
	require.False(t, flags[1], "CKA_EXTRACTABLE must be false: a key born in the token may not be wrapped out")
	require.False(t, flags[2], "CKA_DERIVE must be false: no derive mechanism takes an RSA base key")
	require.True(t, flags[3], "CKA_SIGN must be true: the generated object backs a crypto.Signer")
	require.True(t, flags[4], "CKA_DECRYPT must be true: the generated object backs a crypto.Decrypter")
	require.True(t, flags[5], "CKA_UNWRAP must be true: imported keys are delivered under this key")

	// Enforcement rather than the stored value: CKA_SENSITIVE is the attribute
	// that stops plaintext disclosure, so the private exponent must be
	// unreadable.
	_, err = b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, nil),
	})
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_SENSITIVE),
		"a sensitive RSA key must not reveal its private exponent")

	// The corresponding CKA_EXTRACTABLE enforcement -- C_WrapKey answering
	// CKR_KEY_UNEXTRACTABLE for a generated RSA key -- is covered end to end by
	// TestExportKey_RefusesAKeyTheTokenSealed, which drives it through
	// Backend.ExportKey.
}

// TestGenerateRSAKeyPair_SealedKeyStillSignsAndDecrypts is the other half of
// the protection template: writing CKA_EXTRACTABLE explicitly must not cost the
// key any operation it is supposed to perform.
//
// Both halves are verified outside the backend with crypto/rsa against the
// public key the token reports, so a signature the token could not have
// produced, or a decryption that returned the wrong bytes, fails here.
func TestGenerateRSAKeyPair_SealedKeyStillSignsAndDecrypts(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-protection-usable")

	signer := newRSATestSigner(t, b, "rsa-sealed-usable-key")

	message := []byte("a sealed key is still a working key")
	digest := digestFor(t, crypto.SHA256, message)

	signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err, "a non-extractable key must still sign")
	require.NoError(t,
		rsa.VerifyPKCS1v15(signer.publicKey, crypto.SHA256, digest, signature),
		"the signature must verify under the token's public key")

	// SoftHSM2 implements OAEP with MGF1-SHA-1 only, which is why the decrypt
	// half uses SHA-1 rather than the SHA-256 used for the signature above.
	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, signer.publicKey, message, nil)
	require.NoError(t, err)

	plaintext, err := signer.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA1})
	require.NoError(t, err, "a non-extractable key must still decrypt")
	require.Equal(t, message, plaintext, "the token must recover the exact plaintext")
}

// TestGenerateRSAKeyPair_ClosedPool is the bad-input half for the generation
// path: a pool whose sessions are gone must report the failure and return no
// signer, rather than a signer holding a handle that addresses nothing.
func TestGenerateRSAKeyPair_ClosedPool(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-generate-closed-pool")
	pool := newTestPool(t, b, 1)
	pool.Close()

	id := []byte("rsa-closed-pool-key")
	signer, err := generateRSAKeyPair(pool, id, id, rsaTestKeySize, false, "", "")
	require.Nil(t, signer)
	require.ErrorIs(t, err, ErrSessionPoolClosed)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: generate RSA key pair", wrapped.Msg)
}
