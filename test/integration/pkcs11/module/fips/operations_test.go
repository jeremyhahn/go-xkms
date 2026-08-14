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

//go:build integration && fips

package fips

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"math/big"
	"sort"
	"testing"

	"github.com/miekg/pkcs11"
)

// exercise runs one mechanism end to end and checks the result against an
// independent implementation from crypto/*.
type exercise func(t *testing.T, tok *token, fx *fixtures)

// exercisers maps every mechanism the module advertises under FIPS to a test
// that performs its operation and verifies the outcome against crypto/*.
//
// Checking against the standard library rather than against the module's own
// inverse operation is the point. A module whose signer and verifier share the
// same defect verifies its own broken signatures happily; only an outside
// implementation notices. Likewise a cipher that returns its input unchanged
// round-trips perfectly.
var exercisers = map[uint]exercise{
	pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN: exerciseRSAKeyPairGen,
	pkcs11.CKM_RSA_PKCS:              exerciseRSAPKCS,
	pkcs11.CKM_RSA_PKCS_OAEP:         exerciseRSAOAEP,
	pkcs11.CKM_RSA_PKCS_PSS:          exerciseRSAPSSBare,
	pkcs11.CKM_SHA256_RSA_PKCS:       exerciseRSAPKCSDigest(crypto.SHA256, pkcs11.CKM_SHA256_RSA_PKCS),
	pkcs11.CKM_SHA384_RSA_PKCS:       exerciseRSAPKCSDigest(crypto.SHA384, pkcs11.CKM_SHA384_RSA_PKCS),
	pkcs11.CKM_SHA512_RSA_PKCS:       exerciseRSAPKCSDigest(crypto.SHA512, pkcs11.CKM_SHA512_RSA_PKCS),
	pkcs11.CKM_SHA256_RSA_PKCS_PSS:   exerciseRSAPSSDigest(crypto.SHA256, pkcs11.CKM_SHA256_RSA_PKCS_PSS, pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256),
	pkcs11.CKM_SHA384_RSA_PKCS_PSS:   exerciseRSAPSSDigest(crypto.SHA384, pkcs11.CKM_SHA384_RSA_PKCS_PSS, pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384),
	pkcs11.CKM_SHA512_RSA_PKCS_PSS:   exerciseRSAPSSDigest(crypto.SHA512, pkcs11.CKM_SHA512_RSA_PKCS_PSS, pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512),

	pkcs11.CKM_EC_KEY_PAIR_GEN: exerciseECKeyPairGen,
	pkcs11.CKM_ECDSA:           exerciseECDSABare,
	pkcs11.CKM_ECDSA_SHA256:    exerciseECDSADigest(crypto.SHA256, pkcs11.CKM_ECDSA_SHA256),
	pkcs11.CKM_ECDSA_SHA384:    exerciseECDSADigest(crypto.SHA384, pkcs11.CKM_ECDSA_SHA384),
	pkcs11.CKM_ECDSA_SHA512:    exerciseECDSADigest(crypto.SHA512, pkcs11.CKM_ECDSA_SHA512),
	pkcs11.CKM_ECDH1_DERIVE:    exerciseECDH1Derive,

	ckmECEdwardsKeyPairGen: exerciseEdwardsKeyPairGen,
	ckmEdDSA:               exerciseEdDSA,

	pkcs11.CKM_AES_KEY_GEN:      exerciseAESKeyGen,
	pkcs11.CKM_AES_ECB:          exerciseAESECB,
	pkcs11.CKM_AES_CBC:          exerciseAESCBC,
	pkcs11.CKM_AES_CBC_PAD:      exerciseAESCBCPad,
	pkcs11.CKM_AES_GCM:          exerciseAESGCM,
	pkcs11.CKM_AES_KEY_WRAP:     exerciseAESKeyWrap,
	pkcs11.CKM_AES_KEY_WRAP_PAD: exerciseAESKeyWrapPad,

	pkcs11.CKM_SHA_1:  exerciseDigest(pkcs11.CKM_SHA_1, func() hash.Hash { return sha1.New() }),
	pkcs11.CKM_SHA256: exerciseDigest(pkcs11.CKM_SHA256, func() hash.Hash { return sha256.New() }),
	pkcs11.CKM_SHA384: exerciseDigest(pkcs11.CKM_SHA384, func() hash.Hash { return sha512.New384() }),
	pkcs11.CKM_SHA512: exerciseDigest(pkcs11.CKM_SHA512, func() hash.Hash { return sha512.New() }),
}

// TestFIPSApproved_EveryAdvertisedMechanismWorks runs every mechanism the
// module offers under FIPS and checks its output against crypto/*.
//
// This is the half of FIPS mode the previous coverage never touched. Withholding
// a non-approved mechanism is easy to get right and easy to test; keeping the
// approved ones working through the same code path is where a FIPS build
// actually breaks, and a mechanism that is advertised but broken is worse than
// one that is withheld, because an application has no way to find out except in
// production.
//
// The list of mechanisms comes from C_GetMechanismList rather than from a
// constant here, so the coverage is whatever the module currently promises, and
// TestFIPSFilter_EveryListedMechanismHasAnExerciser fails if that promise grows
// past this table. Nothing is sampled and nothing is dropped.
func TestFIPSApproved_EveryAdvertisedMechanismWorks(t *testing.T) {
	tok := openToken(t)

	advertised, err := collectMechanisms(tok.ctx, tok.slot)
	if err != nil {
		t.Fatalf("collecting mechanisms: %v", err)
	}
	mechs := advertised.types()
	sort.Slice(mechs, func(i, j int) bool { return mechs[i] < mechs[j] })

	fx := newFixtures(t, tok)

	for _, mech := range mechs {
		run, ok := exercisers[mech]
		if !ok {
			t.Errorf("%s (0x%08X) is advertised under FIPS but this suite has no exerciser for it",
				mechName(mech), mech)
			continue
		}
		t.Run(mechName(mech), func(t *testing.T) {
			run(t, tok, fx)
		})
	}
}

// digestInfoPrefixes are the DER-encoded DigestInfo prefixes RFC 8017 §9.2
// puts in front of a digest for RSASSA-PKCS1-v1_5. CKM_RSA_PKCS signs whatever
// the caller hands it, so the caller must build these.
var digestInfoPrefixes = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// digestOf hashes msg with h.
func digestOf(h crypto.Hash, msg []byte) []byte {
	hasher := h.New()
	hasher.Write(msg)
	return hasher.Sum(nil)
}

// sign runs C_SignInit followed by C_Sign and returns the signature.
func sign(t *testing.T, tok *token, mech *pkcs11.Mechanism, key pkcs11.ObjectHandle, data []byte) []byte {
	t.Helper()

	if err := tok.ctx.SignInit(tok.session, []*pkcs11.Mechanism{mech}, key); err != nil {
		t.Fatalf("C_SignInit(0x%08X): %v", mech.Mechanism, err)
	}
	sig, err := tok.ctx.Sign(tok.session, data)
	if err != nil {
		t.Fatalf("C_Sign(0x%08X): %v", mech.Mechanism, err)
	}
	if len(sig) == 0 {
		t.Fatalf("C_Sign(0x%08X) returned an empty signature", mech.Mechanism)
	}
	return sig
}

// exerciseRSAKeyPairGen generates a fresh RSA key pair and proves the public
// half the token published really belongs to the private half it kept, by
// signing with the token and verifying with crypto/rsa.
//
// A module that returned a well-formed but unrelated modulus would pass any
// attribute-shape check and fail here, and every certificate it ever issued
// would be unverifiable.
func exerciseRSAKeyPairGen(t *testing.T, tok *token, fx *fixtures) {
	pair := generateRSA(t, tok, 2048)

	if bits := pair.rsaPub.N.BitLen(); bits != 2048 {
		t.Errorf("CKA_MODULUS is %d bits, want the 2048 requested through CKA_MODULUS_BITS", bits)
	}
	if pair.rsaPub.E != 65537 {
		t.Errorf("CKA_PUBLIC_EXPONENT is %d, want the 65537 requested", pair.rsaPub.E)
	}

	digest := digestOf(crypto.SHA256, []byte("rsa key pair generation"))
	sig := sign(t, tok, pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil), pair.priv,
		[]byte("rsa key pair generation"))
	if err := rsa.VerifyPKCS1v15(pair.rsaPub, crypto.SHA256, digest, sig); err != nil {
		t.Fatalf("crypto/rsa rejects a signature made by the freshly generated private key "+
			"against the public key the token published for it: %v", err)
	}
}

// exerciseRSAPKCS covers the bare CKM_RSA_PKCS mechanism in both of the roles
// its CKF_ flags claim: PKCS#1 v1.5 signing, where the caller supplies the
// DigestInfo, and PKCS#1 v1.5 decryption.
//
// The decryption direction is checked by having crypto/rsa produce the
// ciphertext, so a decrypt that silently returns its input, or that pairs with
// an equally broken encrypt, cannot pass.
func exerciseRSAPKCS(t *testing.T, tok *token, fx *fixtures) {
	message := []byte("bare CKM_RSA_PKCS")
	digest := digestOf(crypto.SHA256, message)
	digestInfo := append(append([]byte{}, digestInfoPrefixes[crypto.SHA256]...), digest...)

	sig := sign(t, tok, pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), fx.rsa.priv, digestInfo)
	if err := rsa.VerifyPKCS1v15(fx.rsa.rsaPub, crypto.SHA256, digest, sig); err != nil {
		t.Fatalf("crypto/rsa rejects the CKM_RSA_PKCS signature over a SHA-256 DigestInfo: %v", err)
	}

	plaintext := []byte("pkcs1 v1.5 payload")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, fx.rsa.rsaPub, plaintext)
	if err != nil {
		t.Fatalf("crypto/rsa could not build the ciphertext: %v", err)
	}
	if err := tok.ctx.DecryptInit(tok.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, fx.rsa.priv); err != nil {
		t.Fatalf("C_DecryptInit(CKM_RSA_PKCS): %v", err)
	}
	recovered, err := tok.ctx.Decrypt(tok.session, ciphertext)
	if err != nil {
		t.Fatalf("C_Decrypt(CKM_RSA_PKCS): %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("C_Decrypt(CKM_RSA_PKCS) returned %q, want %q", recovered, plaintext)
	}
}

// exerciseRSAOAEP has crypto/rsa produce an OAEP ciphertext and asks the token
// to recover it, so the token's OAEP parameters must match RFC 8017 exactly
// rather than merely matching its own encryptor.
func exerciseRSAOAEP(t *testing.T, tok *token, fx *fixtures) {
	plaintext := []byte("oaep payload")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, fx.rsa.rsaPub, plaintext, nil)
	if err != nil {
		t.Fatalf("crypto/rsa could not build the OAEP ciphertext: %v", err)
	}

	params := pkcs11.NewOAEPParams(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256,
		pkcs11.CKZ_DATA_SPECIFIED, nil)
	if err := tok.ctx.DecryptInit(tok.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}, fx.rsa.priv); err != nil {
		t.Fatalf("C_DecryptInit(CKM_RSA_PKCS_OAEP): %v", err)
	}
	recovered, err := tok.ctx.Decrypt(tok.session, ciphertext)
	if err != nil {
		t.Fatalf("C_Decrypt(CKM_RSA_PKCS_OAEP): %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("C_Decrypt(CKM_RSA_PKCS_OAEP) returned %q, want %q", recovered, plaintext)
	}
}

// exerciseRSAPSSBare signs a caller-supplied digest with CKM_RSA_PKCS_PSS and
// verifies the signature with crypto/rsa.
//
// PKCS#11 v3.2 §6.1.15 defines the input to the bare CKM_RSA_PKCS_PSS as the
// message *hash*: the mechanism parameter names the hash the caller already
// applied, it does not ask the token to apply it. A token that hashes the input
// again signs H(H(m)) and produces a signature no verifier can check, which is
// why this exerciser tells the two cases apart in its failure message instead
// of reporting a bare verification error.
func exerciseRSAPSSBare(t *testing.T, tok *token, fx *fixtures) {
	message := []byte("bare pss")
	digest := digestOf(crypto.SHA256, message)
	params := pkcs11.NewPSSParams(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, uint(sha256.Size))

	sig := sign(t, tok, pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, params), fx.rsa.priv, digest)
	if err := rsa.VerifyPSS(fx.rsa.rsaPub, crypto.SHA256, digest, sig,
		&rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256}); err == nil {
		return
	}

	// Distinguish "wrong signature" from "the token hashed the input again":
	// if the signature verifies over SHA-256 of the digest we supplied, the
	// token applied the hash a second time.
	doubled := digestOf(crypto.SHA256, digest)
	if rsa.VerifyPSS(fx.rsa.rsaPub, crypto.SHA256, doubled, sig,
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}) == nil {
		t.Fatalf("CKM_RSA_PKCS_PSS signed SHA-256 of the digest it was given, not the digest: " +
			"the token applied the mechanism parameter's hash to input that PKCS#11 v3.2 " +
			"§6.1.15 defines as already hashed. Every signature this mechanism produces is " +
			"unverifiable by any peer")
	}
	t.Fatalf("crypto/rsa rejects the CKM_RSA_PKCS_PSS signature over the digest supplied, "+
		"and it is not a signature over the doubly-hashed digest either (signature %x)", sig)
}

// exerciseRSAPKCSDigest returns an exerciser for a combined
// CKM_SHA<n>_RSA_PKCS mechanism, which hashes inside the token.
func exerciseRSAPKCSDigest(h crypto.Hash, mech uint) exercise {
	return func(t *testing.T, tok *token, fx *fixtures) {
		message := []byte("combined rsa pkcs1v15 signature")
		sig := sign(t, tok, pkcs11.NewMechanism(mech, nil), fx.rsa.priv, message)
		if err := rsa.VerifyPKCS1v15(fx.rsa.rsaPub, h, digestOf(h, message), sig); err != nil {
			t.Fatalf("crypto/rsa rejects the %s signature: %v", mechName(mech), err)
		}
	}
}

// exerciseRSAPSSDigest returns an exerciser for a combined
// CKM_SHA<n>_RSA_PKCS_PSS mechanism.
func exerciseRSAPSSDigest(h crypto.Hash, mech, hashAlg, mgf uint) exercise {
	return func(t *testing.T, tok *token, fx *fixtures) {
		message := []byte("combined rsa pss signature")
		params := pkcs11.NewPSSParams(hashAlg, mgf, uint(h.Size()))
		sig := sign(t, tok, pkcs11.NewMechanism(mech, params), fx.rsa.priv, message)
		if err := rsa.VerifyPSS(fx.rsa.rsaPub, h, digestOf(h, message), sig,
			&rsa.PSSOptions{SaltLength: h.Size(), Hash: h}); err != nil {
			t.Fatalf("crypto/rsa rejects the %s signature: %v", mechName(mech), err)
		}
	}
}

// splitECDSASignature splits a PKCS#11 ECDSA signature into r and s.
//
// PKCS#11 v3.2 §6.3.6 defines the signature as the concatenation of r and s,
// each padded to the byte length of the curve order -- not the ASN.1 SEQUENCE
// that most software emits. A module that returns DER here is a well-known
// interoperability break, so the length is checked rather than sniffed.
func splitECDSASignature(t *testing.T, sig []byte, byteLen int) (*big.Int, *big.Int) {
	t.Helper()

	if len(sig) != 2*byteLen {
		t.Fatalf("ECDSA signature is %d bytes, want %d: PKCS#11 v3.2 §6.3.6 requires the raw "+
			"r||s concatenation, each padded to the curve order's byte length, not a DER SEQUENCE",
			len(sig), 2*byteLen)
	}
	return new(big.Int).SetBytes(sig[:byteLen]), new(big.Int).SetBytes(sig[byteLen:])
}

// exerciseECKeyPairGen generates a fresh P-256 key pair and proves the
// published point belongs to the retained private key.
func exerciseECKeyPairGen(t *testing.T, tok *token, fx *fixtures) {
	pair := generateEC(t, tok)

	if !pair.ecPub.Curve.IsOnCurve(pair.ecPub.X, pair.ecPub.Y) {
		t.Fatal("CKA_EC_POINT decodes to a point that is not on P-256")
	}

	digest := digestOf(crypto.SHA256, []byte("ec key pair generation"))
	sig := sign(t, tok, pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), pair.priv, digest)
	r, s := splitECDSASignature(t, sig, 32)
	if !ecdsa.Verify(pair.ecPub, digest, r, s) {
		t.Fatal("crypto/ecdsa rejects a signature made by the freshly generated private key " +
			"against the point the token published for it")
	}
}

// exerciseECDSABare signs a caller-supplied digest with CKM_ECDSA.
func exerciseECDSABare(t *testing.T, tok *token, fx *fixtures) {
	digest := digestOf(crypto.SHA256, []byte("bare ecdsa"))
	sig := sign(t, tok, pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), fx.ec.priv, digest)
	r, s := splitECDSASignature(t, sig, 32)
	if !ecdsa.Verify(fx.ec.ecPub, digest, r, s) {
		t.Fatal("crypto/ecdsa rejects the CKM_ECDSA signature")
	}
}

// exerciseECDSADigest returns an exerciser for a combined CKM_ECDSA_SHA<n>
// mechanism, which hashes inside the token.
func exerciseECDSADigest(h crypto.Hash, mech uint) exercise {
	return func(t *testing.T, tok *token, fx *fixtures) {
		message := []byte("combined ecdsa signature")
		sig := sign(t, tok, pkcs11.NewMechanism(mech, nil), fx.ec.priv, message)
		r, s := splitECDSASignature(t, sig, 32)
		if !ecdsa.Verify(fx.ec.ecPub, digestOf(h, message), r, s) {
			t.Fatalf("crypto/ecdsa rejects the %s signature", mechName(mech))
		}
	}
}

// exerciseEdwardsKeyPairGen generates an Ed25519 key pair and proves the
// published public key belongs to the retained private key.
func exerciseEdwardsKeyPairGen(t *testing.T, tok *token, fx *fixtures) {
	pair := generateEd25519(t, tok)

	message := []byte("edwards key pair generation")
	sig := sign(t, tok, pkcs11.NewMechanism(ckmEdDSA, nil), pair.priv, message)
	if !ed25519.Verify(pair.edPub, message, sig) {
		t.Fatal("crypto/ed25519 rejects a signature made by the freshly generated private key " +
			"against the public key the token published for it")
	}
}

// exerciseEdDSA signs with CKM_EDDSA and verifies with crypto/ed25519.
func exerciseEdDSA(t *testing.T, tok *token, fx *fixtures) {
	message := []byte("eddsa signature")
	sig := sign(t, tok, pkcs11.NewMechanism(ckmEdDSA, nil), fx.ed.priv, message)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("CKM_EDDSA signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(fx.ed.edPub, message, sig) {
		t.Fatal("crypto/ed25519 rejects the CKM_EDDSA signature")
	}
}

// exerciseECDH1Derive derives a shared secret on the token and recomputes it
// with crypto/ecdh from the other side of the exchange.
//
// Checking the derived bytes rather than merely that a key object appeared is
// what catches a derivation that returns a constant, or the wrong coordinate:
// both produce a perfectly usable key object that no peer can reproduce.
func exerciseECDH1Derive(t *testing.T, tok *token, fx *fixtures) {
	peerPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating the peer key: %v", err)
	}

	tokenPub, err := ecdh.P256().NewPublicKey(
		append([]byte{0x04}, append(
			leftPad(fx.ec.ecPub.X.Bytes(), 32), leftPad(fx.ec.ecPub.Y.Bytes(), 32)...)...))
	if err != nil {
		t.Fatalf("converting the token's public point for crypto/ecdh: %v", err)
	}
	sharedSecret, err := peerPriv.ECDH(tokenPub)
	if err != nil {
		t.Fatalf("crypto/ecdh could not compute the expected shared secret: %v", err)
	}
	peerPoint := peerPriv.PublicKey().Bytes()

	// CKD_NULL is the case PKCS#11 v3.2 §6.3.11 defines as producing "a raw
	// shared secret value without applying any key derivation function", and it
	// is the only CK_EC_KDF_TYPE whose output an outside implementation can
	// predict exactly. It is also what every peer that speaks plain ECDH asks
	// for, so a module that refuses it cannot complete a key agreement with
	// anything but itself.
	t.Run("CKD_NULL", func(t *testing.T) {
		derived := deriveECDH(t, tok, fx, pkcs11.CKD_NULL, peerPoint, uint(len(sharedSecret)))
		if !bytes.Equal(derived, sharedSecret) {
			t.Fatalf("CKM_ECDH1_DERIVE with CKD_NULL produced %x, but crypto/ecdh computes "+
				"%x for the same exchange", derived, sharedSecret)
		}
	})

	// CKD_SHA256_KDF runs the ANSI X9.63 KDF over that same shared secret, so
	// the oracle is the X9.63 construction applied to the crypto/ecdh result.
	t.Run("CKD_SHA256_KDF", func(t *testing.T) {
		derived := deriveECDH(t, tok, fx, ckdSHA256KDF, peerPoint, 32)
		expected := x963KDF(sha256.New, sharedSecret, nil, 32)
		if !bytes.Equal(derived, expected) {
			t.Fatalf("CKM_ECDH1_DERIVE with CKD_SHA256_KDF produced %x, but the ANSI X9.63 KDF "+
				"over the crypto/ecdh shared secret computes %x", derived, expected)
		}
	})
}

// ckdSHA256KDF is CKD_SHA256_KDF, which github.com/miekg/pkcs11 does not
// define.
const ckdSHA256KDF uint = 0x00000006

// deriveECDH runs C_DeriveKey and returns the derived key's value.
func deriveECDH(t *testing.T, tok *token, fx *fixtures, kdf uint, peerPoint []byte, length uint) []byte {
	t.Helper()

	params := pkcs11.NewECDH1DeriveParams(kdf, nil, peerPoint)
	derived, err := tok.ctx.DeriveKey(tok.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, params)},
		fx.ec.priv,
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, length),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, uniqueLabel("fips-ecdh")),
		})
	if err != nil {
		t.Fatalf("C_DeriveKey(CKM_ECDH1_DERIVE, kdf 0x%08X): %v", kdf, err)
	}
	return attribute(t, tok, derived, pkcs11.CKA_VALUE, "CKA_VALUE")
}

// x963KDF is the ANSI X9.63 key derivation function, used as the oracle for
// CKD_SHA256_KDF: K = H(Z || counter || SharedInfo) concatenated over an
// increasing 32-bit big-endian counter starting at 1.
func x963KDF(newHash func() hash.Hash, secret, sharedInfo []byte, length int) []byte {
	out := make([]byte, 0, length)
	counter := make([]byte, 4)
	for i := uint32(1); len(out) < length; i++ {
		binary.BigEndian.PutUint32(counter, i)
		h := newHash()
		h.Write(secret)
		h.Write(counter)
		h.Write(sharedInfo)
		out = h.Sum(out)
	}
	return out[:length]
}

// leftPad zero-extends b on the left to n bytes.
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// exerciseAESKeyGen generates an AES key on the token and proves the key
// material is real by encrypting with the token and decrypting with crypto/aes.
//
// The key is generated non-sensitive so its value can be read back; a sensitive
// key could only be checked against the token's own decryptor, which a module
// that generated an all-zero key would still pass.
func exerciseAESKeyGen(t *testing.T, tok *token, fx *fixtures) {
	handle := generateAESKey(t, tok, 32)

	value := attribute(t, tok, handle, pkcs11.CKA_VALUE, "CKA_VALUE")
	if len(value) != 32 {
		t.Fatalf("CKM_AES_KEY_GEN produced a %d-byte key, want the 32 requested through CKA_VALUE_LEN",
			len(value))
	}
	if bytes.Equal(value, make([]byte, 32)) {
		t.Fatal("CKM_AES_KEY_GEN produced an all-zero key")
	}

	// CBC rather than ECB, because this exerciser is about the key material,
	// not about a mode. CKM_AES_ECB has its own exerciser and its own verdict.
	iv := bytes.Repeat([]byte{0x77}, aes.BlockSize)
	plaintext := bytes.Repeat([]byte{0x5a}, 2*aes.BlockSize)
	ciphertext := encrypt(t, tok, pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, iv), handle, plaintext)

	block, err := aes.NewCipher(value)
	if err != nil {
		t.Fatalf("crypto/aes rejects the generated key: %v", err)
	}
	expected := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(expected, plaintext)
	if !bytes.Equal(ciphertext, expected) {
		t.Fatalf("the token encrypted with the generated key to %x, but crypto/aes computes %x "+
			"from the value the token published as CKA_VALUE", ciphertext, expected)
	}
}

// encrypt runs C_EncryptInit followed by C_Encrypt.
func encrypt(t *testing.T, tok *token, mech *pkcs11.Mechanism, key pkcs11.ObjectHandle, data []byte) []byte {
	t.Helper()

	if err := tok.ctx.EncryptInit(tok.session, []*pkcs11.Mechanism{mech}, key); err != nil {
		t.Fatalf("C_EncryptInit(0x%08X): %v", mech.Mechanism, err)
	}
	out, err := tok.ctx.Encrypt(tok.session, data)
	if err != nil {
		t.Fatalf("C_Encrypt(0x%08X): %v", mech.Mechanism, err)
	}
	return out
}

// exerciseAESECB encrypts one block on the token and recomputes it with
// crypto/aes using the key value this test chose.
func exerciseAESECB(t *testing.T, tok *token, fx *fixtures) {
	plaintext := bytes.Repeat([]byte{0xa5}, aes.BlockSize)
	ciphertext := encrypt(t, tok, pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil), fx.aesKey, plaintext)

	block, err := aes.NewCipher(fx.aesKeyValue)
	if err != nil {
		t.Fatalf("crypto/aes: %v", err)
	}
	expected := make([]byte, aes.BlockSize)
	block.Encrypt(expected, plaintext)
	if !bytes.Equal(ciphertext, expected) {
		t.Fatalf("CKM_AES_ECB produced %x, crypto/aes computes %x", ciphertext, expected)
	}
}

// exerciseAESCBC encrypts two blocks under a fixed IV and recomputes the
// ciphertext with crypto/cipher.
func exerciseAESCBC(t *testing.T, tok *token, fx *fixtures) {
	iv := bytes.Repeat([]byte{0x11}, aes.BlockSize)
	plaintext := bytes.Repeat([]byte{0x33}, 2*aes.BlockSize)

	ciphertext := encrypt(t, tok, pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, iv), fx.aesKey, plaintext)

	block, err := aes.NewCipher(fx.aesKeyValue)
	if err != nil {
		t.Fatalf("crypto/aes: %v", err)
	}
	expected := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(expected, plaintext)
	if !bytes.Equal(ciphertext, expected) {
		t.Fatalf("CKM_AES_CBC produced %x, crypto/cipher computes %x", ciphertext, expected)
	}
}

// exerciseAESCBCPad encrypts a plaintext that is not a block multiple and
// checks the result against crypto/cipher with the PKCS#7 padding PKCS#11
// v3.2 §6.10.6 prescribes.
func exerciseAESCBCPad(t *testing.T, tok *token, fx *fixtures) {
	iv := bytes.Repeat([]byte{0x22}, aes.BlockSize)
	plaintext := []byte("cbc pad payload of 21")

	ciphertext := encrypt(t, tok, pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv), fx.aesKey, plaintext)

	block, err := aes.NewCipher(fx.aesKeyValue)
	if err != nil {
		t.Fatalf("crypto/aes: %v", err)
	}
	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(append([]byte{}, plaintext...), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
	expected := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(expected, padded)
	if !bytes.Equal(ciphertext, expected) {
		t.Fatalf("CKM_AES_CBC_PAD produced %x, crypto/cipher with PKCS#7 padding computes %x",
			ciphertext, expected)
	}
}

// exerciseAESGCM encrypts with the token and opens the result with
// crypto/cipher, which checks both the ciphertext and the authentication tag.
func exerciseAESGCM(t *testing.T, tok *token, fx *fixtures) {
	nonce := bytes.Repeat([]byte{0x44}, 12)
	plaintext := []byte("gcm payload")

	block, err := aes.NewCipher(fx.aesKeyValue)
	if err != nil {
		t.Fatalf("crypto/aes: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("crypto/cipher: %v", err)
	}

	run := func(t *testing.T, aad []byte) {
		params := pkcs11.NewGCMParams(nonce, aad, 128)
		defer params.Free()

		ciphertext := encrypt(t, tok, pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params), fx.aesKey, plaintext)
		recovered, openErr := aead.Open(nil, nonce, ciphertext, aad)
		if openErr != nil {
			t.Fatalf("crypto/cipher cannot open the CKM_AES_GCM ciphertext: %v; the token must "+
				"emit ciphertext||tag over the nonce and additional authenticated data the "+
				"mechanism parameter carried", openErr)
		}
		if !bytes.Equal(recovered, plaintext) {
			t.Fatalf("CKM_AES_GCM round trip returned %q, want %q", recovered, plaintext)
		}
	}

	t.Run("no-AAD", func(t *testing.T) { run(t, nil) })

	// CK_GCM_PARAMS carries pAAD and ulAADLen (PKCS#11 v3.2 §6.13.5), and GCM's
	// whole reason to exist over CTR is that it authenticates that data. A token
	// that accepts the parameter but ignores or refuses the field gives an
	// application no way to bind a ciphertext to its context, and the loss is
	// silent at the call site that matters.
	t.Run("with-AAD", func(t *testing.T) { run(t, []byte("associated data")) })
}

// aesKeyWrapIV is the RFC 3394 §2.2.3.1 default initial value.
var aesKeyWrapIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// aesKeyUnwrap is an independent RFC 3394 key unwrap, used as the oracle for
// CKM_AES_KEY_WRAP. It returns the recovered plaintext and the integrity check
// register so a caller can decide what a mismatch means.
func aesKeyUnwrap(kek, wrapped []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, err
	}
	if len(wrapped) < 16 || len(wrapped)%8 != 0 {
		return nil, nil, &errWrapShape{length: len(wrapped)}
	}

	n := len(wrapped)/8 - 1
	a := append([]byte{}, wrapped[:8]...)
	r := append([]byte{}, wrapped[8:]...)
	buf := make([]byte, 16)

	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			round := uint64(n*j + i)
			copy(buf[:8], a)
			for k := 0; k < 8; k++ {
				buf[7-k] ^= byte(round >> (8 * k))
			}
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	return r, a, nil
}

// errWrapShape reports a wrapped blob whose length cannot be an RFC 3394
// result.
type errWrapShape struct {
	length int
}

func (e *errWrapShape) Error() string {
	return "wrapped key is " + itoa(e.length) + " bytes, which is not a multiple of 8 above 16 as RFC 3394 requires"
}

// itoa renders a small non-negative int without pulling in strconv for one call
// site inside an error type.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// exerciseAESKeyWrap wraps a key whose value this test knows and unwraps the
// result with an RFC 3394 implementation written here.
//
// Unwrapping with the token would prove only that the token is
// self-consistent; a wrap that emitted the key in the clear, or that used the
// wrong initial value, would round-trip perfectly and be rejected by every
// other RFC 3394 implementation in the world.
func exerciseAESKeyWrap(t *testing.T, tok *token, fx *fixtures) {
	targetHandle := generateAESKey(t, tok, 32)
	target := attribute(t, tok, targetHandle, pkcs11.CKA_VALUE, "CKA_VALUE")

	wrapped, err := tok.ctx.WrapKey(tok.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)},
		fx.aesKey, targetHandle)
	if err != nil {
		t.Fatalf("C_WrapKey(CKM_AES_KEY_WRAP): %v", err)
	}
	if bytes.Contains(wrapped, target) {
		t.Fatal("C_WrapKey(CKM_AES_KEY_WRAP) output contains the plaintext key material")
	}

	recovered, iv, err := aesKeyUnwrap(fx.aesKeyValue, wrapped)
	if err != nil {
		t.Fatalf("RFC 3394 unwrap of the token's output failed: %v", err)
	}
	if !bytes.Equal(iv, aesKeyWrapIV) {
		t.Fatalf("RFC 3394 integrity check register is %x, want the default IV %x: "+
			"the token wrapped with a different initial value", iv, aesKeyWrapIV)
	}
	if !bytes.Equal(recovered, target) {
		t.Fatalf("RFC 3394 unwrap recovered %x, want the wrapped key %x", recovered, target)
	}
}

// exerciseAESKeyWrapPad wraps a key with CKM_AES_KEY_WRAP_PAD and unwraps it
// with an RFC 5649 check, which uses the alternative initial value that carries
// the unpadded length.
func exerciseAESKeyWrapPad(t *testing.T, tok *token, fx *fixtures) {
	targetHandle := generateAESKey(t, tok, 24)
	target := attribute(t, tok, targetHandle, pkcs11.CKA_VALUE, "CKA_VALUE")

	wrapped, err := tok.ctx.WrapKey(tok.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)},
		fx.aesKey, targetHandle)
	if err != nil {
		t.Fatalf("C_WrapKey(CKM_AES_KEY_WRAP_PAD): %v", err)
	}
	if bytes.Contains(wrapped, target) {
		t.Fatal("C_WrapKey(CKM_AES_KEY_WRAP_PAD) output contains the plaintext key material")
	}

	recovered, aiv, err := aesKeyUnwrap(fx.aesKeyValue, wrapped)
	if err != nil {
		t.Fatalf("RFC 5649 unwrap of the token's output failed: %v", err)
	}
	wantAIV := []byte{0xA6, 0x59, 0x59, 0xA6, 0x00, 0x00, 0x00, byte(len(target))}
	if !bytes.Equal(aiv, wantAIV) {
		t.Fatalf("RFC 5649 alternative initial value is %x, want %x", aiv, wantAIV)
	}
	if !bytes.Equal(recovered[:len(target)], target) {
		t.Fatalf("RFC 5649 unwrap recovered %x, want the wrapped key %x", recovered[:len(target)], target)
	}
}

// exerciseDigest returns an exerciser that digests a message on the token and
// compares the result with the standard library.
func exerciseDigest(mech uint, newHash func() hash.Hash) exercise {
	return func(t *testing.T, tok *token, fx *fixtures) {
		message := []byte("the quick brown fox jumps over the lazy dog")

		if err := tok.ctx.DigestInit(tok.session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}); err != nil {
			t.Fatalf("C_DigestInit(%s): %v", mechName(mech), err)
		}
		got, err := tok.ctx.Digest(tok.session, message)
		if err != nil {
			t.Fatalf("C_Digest(%s): %v", mechName(mech), err)
		}

		h := newHash()
		h.Write(message)
		want := h.Sum(nil)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s produced %x, the standard library computes %x", mechName(mech), got, want)
		}
	}
}
