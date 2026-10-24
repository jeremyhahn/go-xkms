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

package checkpoint

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512" // registers SHA-384 and SHA-512 for crypto.Hash.New
	"crypto/x509"
	"encoding/binary"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Built-in algorithm IDs. Ed25519 and ECDSA carry the signature type bytes
// signed-note §Signature types assigns them; every other built-in is a
// TypeExtended algorithm whose ID is its extended identifier.
const (
	// AlgorithmEd25519 is signature type 0x01: Ed25519 (RFC 8032) over the
	// note text (signed-note §Ed25519 signatures).
	AlgorithmEd25519 = "ed25519"

	// AlgorithmECDSA is signature type 0x02: ECDSA as implemented by
	// transparency-dev/witness, on NIST P-256, P-384 or P-521, over the
	// SHA-256 digest of the note text, with an ASN.1 DER signature. The
	// public key is the DER SubjectPublicKeyInfo and the key ID is the
	// truncated SHA-256 hash of it (signed-note §Signature types).
	AlgorithmECDSA = "ecdsa"

	// AlgorithmECDSAP224SHA256 is ECDSA on NIST P-224 over SHA-256, which
	// signature type 0x02 does not admit.
	AlgorithmECDSAP224SHA256 = "go-xkms/ecdsa-p224-sha256"
	// AlgorithmECDSAP384SHA384 is ECDSA on NIST P-384 over SHA-384, for a
	// key bound to that digest (cloud KMS P-384 keys are).
	AlgorithmECDSAP384SHA384 = "go-xkms/ecdsa-p384-sha384"
	// AlgorithmECDSAP521SHA512 is ECDSA on NIST P-521 over SHA-512, for a
	// key bound to that digest.
	AlgorithmECDSAP521SHA512 = "go-xkms/ecdsa-p521-sha512"

	// AlgorithmRSAPKCS1SHA256 is RSASSA-PKCS1-v1_5 with SHA-256.
	AlgorithmRSAPKCS1SHA256 = "go-xkms/rsa-pkcs1-sha256"
	// AlgorithmRSAPKCS1SHA384 is RSASSA-PKCS1-v1_5 with SHA-384.
	AlgorithmRSAPKCS1SHA384 = "go-xkms/rsa-pkcs1-sha384"
	// AlgorithmRSAPKCS1SHA512 is RSASSA-PKCS1-v1_5 with SHA-512.
	AlgorithmRSAPKCS1SHA512 = "go-xkms/rsa-pkcs1-sha512"
	// AlgorithmRSAPSSSHA256 is RSASSA-PSS with SHA-256 and a salt as long
	// as the digest.
	AlgorithmRSAPSSSHA256 = "go-xkms/rsa-pss-sha256"
	// AlgorithmRSAPSSSHA384 is RSASSA-PSS with SHA-384 and a salt as long
	// as the digest.
	AlgorithmRSAPSSSHA384 = "go-xkms/rsa-pss-sha384"
	// AlgorithmRSAPSSSHA512 is RSASSA-PSS with SHA-512 and a salt as long
	// as the digest.
	AlgorithmRSAPSSSHA512 = "go-xkms/rsa-pss-sha512"

	// AlgorithmMLDSA44 is pure ML-DSA-44 (FIPS 204) over the note text,
	// with an empty context. It is not signature type 0x06, which is the
	// timestamped checkpoint cosignature of c2sp.org/tlog-cosignature.
	AlgorithmMLDSA44 = "go-xkms/ml-dsa-44"
	// AlgorithmMLDSA65 is pure ML-DSA-65 (FIPS 204) over the note text.
	AlgorithmMLDSA65 = "go-xkms/ml-dsa-65"
	// AlgorithmMLDSA87 is pure ML-DSA-87 (FIPS 204) over the note text.
	AlgorithmMLDSA87 = "go-xkms/ml-dsa-87"
)

// minRSABits is the smallest RSA modulus the built-in RSA algorithms accept.
const minRSABits = 2048

// witnessCurves are the curves signature type 0x02 admits.
var witnessCurves = map[elliptic.Curve]bool{
	elliptic.P256(): true,
	elliptic.P384(): true,
	elliptic.P521(): true,
}

// builtinAlgorithms covers every signing key go-xkms offers: Ed25519,
// ECDSA on every NIST curve, RSA and ML-DSA.
var builtinAlgorithms = []Algorithm{
	{
		ID:              AlgorithmEd25519,
		Type:            0x01,
		SignerOpts:      crypto.Hash(0),
		EncodePublicKey: encodeEd25519,
		DecodePublicKey: decodeEd25519,
		Verify:          verifyEd25519,
	},
	{
		ID:              AlgorithmECDSA,
		Type:            0x02,
		SignerOpts:      crypto.SHA256,
		EncodePublicKey: ecdsaEncoder(witnessCurves),
		DecodePublicKey: ecdsaDecoder(witnessCurves),
		Verify:          ecdsaVerifier(crypto.SHA256),
		keyID:           spkiKeyID,
	},
	ecdsaAlgorithm(AlgorithmECDSAP224SHA256, elliptic.P224(), crypto.SHA256),
	ecdsaAlgorithm(AlgorithmECDSAP384SHA384, elliptic.P384(), crypto.SHA384),
	ecdsaAlgorithm(AlgorithmECDSAP521SHA512, elliptic.P521(), crypto.SHA512),
	rsaPKCS1Algorithm(AlgorithmRSAPKCS1SHA256, crypto.SHA256),
	rsaPKCS1Algorithm(AlgorithmRSAPKCS1SHA384, crypto.SHA384),
	rsaPKCS1Algorithm(AlgorithmRSAPKCS1SHA512, crypto.SHA512),
	rsaPSSAlgorithm(AlgorithmRSAPSSSHA256, crypto.SHA256),
	rsaPSSAlgorithm(AlgorithmRSAPSSSHA384, crypto.SHA384),
	rsaPSSAlgorithm(AlgorithmRSAPSSSHA512, crypto.SHA512),
	mldsaAlgorithm(AlgorithmMLDSA44, mldsa.MLDSA44()),
	mldsaAlgorithm(AlgorithmMLDSA65, mldsa.MLDSA65()),
	mldsaAlgorithm(AlgorithmMLDSA87, mldsa.MLDSA87()),
}

// digest returns the message the crypto.Signer signs for text: the text
// itself when h is zero, otherwise its h digest.
func digest(h crypto.Hash, text []byte) []byte {
	if h == 0 {
		return text
	}
	d := h.New()
	d.Write(text)
	return d.Sum(nil)
}

// spkiKeyID is the key ID of signature type 0x02: the truncated SHA-256
// hash of the DER SubjectPublicKeyInfo (signed-note §Signature types).
func spkiKeyID(_ string, _ []byte, material []byte) uint32 {
	sum := sha256.Sum256(material)
	return binary.BigEndian.Uint32(sum[:])
}

// encodeEd25519 encodes an Ed25519 key as its 32-byte RFC 8032 encoding
// (signed-note §Ed25519 signatures, §Verifier keys).
func encodeEd25519(pub crypto.PublicKey) ([]byte, error) {
	key, ok := pub.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, ErrUnsupportedKey
	}
	return append([]byte(nil), key...), nil
}

// decodeEd25519 parses a 32-byte RFC 8032 Ed25519 public key.
func decodeEd25519(material []byte) (crypto.PublicKey, error) {
	if len(material) != ed25519.PublicKeySize {
		return nil, &errs.Detail{Err: ErrMalformedVerifierKey, Detail: "Ed25519 public key must be 32 bytes"}
	}
	return ed25519.PublicKey(append([]byte(nil), material...)), nil
}

// verifyEd25519 verifies an RFC 8032 signature over the note text.
func verifyEd25519(pub crypto.PublicKey, text, sig []byte) bool {
	key, ok := pub.(ed25519.PublicKey)
	return ok && ed25519.Verify(key, text, sig)
}

// ecdsaAlgorithm builds a TypeExtended ECDSA algorithm on one curve over h.
func ecdsaAlgorithm(id string, curve elliptic.Curve, h crypto.Hash) Algorithm {
	curves := map[elliptic.Curve]bool{curve: true}
	return Algorithm{
		ID:              id,
		Type:            TypeExtended,
		SignerOpts:      h,
		EncodePublicKey: ecdsaEncoder(curves),
		DecodePublicKey: ecdsaDecoder(curves),
		Verify:          ecdsaVerifier(h),
	}
}

// ecdsaEncoder encodes an ECDSA key on one of curves as its DER
// SubjectPublicKeyInfo.
func ecdsaEncoder(curves map[elliptic.Curve]bool) func(crypto.PublicKey) ([]byte, error) {
	return func(pub crypto.PublicKey) ([]byte, error) {
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok || key == nil || !curves[key.Curve] {
			return nil, ErrUnsupportedKey
		}
		return x509.MarshalPKIXPublicKey(key)
	}
}

// ecdsaDecoder parses a DER SubjectPublicKeyInfo holding an ECDSA key on
// one of curves.
func ecdsaDecoder(curves map[elliptic.Curve]bool) func([]byte) (crypto.PublicKey, error) {
	return func(material []byte) (crypto.PublicKey, error) {
		parsed, err := x509.ParsePKIXPublicKey(material)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrMalformedVerifierKey, Detail: "ECDSA public key", Cause: err}
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok || !curves[key.Curve] {
			return nil, &errs.Detail{Err: ErrMalformedVerifierKey, Detail: "not an ECDSA key on an admitted curve"}
		}
		return key, nil
	}
}

// ecdsaVerifier verifies an ASN.1 DER ECDSA signature over the h digest of
// the note text.
func ecdsaVerifier(h crypto.Hash) func(crypto.PublicKey, []byte, []byte) bool {
	return func(pub crypto.PublicKey, text, sig []byte) bool {
		key, ok := pub.(*ecdsa.PublicKey)
		return ok && ecdsa.VerifyASN1(key, digest(h, text), sig)
	}
}

// rsaAlgorithm builds a TypeExtended RSA algorithm around a verify function.
func rsaAlgorithm(id string, opts crypto.SignerOpts, verify func(*rsa.PublicKey, []byte, []byte) error) Algorithm {
	return Algorithm{
		ID:              id,
		Type:            TypeExtended,
		SignerOpts:      opts,
		EncodePublicKey: encodeRSA,
		DecodePublicKey: decodeRSA,
		Verify: func(pub crypto.PublicKey, text, sig []byte) bool {
			key, ok := pub.(*rsa.PublicKey)
			return ok && verify(key, digest(opts.HashFunc(), text), sig) == nil
		},
	}
}

// rsaPKCS1Algorithm builds an RSASSA-PKCS1-v1_5 algorithm over h.
func rsaPKCS1Algorithm(id string, h crypto.Hash) Algorithm {
	return rsaAlgorithm(id, h, func(key *rsa.PublicKey, d, sig []byte) error {
		return rsa.VerifyPKCS1v15(key, h, d, sig)
	})
}

// rsaPSSAlgorithm builds an RSASSA-PSS algorithm over h with a salt as long
// as the digest.
func rsaPSSAlgorithm(id string, h crypto.Hash) Algorithm {
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
	return rsaAlgorithm(id, opts, func(key *rsa.PublicKey, d, sig []byte) error {
		return rsa.VerifyPSS(key, h, d, sig, opts)
	})
}

// encodeRSA encodes an RSA key of at least minRSABits as its DER
// SubjectPublicKeyInfo.
func encodeRSA(pub crypto.PublicKey) ([]byte, error) {
	key, ok := pub.(*rsa.PublicKey)
	if !ok || key == nil || key.N == nil || key.N.BitLen() < minRSABits {
		return nil, ErrUnsupportedKey
	}
	return x509.MarshalPKIXPublicKey(key)
}

// decodeRSA parses a DER SubjectPublicKeyInfo holding an RSA key of at
// least minRSABits.
func decodeRSA(material []byte) (crypto.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(material)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedVerifierKey, Detail: "RSA public key", Cause: err}
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < minRSABits {
		return nil, &errs.Detail{Err: ErrMalformedVerifierKey, Detail: "not an RSA key of at least 2048 bits"}
	}
	return key, nil
}

// mldsaConvertible is a go-xkms ML-DSA public key that is not a
// crypto/mldsa key itself, such as the software key provider's.
type mldsaConvertible interface {
	MLDSA() (*mldsa.PublicKey, error)
}

// mldsaAlgorithm builds a TypeExtended pure ML-DSA algorithm for params.
func mldsaAlgorithm(id string, params mldsa.Parameters) Algorithm {
	return Algorithm{
		ID:         id,
		Type:       TypeExtended,
		SignerOpts: crypto.Hash(0),
		EncodePublicKey: func(pub crypto.PublicKey) ([]byte, error) {
			key, err := mldsaKey(pub)
			if err != nil || key.Parameters() != params {
				return nil, ErrUnsupportedKey
			}
			return key.Bytes(), nil
		},
		DecodePublicKey: func(material []byte) (crypto.PublicKey, error) {
			key, err := mldsa.NewPublicKey(params, material)
			if err != nil {
				return nil, &errs.Joined{Lead: ErrMalformedVerifierKey, Detail: params.String() + " public key", Cause: err}
			}
			return key, nil
		},
		Verify: func(pub crypto.PublicKey, text, sig []byte) bool {
			key, ok := pub.(*mldsa.PublicKey)
			return ok && mldsa.Verify(key, text, sig, nil) == nil
		},
	}
}

// mldsaKey returns pub as a crypto/mldsa public key.
func mldsaKey(pub crypto.PublicKey) (*mldsa.PublicKey, error) {
	if key, ok := pub.(*mldsa.PublicKey); ok && key != nil {
		return key, nil
	}
	if key, ok := pub.(mldsaConvertible); ok {
		return key.MLDSA()
	}
	return nil, ErrUnsupportedKey
}
