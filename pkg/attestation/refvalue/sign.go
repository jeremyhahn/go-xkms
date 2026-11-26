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

package refvalue

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/corim/corim"
	cose "github.com/veraison/go-cose"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// tagUnsignedCorim is the CBOR tag of a tagged-unsigned-corim-map,
// draft-ietf-rats-corim-11 §4.1.
const tagUnsignedCorim = 501

// minRSABits is the smallest RSA modulus COSE accepts, RFC 8230 §6.1.
const minRSABits = 2048

// Meta is the corim-meta-map of a signed CoRIM, draft-ietf-rats-corim-11
// §4.2.3: the signer (§4.2.3.1) and an optional signature validity (§7.3).
type Meta struct {
	// SignerName is the signer-name of the organization that signs the
	// CoRIM. It is required.
	SignerName string
	// SignerURI is the optional signer-uri identifying the same
	// organization.
	SignerURI string
	// NotBefore and NotAfter bound the signature validity. A zero NotAfter
	// omits the validity; NotBefore is optional within it and an error
	// without it.
	NotBefore, NotAfter time.Time
}

// ecdsaAlgorithms maps an ECDSA curve to its COSE algorithm, RFC 9053 §2.1.
var ecdsaAlgorithms = map[elliptic.Curve]cose.Algorithm{
	elliptic.P256(): cose.AlgorithmES256,
	elliptic.P384(): cose.AlgorithmES384,
	elliptic.P521(): cose.AlgorithmES512,
}

// Sign wraps an unsigned CoRIM in the COSE_Sign1 signed-corim of
// draft-ietf-rats-corim-11 §4.2, signed directly: the protected header
// (§4.2.1) carries alg, the content type application/rim+cbor and meta
// as corim-meta, and the payload is the tagged-unsigned-corim-map (#6.501).
// unsigned is the CBOR unsigned-corim-map, tagged or not. The algorithm
// follows the signer's key: ES256, ES384 or ES512 for ECDSA P-256, P-384 or
// P-521, PS256, PS384 or PS512 for RSA by modulus size, and EdDSA for
// Ed25519, the algorithms VerifySigned accepts. The result verifies with
// VerifySigned under the signer's public key.
func Sign(unsigned []byte, meta Meta, signer crypto.Signer) ([]byte, error) {
	if signer == nil {
		return nil, ErrSignerKey
	}
	alg, err := signatureAlgorithm(signer.Public())
	if err != nil {
		return nil, err
	}
	payload, err := taggedUnsignedCorim(unsigned)
	if err != nil {
		return nil, err
	}
	metaCBOR, err := encodeMeta(meta)
	if err != nil {
		return nil, err
	}
	coseSigner, err := cose.NewSigner(alg, signer)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrSignerKey, Cause: err}
	}

	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(alg)
	msg.Headers.Protected[cose.HeaderLabelContentType] = corim.ContentType
	msg.Headers.Protected[corim.HeaderLabelCorimMeta] = metaCBOR
	if err := msg.Sign(rand.Reader, nil, coseSigner); err != nil {
		return nil, &errs.Joined{Lead: ErrSign, Cause: err}
	}
	out, err := msg.MarshalCBOR()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrSign, Cause: err}
	}
	return out, nil
}

// signatureAlgorithm picks the COSE algorithm for a signer's public key.
func signatureAlgorithm(pub crypto.PublicKey) (cose.Algorithm, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if alg, ok := ecdsaAlgorithms[k.Curve]; ok {
			return alg, nil
		}
	case *rsa.PublicKey:
		return rsaAlgorithm(k.N.BitLen())
	case ed25519.PublicKey:
		return cose.AlgorithmEdDSA, nil
	}
	return 0, ErrSignerKey
}

// rsaAlgorithm matches the RSASSA-PSS hash to the modulus strength, RFC 8230
// §2: SHA-256 below 3072 bits, SHA-384 below 4096 and SHA-512 above.
func rsaAlgorithm(bits int) (cose.Algorithm, error) {
	switch {
	case bits < minRSABits:
		return 0, ErrSignerKey
	case bits < 3072:
		return cose.AlgorithmPS256, nil
	case bits < 4096:
		return cose.AlgorithmPS384, nil
	default:
		return cose.AlgorithmPS512, nil
	}
}

// taggedUnsignedCorim validates an unsigned CoRIM and encodes it as the
// tagged-unsigned-corim-map payload of §4.2.
func taggedUnsignedCorim(unsigned []byte) ([]byte, error) {
	var tag cbor.RawTag
	if err := cbor.Unmarshal(unsigned, &tag); err == nil {
		if tag.Number != tagUnsignedCorim {
			return nil, ErrMalformed
		}
		unsigned = tag.Content
	}
	var u corim.UnsignedCorim
	if err := u.FromCBOR(unsigned); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}
	if err := u.Valid(); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}
	content, err := u.ToCBOR()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}
	payload, err := cbor.Marshal(cbor.RawTag{Number: tagUnsignedCorim, Content: content})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}
	return payload, nil
}

// encodeMeta validates meta and encodes it as a corim-meta-map, §4.2.3.
func encodeMeta(meta Meta) ([]byte, error) {
	// A validity-map always states not-after, §7.3.
	if meta.NotAfter.IsZero() && !meta.NotBefore.IsZero() {
		return nil, ErrMeta
	}
	m := corim.NewMeta()
	var uri *string
	if meta.SignerURI != "" {
		uri = &meta.SignerURI
	}
	m = m.SetSigner(meta.SignerName, uri)
	if m != nil && !meta.NotAfter.IsZero() {
		var notBefore *time.Time
		if !meta.NotBefore.IsZero() {
			notBefore = &meta.NotBefore
		}
		m = m.SetValidity(meta.NotAfter, notBefore)
	}
	if m == nil {
		return nil, ErrMeta
	}
	if err := m.Valid(); err != nil {
		return nil, &errs.Joined{Lead: ErrMeta, Cause: err}
	}
	out, err := m.ToCBOR()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrMeta, Cause: err}
	}
	return out, nil
}
