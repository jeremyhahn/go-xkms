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
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"io"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/corim/corim"
	"github.com/veraison/go-cose"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

var (
	// ErrNilSigner reports a Sign call without a signer.
	ErrNilSigner = errors.New("refvalue: a signer is required to sign a CoRIM")

	// ErrNoSignerName reports an empty signer name; the CoRIM meta map
	// requires one.
	ErrNoSignerName = errors.New("refvalue: a signer name is required to sign a CoRIM")

	// ErrUnsupportedKey reports a signer whose key go-cose cannot sign with
	// under the requested algorithm.
	ErrUnsupportedKey = errors.New("refvalue: the signer's key cannot sign with the requested COSE algorithm")

	// ErrSign reports a COSE signing failure of the signer itself.
	ErrSign = errors.New("refvalue: signing the CoRIM failed")
)

// Sign wraps an unsigned CoRIM (its CBOR encoding) in a COSE_Sign1 message
// signed by signer under alg, with the CoRIM meta header naming signerName.
// The signer is only a crypto.Signer, so a hardware or backend key signs
// without its private part leaving the backend. The result verifies with
// VerifySigned under the signer's public key.
func Sign(ctx context.Context, unsigned []byte, signer crypto.Signer, alg cose.Algorithm, signerName string) ([]byte, error) {
	if signer == nil {
		return nil, ErrNilSigner
	}
	if signerName == "" {
		return nil, ErrNoSignerName
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// go-cose calls an opaque ECDSA signer with nil SignerOpts; a KMS signer
	// rejects that (AWS) or assumes SHA-256 (GCP), so the algorithm's hash is
	// named on every call.
	switch alg {
	case cose.AlgorithmES256:
		signer = hashedSigner{Signer: signer, hash: crypto.SHA256}
	case cose.AlgorithmES384:
		signer = hashedSigner{Signer: signer, hash: crypto.SHA384}
	case cose.AlgorithmES512:
		signer = hashedSigner{Signer: signer, hash: crypto.SHA512}
	}
	coseSigner, err := cose.NewSigner(alg, signer)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrUnsupportedKey, Cause: err}
	}

	// The whole input must be one well-formed CBOR item with bounded
	// container sizes before the corim decoder sees it: a bare tag head or a
	// huge declared map makes that decoder panic or allocate without bound.
	if err := wellformedMode.Wellformed(unsigned); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}
	var parsed corim.UnsignedCorim
	if err := parsed.FromCBOR(unsigned); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}
	if err := parsed.Valid(); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}
	// Valid only checks that each tag is nonempty: the embedded tags are
	// checked too, or a signed CoRIM could crash the appraisal that decodes it.
	if err := checkTags(parsed.Tags); err != nil {
		return nil, err
	}
	metaCBOR, err := corim.NewMeta().SetSigner(signerName, nil).ToCBOR()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrSign, Cause: err}
	}

	// The COSE payload is the caller's bytes, not a re-encoding: the corim
	// decoder drops fields it does not register, and a signature must never
	// cover a document that differs from the one submitted.
	msg := cose.NewSign1Message()
	msg.Payload = unsigned
	msg.Headers.Protected.SetAlgorithm(alg)
	msg.Headers.Protected[cose.HeaderLabelContentType] = corim.ContentType
	msg.Headers.Protected[corim.HeaderLabelCorimMeta] = metaCBOR
	if err := msg.Sign(rand.Reader, corim.NoExternalData, coseSigner); err != nil {
		return nil, &errs.Joined{Lead: ErrSign, Cause: err}
	}
	out, err := msg.MarshalCBOR()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrSign, Cause: err}
	}
	return out, nil
}

// maxCBORItems bounds every array and map in a CoRIM submitted for signing.
const maxCBORItems = 1 << 16

// wellformedMode checks CoRIM input for well-formedness with bounded
// container sizes and nesting.
var wellformedMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		MaxArrayElements: maxCBORItems,
		MaxMapPairs:      maxCBORItems,
		MaxNestedLevels:  32,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

// hashedSigner passes hash as the SignerOpts of every Sign, whatever its
// caller gave.
type hashedSigner struct {
	crypto.Signer
	hash crypto.Hash
}

// Sign signs digest with the hash the COSE algorithm names.
func (h hashedSigner) Sign(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return h.Signer.Sign(rand, digest, h.hash)
}
