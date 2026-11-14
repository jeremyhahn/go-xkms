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
	"errors"

	"github.com/veraison/corim/corim"
	"github.com/veraison/go-cose"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

var (
	// ErrNilSigner reports a Sign call without a signer.
	ErrNilSigner = errors.New("refvalue: a signer is required to sign a CoRIM")

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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	coseSigner, err := cose.NewSigner(alg, signer)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrUnsupportedKey, Cause: err}
	}

	var signed corim.SignedCorim
	if err := signed.UnsignedCorim.FromCBOR(unsigned); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}
	signed.Meta = *corim.NewMeta().SetSigner(signerName, nil)

	out, err := signed.Sign(coseSigner)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrSign, Cause: err}
	}
	return out, nil
}
