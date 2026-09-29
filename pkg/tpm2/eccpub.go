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
	"crypto/ecdsa"
	"errors"

	"github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecpoint"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// ErrECCPublicArea means the ECC public area of a TPM object would not yield
// a usable ECDSA public key: the parameters or unique field would not parse,
// the curve is unknown, or -- the case this exists for -- the point the TPM
// reported does not lie on that curve.
//
// A point that is not on the curve is not a formatting complaint. It means
// the device supplying the EK, SRK, IDevID, IAK or attested key is not
// producing valid ECC public areas, and the value must not become an
// attestation identity.
var ErrECCPublicArea = errors.New("tpm2: ECC public area does not yield a valid public key")

// eccPublicKey reconstructs the ECDSA public key described by a TPMT_PUBLIC
// ECC public area, validating that the reported point lies on the curve.
//
// TPM2B_ECC_PARAMETER buffers are not required to carry leading zero bytes,
// so a coordinate whose high byte is zero arrives short; ecpoint.PublicKey
// left-pads before parsing so such a key reconstructs rather than being
// rejected at random.
func eccPublicKey(pub *tpm2.TPMTPublic) (*ecdsa.PublicKey, error) {
	detail, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, &errs.Detail{Err: ErrECCPublicArea, Detail: err.Error()}
	}
	curve, err := detail.CurveID.Curve()
	if err != nil {
		return nil, &errs.Detail{Err: ErrECCPublicArea, Detail: err.Error()}
	}
	unique, err := pub.Unique.ECC()
	if err != nil {
		return nil, &errs.Detail{Err: ErrECCPublicArea, Detail: err.Error()}
	}
	key, err := ecpoint.PublicKey(curve, unique.X.Buffer, unique.Y.Buffer)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrECCPublicArea, Cause: err}
	}
	return key, nil
}

// packRawECDSASignature packs a TPM2_Certify or TPM2_CertifyCreation ECDSA
// signature as the raw r||s pair, each half left-padded to attester's curve
// field size.
//
// This is the wire format a TCG-CSR-IDEVID carries: sgnCertifyInfoSignature
// and atCertifyInfoSignature store the bare signature value with no algorithm
// alongside it (TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00
// r12 section 13.1), and [signatureFromScheme] recovers r and s from it by
// splitting the buffer exactly in half. TPM2B_ECC_PARAMETER buffers are not
// required to carry leading zero bytes, so r or s can arrive shorter than the
// field size; without padding here the two halves would not be the same
// length and a genuine signature would fail to parse back, or -- for a
// signature whose two halves happen to differ in leading-zero count by
// exactly the right amount -- silently split at the wrong point.
func packRawECDSASignature(attester *tpm2.TPMTPublic, r, s []byte) ([]byte, error) {
	detail, err := attester.Parameters.ECCDetail()
	if err != nil {
		return nil, &errs.Detail{Err: ErrECCPublicArea, Detail: err.Error()}
	}
	curve, err := detail.CurveID.Curve()
	if err != nil {
		return nil, &errs.Detail{Err: ErrECCPublicArea, Detail: err.Error()}
	}
	size := ecpoint.CoordinateSize(curve)
	if len(r) > size || len(s) > size {
		return nil, &errs.Detail{Err: ErrECCPublicArea, Detail: "ECDSA signature component wider than the curve field size"}
	}
	raw := make([]byte, 2*size)
	copy(raw[size-len(r):size], r)
	copy(raw[2*size-len(s):], s)
	return raw, nil
}
