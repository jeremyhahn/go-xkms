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
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// The policy authority of a scope is an ordinary ECDSA signing child key made
// with CreateECDSA. These functions are the two things the authorized-policy
// flow needs of it beyond an ordinary key: its Name and public area, which
// every policy index and approval refers to, and a signature in the
// TPMT_SIGNATURE form TPM2_VerifySignature takes.

// AuthorityName returns the Name and public area of the authority key
// described by authority, read from its saved public blob. backend may be
// nil, in which case the platform backend is used.
func (tpm *TPM2) AuthorityName(
	authority *types.KeyAttributes,
	backend store.KeyBackend) (tpm2.TPM2BName, tpm2.TPM2BPublic, error) {

	if authority == nil {
		return tpm2.TPM2BName{}, tpm2.TPM2BPublic{}, store.ErrInvalidKeyAttributes
	}
	if backend == nil {
		backend = tpm.backend
	}
	if backend == nil {
		return tpm2.TPM2BName{}, tpm2.TPM2BPublic{}, ErrNoStorageBackend
	}
	blob, err := backend.Get(authority, store.FSEXT_PUBLIC_BLOB)
	if err != nil {
		return tpm2.TPM2BName{}, tpm2.TPM2BPublic{}, err
	}
	public := tpm2.BytesAs2B[tpm2.TPMTPublic](blob)
	pub, err := public.Contents()
	if err != nil {
		return tpm2.TPM2BName{}, tpm2.TPM2BPublic{}, err
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return tpm2.TPM2BName{}, tpm2.TPM2BPublic{}, err
	}
	return *name, public, nil
}

// SignApproval signs aHash (see ApprovalDigest) with the ECDSA authority key
// described by authority and returns the signature as a TPMT_SIGNATURE, the
// form TPM2_VerifySignature takes. The key is loaded and authorized exactly
// as Sign does it. backend may be nil, in which case the platform backend is
// used.
func (tpm *TPM2) SignApproval(
	authority *types.KeyAttributes,
	backend store.KeyBackend,
	aHash []byte) (*tpm2.TPMTSignature, error) {

	hashAlg, ok := schemeHashByDigestSize[len(aHash)]
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidAuthoritySignature, Detail: fmt.Sprintf("no hash has a %d byte digest", len(aHash))}
	}
	_, public, err := tpm.AuthorityName(authority, backend)
	if err != nil {
		return nil, err
	}
	pub, err := public.Contents()
	if err != nil {
		return nil, err
	}
	if pub.Type != tpm2.TPMAlgECC {
		return nil, &errs.Detail{Err: ErrInvalidAuthoritySignature, Detail: "the authority is not an ECC key"}
	}
	eccPub, err := eccPublicKey(pub)
	if err != nil {
		return nil, err
	}

	der, err := tpm.Sign(nil, aHash, &store.SignerOpts{KeyAttributes: authority, Backend: backend})
	if err != nil {
		return nil, err
	}
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
		return nil, &errs.Detail{Err: ErrInvalidAuthoritySignature, Detail: "malformed ECDSA signature"}
	}

	size := (eccPub.Curve.Params().BitSize + 7) / 8
	return &tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       hashAlg,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: sig.R.FillBytes(make([]byte, size))},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: sig.S.FillBytes(make([]byte, size))},
		}),
	}, nil
}

// verifyApproval checks signature over aHash against the authority whose
// public area is authority, and returns the TPMT_TK_VERIFIED ticket that
// TPM2_PolicyAuthorize redeems, together with the authority's Name as the TPM
// computed it.
//
// The public area is loaded into the owner hierarchy rather than the NULL
// hierarchy: TPM2_VerifySignature issues a NULL ticket for a key in the NULL
// hierarchy, and TPM2_PolicyAuthorize refuses a NULL ticket.
func (tpm *TPM2) verifyApproval(
	authority tpm2.TPM2BPublic,
	aHash []byte,
	signature tpm2.TPMTSignature) (*tpm2.TPMTTKVerified, tpm2.TPM2BName, error) {

	loaded, err := tpm2.LoadExternal{
		InPublic:  authority,
		Hierarchy: tpm2.TPMRHOwner,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, tpm2.TPM2BName{}, err
	}
	defer tpm.Flush(loaded.ObjectHandle)

	verified, err := tpm2.VerifySignature{
		KeyHandle: tpm2.NamedHandle{Handle: loaded.ObjectHandle, Name: loaded.Name},
		Digest:    tpm2.TPM2BDigest{Buffer: aHash},
		Signature: signature,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, tpm2.TPM2BName{}, err
	}
	return &verified.Validation, loaded.Name, nil
}
