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
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// This file implements the IDevID/IAK key authorization model specified by
// TCG "TPM 2.0 Keys for Device Identity and Attestation", Version 1.00,
// Revision 12 (2021-10-08), section 7.3 "Recoverable IDevID/IAK Keys". The
// specification is checked in at
// docs/references/TCG-TPM-2.0-Keys-for-Device-Identity-and-Attestation-v1.00-r12.pdf
// and every digest below is pinned against the values the specification
// publishes in Tables 14 through 19 (devid_policy_test.go).
//
// The model, from section 7.2.4:
//
//	The recommended key templates enable the IDevID/IAK key's authValue
//	password to authorize USE of the key but not ADMINISTRATION of the key.
//	userWithAuth == SET enables the USER role via authValue, but
//	adminWithPolicy == SET disables the ADMIN role with authValue.
//
// So the authValue signs; only a policy administers. The policy attached to
// the key (section 7.3.6.6, "IDevID/IAK Key Policy") is a TPM2_PolicyOR of
// four branches:
//
//  1. PolicyUser               - TPM2_PolicySecret(endorsementAuth): the
//                                Privacy Administrator may USE the key.
//  2. PolicyCertify            - PolicyUser then
//                                TPM2_PolicyCommandCode(TPM_CC_Certify): the
//                                Privacy Administrator may certify the key.
//  3. PolicyActivateCredential - PolicyUser then
//                                TPM2_PolicyCommandCode(TPM_CC_ActivateCredential).
//  4. PolicyDelegationNV       - TPM2_PolicyAuthorizeNV(Policy NV Index): the
//                                Privacy Administrator delegates USE to the
//                                device owner by writing a Delegation Policy
//                                into a reserved NV index (section 7.3.5).
//
// Branches 1-3 depend only on the hash algorithm. Branch 4 depends on the
// Name of the Policy NV Index, which is itself deterministic (section 7.3.6.5)
// because the index's public area is fixed by the specification. Every value
// here is therefore computable offline, without a TPM, and is computed through
// go-tpm's trial-policy calculator so that the arithmetic is the library's
// implementation of PolicyUpdate rather than a private one.

// DevIDKeyKind selects between the two key types the specification defines,
// which differ only in the NV index that carries their Delegation Policy.
type DevIDKeyKind uint8

const (
	// DevIDKeySigning is the IDevID: an Unrestricted signing key
	// (section 7.3.4.1, "DevID (signing): Restricted = 0").
	DevIDKeySigning DevIDKeyKind = iota + 1

	// DevIDKeyAttestation is the IAK: a Restricted signing key
	// (section 7.3.4.1, "AK: Restricted = 1").
	DevIDKeyAttestation
)

// String returns the specification's name for the key kind.
func (k DevIDKeyKind) String() string {
	switch k {
	case DevIDKeySigning:
		return "IDevID"
	case DevIDKeyAttestation:
		return "IAK"
	default:
		return fmt.Sprintf("DevIDKeyKind(%d)", uint8(k))
	}
}

// Policy NV Indices for Recoverable Keys (section 7.3.2). One index is
// reserved per key kind per hash algorithm.
const (
	devidPolicyIndexDS1 tpm2.TPMHandle = 0x01C90010 // IDevID, SHA256
	devidPolicyIndexDS2 tpm2.TPMHandle = 0x01C90011 // IDevID, SHA384
	devidPolicyIndexDS3 tpm2.TPMHandle = 0x01C90012 // IDevID, SHA512
	devidPolicyIndexDA1 tpm2.TPMHandle = 0x01C90018 // IAK, SHA256
	devidPolicyIndexDA2 tpm2.TPMHandle = 0x01C90019 // IAK, SHA384
	devidPolicyIndexDA3 tpm2.TPMHandle = 0x01C9001A // IAK, SHA512
)

// devidPolicyNVAttributes is TPMA_NV 0x220F1008, NV Policy Template I-0
// (section 7.3.5.1): writable only through the index's own policy, readable
// by everyone, written all at once, DA-exempt. TPMA_NV_WRITTEN is part of the
// value because the specification computes the index Name over the WRITTEN
// state (section 7.3.6.5); the TPM sets that bit itself on the first write.
var devidPolicyNVAttributes = tpm2.TPMANV{
	PolicyWrite: true,
	WriteAll:    true,
	PPRead:      true,
	OwnerRead:   true,
	AuthRead:    true,
	PolicyRead:  true,
	NoDA:        true,
	Written:     true,
	NT:          tpm2.TPMNTOrdinary,
}

// DevIDPolicyNVIndex returns the reserved NV index that carries the
// Delegation Policy for a key of the given kind and hash algorithm
// (section 7.3.2).
func DevIDPolicyNVIndex(kind DevIDKeyKind, nameAlg tpm2.TPMAlgID) (tpm2.TPMHandle, error) {
	switch kind {
	case DevIDKeySigning:
		switch nameAlg {
		case tpm2.TPMAlgSHA256:
			return devidPolicyIndexDS1, nil
		case tpm2.TPMAlgSHA384:
			return devidPolicyIndexDS2, nil
		case tpm2.TPMAlgSHA512:
			return devidPolicyIndexDS3, nil
		}
	case DevIDKeyAttestation:
		switch nameAlg {
		case tpm2.TPMAlgSHA256:
			return devidPolicyIndexDA1, nil
		case tpm2.TPMAlgSHA384:
			return devidPolicyIndexDA2, nil
		case tpm2.TPMAlgSHA512:
			return devidPolicyIndexDA3, nil
		}
	}
	return 0, &errs.Detail{Err: ErrDevIDPolicyUnsupported,
		Detail: fmt.Sprintf("kind=%s nameAlg=0x%04x", kind, uint16(nameAlg))}
}

// DevIDPolicyNVPublic returns the public area of the Policy NV Index for a
// key of the given kind and hash algorithm: NV Policy Templates I-1 through
// I-3 (sections 7.3.5.2-7.3.5.4). The index's own authPolicy is PolicyUser,
// so only the Privacy Administrator can write the Delegation Policy. Its
// dataSize is 0x0022, 0x0032 or 0x0042 (section 7.3.6.5): the payload is a
// TPMT_HA -- a two-byte hash algorithm ID followed by the Delegation Policy
// digest -- which is why Table 20's example policies are shown "with leading
// HASH ID". A Name computed over a bare-digest dataSize does not match the
// specification's Table 18, and neither then does anything derived from it.
func DevIDPolicyNVPublic(kind DevIDKeyKind, nameAlg tpm2.TPMAlgID) (tpm2.TPMSNVPublic, error) {
	index, err := DevIDPolicyNVIndex(kind, nameAlg)
	if err != nil {
		return tpm2.TPMSNVPublic{}, err
	}
	userPolicy, err := DevIDPolicyUserDigest(nameAlg)
	if err != nil {
		return tpm2.TPMSNVPublic{}, err
	}
	size, err := devidPolicyNVDataSize(nameAlg)
	if err != nil {
		return tpm2.TPMSNVPublic{}, err
	}
	return tpm2.TPMSNVPublic{
		NVIndex:    index,
		NameAlg:    nameAlg,
		Attributes: devidPolicyNVAttributes,
		AuthPolicy: tpm2.TPM2BDigest{Buffer: userPolicy},
		DataSize:   size,
	}, nil
}

// DevIDPolicyNVName returns the Name of the Policy NV Index for a key of the
// given kind and hash algorithm (section 7.3.6.5, Table 18). The Name is what
// TPM2_PolicyAuthorizeNV extends into a policy session, which is why it must
// be reproducible without consulting the TPM.
func DevIDPolicyNVName(kind DevIDKeyKind, nameAlg tpm2.TPMAlgID) (tpm2.TPM2BName, error) {
	public, err := DevIDPolicyNVPublic(kind, nameAlg)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	name, err := tpm2.NVName(&public)
	if err != nil {
		return tpm2.TPM2BName{}, &errs.Detail{Err: ErrDevIDPolicyDigestCompute, Detail: fmt.Sprintf("NV Name: %v", err)}
	}
	return *name, nil
}

// DevIDPolicyUserDigest computes PolicyUser (section 7.3.6.1, Table 14): a
// single TPM2_PolicySecret whose authorizing entity is the Endorsement
// Hierarchy. This is the policy the Privacy Administrator satisfies with
// endorsementAuth.
func DevIDPolicyUserDigest(nameAlg tpm2.TPMAlgID) ([]byte, error) {
	calc, err := devidPolicyCalculator(nameAlg)
	if err != nil {
		return nil, err
	}
	if err := devidPolicySecretEH().Update(calc); err != nil {
		return nil, &errs.Detail{Err: ErrDevIDPolicyDigestCompute, Detail: fmt.Sprintf("PolicySecret trial: %v", err)}
	}
	return calc.Hash().Digest, nil
}

// DevIDPolicyCertifyDigest computes PolicyCertify (section 7.3.6.2,
// Table 15): PolicyUser extended by TPM2_PolicyCommandCode(TPM_CC_Certify).
// It authorizes the ADMIN role for exactly one command, which is what lets the
// Privacy Administrator certify the key without being able to do anything
// else to it.
func DevIDPolicyCertifyDigest(nameAlg tpm2.TPMAlgID) ([]byte, error) {
	return devidPolicyCommandDigest(nameAlg, tpm2.TPMCCCertify)
}

// DevIDPolicyActivateCredentialDigest computes PolicyActivateCredential
// (section 7.3.6.3, Table 16): PolicyUser extended by
// TPM2_PolicyCommandCode(TPM_CC_ActivateCredential).
func DevIDPolicyActivateCredentialDigest(nameAlg tpm2.TPMAlgID) ([]byte, error) {
	return devidPolicyCommandDigest(nameAlg, tpm2.TPMCCActivateCredential)
}

// DevIDPolicyDelegationNVDigest computes PolicyDelegationNV (section 7.3.6.4,
// Table 17): TPM2_PolicyAuthorizeNV over the Name of the key kind's Policy NV
// Index, starting from the zero digest. A session reaches this digest by
// first satisfying whatever Delegation Policy the index holds and then
// executing TPM2_PolicyAuthorizeNV against the index.
func DevIDPolicyDelegationNVDigest(kind DevIDKeyKind, nameAlg tpm2.TPMAlgID) ([]byte, error) {
	index, err := DevIDPolicyNVIndex(kind, nameAlg)
	if err != nil {
		return nil, err
	}
	name, err := DevIDPolicyNVName(kind, nameAlg)
	if err != nil {
		return nil, err
	}
	calc, err := devidPolicyCalculator(nameAlg)
	if err != nil {
		return nil, err
	}
	cmd := tpm2.PolicyAuthorizeNV{
		NVIndex: tpm2.NamedHandle{Handle: index, Name: name},
	}
	if err := cmd.Update(calc); err != nil {
		return nil, &errs.Detail{Err: ErrDevIDPolicyDigestCompute, Detail: fmt.Sprintf("PolicyAuthorizeNV trial: %v", err)}
	}
	return calc.Hash().Digest, nil
}

// DevIDKeyPolicyBranches returns the four constituent digests of the
// IDevID/IAK Key Policy in the order the specification lists them
// (section 7.3.6.6): PolicyUser, PolicyCertify, PolicyActivateCredential,
// PolicyDelegationNV. A policy session must present them in this order to
// TPM2_PolicyOR.
func DevIDKeyPolicyBranches(kind DevIDKeyKind, nameAlg tpm2.TPMAlgID) (tpm2.TPMLDigest, error) {
	user, err := DevIDPolicyUserDigest(nameAlg)
	if err != nil {
		return tpm2.TPMLDigest{}, err
	}
	certify, err := DevIDPolicyCertifyDigest(nameAlg)
	if err != nil {
		return tpm2.TPMLDigest{}, err
	}
	activate, err := DevIDPolicyActivateCredentialDigest(nameAlg)
	if err != nil {
		return tpm2.TPMLDigest{}, err
	}
	delegation, err := DevIDPolicyDelegationNVDigest(kind, nameAlg)
	if err != nil {
		return tpm2.TPMLDigest{}, err
	}
	return tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{
		{Buffer: user},
		{Buffer: certify},
		{Buffer: activate},
		{Buffer: delegation},
	}}, nil
}

// DevIDKeyPolicyDigest computes the IDevID/IAK Key Policy (section 7.3.6.6,
// Table 19): TPM2_PolicyOR over the four branches. This is the value assigned
// to the key template's authPolicy, and the value a policy session must reach
// before the TPM will honour it for the ADMIN role.
func DevIDKeyPolicyDigest(kind DevIDKeyKind, nameAlg tpm2.TPMAlgID) ([]byte, error) {
	branches, err := DevIDKeyPolicyBranches(kind, nameAlg)
	if err != nil {
		return nil, err
	}
	calc, err := devidPolicyCalculator(nameAlg)
	if err != nil {
		return nil, err
	}
	cmd := tpm2.PolicyOr{PHashList: branches}
	if err := cmd.Update(calc); err != nil {
		return nil, &errs.Detail{Err: ErrDevIDPolicyDigestCompute, Detail: fmt.Sprintf("PolicyOR trial: %v", err)}
	}
	return calc.Hash().Digest, nil
}

// devidPolicySecretEH is the TPM2_PolicySecret statement every branch of the
// key policy starts from, with the Endorsement Hierarchy as the authorizing
// entity and an empty policyRef (section 7.3.6.1). In trial mode go-tpm hashes
// the handle's Name, which for a permanent handle is the handle value itself,
// 0x4000000B.
func devidPolicySecretEH() tpm2.PolicySecret {
	return tpm2.PolicySecret{
		AuthHandle: tpm2.TPMRHEndorsement,
	}
}

// devidPolicyCommandDigest computes PolicyUser extended by
// TPM2_PolicyCommandCode(code) in one calculator, since the command-code
// statement extends the PolicySecret digest rather than starting fresh
// (section 7.3.6.2: "Where policyDigest_old is the Policy EH").
func devidPolicyCommandDigest(nameAlg tpm2.TPMAlgID, code tpm2.TPMCC) ([]byte, error) {
	calc, err := devidPolicyCalculator(nameAlg)
	if err != nil {
		return nil, err
	}
	if err := devidPolicySecretEH().Update(calc); err != nil {
		return nil, &errs.Detail{Err: ErrDevIDPolicyDigestCompute, Detail: fmt.Sprintf("PolicySecret trial: %v", err)}
	}
	cmd := tpm2.PolicyCommandCode{Code: code}
	if err := cmd.Update(calc); err != nil {
		return nil, &errs.Detail{Err: ErrDevIDPolicyDigestCompute, Detail: fmt.Sprintf("PolicyCommandCode trial: %v", err)}
	}
	return calc.Hash().Digest, nil
}

// devidPolicyCalculator returns a trial-policy calculator for the hash
// algorithm, refusing algorithms the specification does not define templates
// for rather than computing a digest nothing can be checked against.
func devidPolicyCalculator(nameAlg tpm2.TPMAlgID) (*tpm2.PolicyCalculator, error) {
	if _, err := devidDigestSize(nameAlg); err != nil {
		return nil, err
	}
	calc, err := tpm2.NewPolicyCalculator(nameAlg)
	if err != nil {
		return nil, &errs.Detail{Err: ErrDevIDPolicyDigestCompute, Detail: fmt.Sprintf("%v", err)}
	}
	return calc, nil
}

// devidPolicyNVDataSize returns the Policy NV Index dataSize for a nameAlg
// (section 7.3.6.5): the size of a TPMT_HA holding one digest in that
// algorithm, i.e. two bytes of algorithm ID plus the digest.
func devidPolicyNVDataSize(nameAlg tpm2.TPMAlgID) (uint16, error) {
	size, err := devidDigestSize(nameAlg)
	if err != nil {
		return 0, err
	}
	return 2 + size, nil
}

// devidDigestSize returns the digest size for each nameAlg the
// specification defines templates for (sections 7.3.5.2-7.3.5.4).
func devidDigestSize(nameAlg tpm2.TPMAlgID) (uint16, error) {
	switch nameAlg {
	case tpm2.TPMAlgSHA256:
		return 32, nil
	case tpm2.TPMAlgSHA384:
		return 48, nil
	case tpm2.TPMAlgSHA512:
		return 64, nil
	default:
		return 0, &errs.Detail{Err: ErrDevIDPolicyUnsupported,
			Detail: fmt.Sprintf("nameAlg=0x%04x; the specification defines templates for SHA256, SHA384 and SHA512", uint16(nameAlg))}
	}
}
