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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// This file implements Delegated Usage of a Recoverable IDevID/IAK Key,
// TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12,
// sections 7.2.2, 7.2.4, 7.3 and 7.3.5. devid_policy.go computes the digests;
// this file drives the TPM.
//
// The model: the key's authPolicy (section 7.3.6.6) has a PolicyDelegationNV
// branch, TPM2_PolicyAuthorizeNV over the Name of a reserved Policy NV Index
// (section 7.3.2). The index is defined by the device Owner "using Owner
// Authorization" (section 7.3.5) to NV Policy Template I-0 and is writable
// only under its own authPolicy, PolicyUser = PolicySecret(TPM_RH_ENDORSEMENT)
// -- so only the Privacy Administrator can choose what it holds. What it holds
// is a Delegation Policy: a TPMT_HA (section 7.3.5 NOTE: "The first two bytes
// of the Index data area contain a TPM_ALG_ID structure, followed by the
// policy value"). A delegated entity satisfies that policy in a session,
// executes TPM2_PolicyAuthorizeNV against the index, and the TPM replaces the
// session digest with the PolicyDelegationNV branch; PolicyOR over the four
// branches then reaches the key's authPolicy (section 7.3).
//
// Section 7.3.5: the index "SHOULD NOT be populated by the OEM". On this
// platform the operator that runs provisioning is the device Owner, and the
// index is populated only when the configuration asks for platform binding
// (PlatformPolicy on the IDevID or IAK); the Owner surface below is exported
// so a separate Owner can define and write it after the fact.

// DevIDDelegation is a Delegation Policy (section 7.3) in the two forms it
// takes: the digest the Privacy Administrator writes into the Policy NV
// Index, and the assertions a delegated entity executes in a policy session
// to reach that digest before TPM2_PolicyAuthorizeNV.
type DevIDDelegation struct {
	// NameAlg is the hash algorithm Digest is computed in. It must be the
	// nameAlg of the key being delegated: the session that satisfies the
	// Delegation Policy is the session that then has to reach the key's
	// authPolicy, and a session has one hash algorithm.
	NameAlg tpm2.TPMAlgID

	// Digest is the Delegation Policy digest, without the leading hash ID
	// the NV index stores in front of it (see DevIDDelegationPolicyPayload).
	Digest []byte

	// Satisfy executes, in policySession, the policy assertions that bring
	// the session's policyDigest to Digest.
	Satisfy func(t transport.TPM, policySession tpm2.TPMHandle) error
}

// devidSigningDelegationCommands is the command set of the example IDevID
// Delegation Policy (section 7.3.7, Figure 10; Table 20 "Signing Delegation
// Policy"): use of the key for signing, and certification at the ADMIN role.
// The order is the order of Table 20's PolicyOR.
func devidSigningDelegationCommands() []tpm2.TPMCC {
	return []tpm2.TPMCC{tpm2.TPMCCSign, tpm2.TPMCCCertify}
}

// devidAttestationDelegationCommands is the command set of the example IAK
// Delegation Policy (section 7.3.7, Figure 11; Table 20 "Attestation
// Delegation Policy"): Quote, signing an audit digest, certifying another key
// and releasing a credential. The order is the order of Table 20's PolicyOR.
func devidAttestationDelegationCommands() []tpm2.TPMCC {
	return []tpm2.TPMCC{
		tpm2.TPMCCQuote,
		tpm2.TPMCCGetSessionAuditDigest,
		tpm2.TPMCCCertify,
		tpm2.TPMCCActivateCredential,
	}
}

// DevIDSigningDelegation returns the specification's example IDevID
// Delegation Policy (section 7.3.7, Table 20): PolicyOR over
// PolicyCommandCode(TPM_CC_Sign) and PolicyCommandCode(TPM_CC_Certify),
// satisfied for command. Written into the IDevID's Policy NV Index it lets
// anyone with a policy session sign with the key and certify it, and nothing
// else.
func DevIDSigningDelegation(nameAlg tpm2.TPMAlgID, command tpm2.TPMCC) (DevIDDelegation, error) {
	return DevIDCommandDelegation(nameAlg, command, devidSigningDelegationCommands()...)
}

// DevIDAttestationDelegation returns the specification's example IAK
// Delegation Policy (section 7.3.7, Table 20): PolicyOR over
// PolicyCommandCode for TPM_CC_Quote, TPM_CC_GetSessionAuditDigest,
// TPM_CC_Certify and TPM_CC_ActivateCredential, satisfied for command.
func DevIDAttestationDelegation(nameAlg tpm2.TPMAlgID, command tpm2.TPMCC) (DevIDDelegation, error) {
	return DevIDCommandDelegation(nameAlg, command, devidAttestationDelegationCommands()...)
}

// DevIDCommandDelegation builds a Delegation Policy that admits exactly the
// listed commands: PolicyOR over one PolicyCommandCode branch per command,
// in the order given (a single command is its PolicyCommandCode digest
// alone). command selects the branch the returned Satisfy walks, so it must
// be one of allowed; a session built for one command cannot authorize
// another, which is the confinement a command-code policy exists for.
func DevIDCommandDelegation(nameAlg tpm2.TPMAlgID, command tpm2.TPMCC, allowed ...tpm2.TPMCC) (DevIDDelegation, error) {
	if len(allowed) == 0 {
		return DevIDDelegation{}, &errs.Detail{Err: ErrDevIDPolicySession,
			Detail: "a command delegation must admit at least one command"}
	}
	branches := tpm2.TPMLDigest{}
	admitted := false
	for _, code := range allowed {
		calc, err := devidPolicyCalculator(nameAlg)
		if err != nil {
			return DevIDDelegation{}, err
		}
		if err := (tpm2.PolicyCommandCode{Code: code}).Update(calc); err != nil {
			return DevIDDelegation{}, &errs.Detail{Err: ErrDevIDPolicyDigestCompute, Detail: fmt.Sprintf("PolicyCommandCode trial: %v", err)}
		}
		branches.Digests = append(branches.Digests, tpm2.TPM2BDigest{Buffer: calc.Hash().Digest})
		admitted = admitted || code == command
	}
	if !admitted {
		return DevIDDelegation{}, &errs.Detail{Err: ErrDevIDPolicySession,
			Detail: fmt.Sprintf("command 0x%08x is not admitted by the delegation policy", uint32(command))}
	}

	digest := branches.Digests[0].Buffer
	if len(branches.Digests) > 1 {
		calc, err := devidPolicyCalculator(nameAlg)
		if err != nil {
			return DevIDDelegation{}, err
		}
		if err := (tpm2.PolicyOr{PHashList: branches}).Update(calc); err != nil {
			return DevIDDelegation{}, &errs.Detail{Err: ErrDevIDPolicyDigestCompute, Detail: fmt.Sprintf("PolicyOR trial: %v", err)}
		}
		digest = calc.Hash().Digest
	}

	return DevIDDelegation{
		NameAlg: nameAlg,
		Digest:  digest,
		Satisfy: func(t transport.TPM, policySession tpm2.TPMHandle) error {
			if _, err := (tpm2.PolicyCommandCode{PolicySession: policySession, Code: command}).Execute(t); err != nil {
				return devidPolicyStepError("PolicyCommandCode", err)
			}
			if len(branches.Digests) == 1 {
				return nil
			}
			if _, err := (tpm2.PolicyOr{PolicySession: policySession, PHashList: branches}).Execute(t); err != nil {
				return devidPolicyStepError("PolicyOR(delegation)", err)
			}
			return nil
		},
	}, nil
}

// DevIDPlatformDelegation returns the Delegation Policy that binds use of an
// IDevID or IAK to the platform's measured state: TPM2_PolicyPCR over the
// configured platform PCR at its current value, in the key's nameAlg. This is
// what PlatformPolicy on an IDevID or IAK configuration means under the
// specification: the key's authPolicy is fixed by Template H-0, so platform
// binding is expressed as the Delegation Policy the Owner writes into the
// Policy NV Index (section 7.2.4), not as a different key policy.
//
// The digest is taken from the live PCR, so the returned delegation describes
// the state the platform is in now. A session built from it after the
// platform state moves fails at TPM2_PolicyPCR -- that refusal is the binding.
func (tpm *TPM2) DevIDPlatformDelegation(nameAlg tpm2.TPMAlgID) (DevIDDelegation, error) {
	bank, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return DevIDDelegation{}, &errs.Detail{Err: ErrDevIDPolicySession, Detail: fmt.Sprintf("%v", err)}
	}
	pcrDigest, err := tpm.platformPCRDigest(nameAlg)
	if err != nil {
		return DevIDDelegation{}, err
	}
	selection := platformPolicyPCRSelection(bank, tpm.config.PlatformPCR)

	calc, err := devidPolicyCalculator(nameAlg)
	if err != nil {
		return DevIDDelegation{}, err
	}
	trial := tpm2.PolicyPCR{PcrDigest: tpm2.TPM2BDigest{Buffer: pcrDigest}, Pcrs: selection}
	if err := trial.Update(calc); err != nil {
		return DevIDDelegation{}, &errs.Detail{Err: ErrDevIDPolicyDigestCompute, Detail: fmt.Sprintf("PolicyPCR trial: %v", err)}
	}

	return DevIDDelegation{
		NameAlg: nameAlg,
		Digest:  calc.Hash().Digest,
		Satisfy: func(t transport.TPM, policySession tpm2.TPMHandle) error {
			_, err := tpm2.PolicyPCR{
				PolicySession: policySession,
				PcrDigest:     tpm2.TPM2BDigest{Buffer: pcrDigest},
				Pcrs:          selection,
			}.Execute(t)
			if err != nil {
				return devidPolicyStepError("PolicyPCR", err)
			}
			return nil
		},
	}, nil
}

// DevIDDelegationPolicyPayload returns the bytes the Policy NV Index holds
// for a Delegation Policy digest: a TPMT_HA, the two-byte hash algorithm ID
// followed by the digest without a size (section 7.3.5 NOTE). This is the
// form Table 20 prints its example policies in, "with leading HASH ID", and
// the form TPM2_PolicyAuthorizeNV reads back; a bare digest in the index is
// refused by the TPM as a malformed TPMT_HA.
func DevIDDelegationPolicyPayload(nameAlg tpm2.TPMAlgID, policyDigest []byte) ([]byte, error) {
	size, err := devidDigestSize(nameAlg)
	if err != nil {
		return nil, err
	}
	if len(policyDigest) != int(size) {
		return nil, &errs.Detail{Err: ErrDevIDPolicyDigestCompute,
			Detail: fmt.Sprintf("a delegation policy digest for nameAlg 0x%04x is %d bytes, got %d", uint16(nameAlg), size, len(policyDigest))}
	}
	payload := make([]byte, 2+len(policyDigest))
	binary.BigEndian.PutUint16(payload, uint16(nameAlg))
	copy(payload[2:], policyDigest)
	return payload, nil
}

// DefineDevIDPolicyNV defines the Policy NV Index for a key kind and nameAlg
// to NV Policy Template I-0/I-1..I-3 under Owner authorization: "a Policy NV
// Index MAY be defined by the device Owner using Owner Authorization"
// (section 7.3.5). The index's authPolicy is PolicyUser, so once defined
// only the Privacy Administrator can write it (WriteDevIDDelegationPolicy).
//
// The call is idempotent. An index that already exists is accepted when its
// Name is the specification's -- Table 18 once written, or the same public
// area before its first write -- and refused with ErrDevIDPolicyNVIndex
// otherwise: the Name is what the key policy's PolicyDelegationNV branch was
// computed over (section 7.3.6.4), so an index with any other public area
// can never delegate this key, whatever is written into it.
func (tpm *TPM2) DefineDevIDPolicyNV(kind DevIDKeyKind, nameAlg tpm2.TPMAlgID, ownerAuth []byte) error {
	public, err := DevIDPolicyNVPublic(kind, nameAlg)
	if err != nil {
		return err
	}

	// TPMA_NV_WRITTEN is set by the TPM on the first write and is not an
	// input to TPM2_NV_DefineSpace; the template's Name (Table 18) is over the
	// WRITTEN state, so the freshly defined index has the unwritten Name.
	define := public
	define.Attributes.Written = false

	err = tpm.nvDefineSpace(tpm2.TPMRHOwner, ownerAuth, &tpm2.NVDefineSpace{
		PublicInfo: tpm2.New2B(define),
	})
	if err != nil && !errors.Is(err, tpm2.TPMRCNVDefined) {
		return &errs.Detail{Err: ErrDevIDDelegation, Detail: fmt.Sprintf("NV_DefineSpace 0x%08x: %v", uint32(public.NVIndex), err)}
	}
	if err == nil {
		tpm.logger.Info("devid: Policy NV Index defined",
			slog.String("kind", kind.String()),
			slog.String("index", fmt.Sprintf("0x%08x", uint32(public.NVIndex))))
	}

	// Whether the TPM just defined the index or reported it already defined,
	// what matters is the Name it actually carries.
	_, err = tpm.devidPolicyNVName(kind, nameAlg)
	return err
}

// devidPolicyNVName reads the Policy NV Index back from the TPM and returns
// its current Name, refusing with ErrDevIDPolicyNVIndex unless that Name is
// the specification's for the index's written or unwritten state.
func (tpm *TPM2) devidPolicyNVName(kind DevIDKeyKind, nameAlg tpm2.TPMAlgID) (tpm2.TPM2BName, error) {
	public, err := DevIDPolicyNVPublic(kind, nameAlg)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	written, err := DevIDPolicyNVName(kind, nameAlg)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	unwrittenPublic := public
	unwrittenPublic.Attributes.Written = false
	unwritten, err := tpm2.NVName(&unwrittenPublic)
	if err != nil {
		return tpm2.TPM2BName{}, &errs.Detail{Err: ErrDevIDPolicyDigestCompute, Detail: fmt.Sprintf("NV Name: %v", err)}
	}

	rsp, err := tpm2.NVReadPublic{NVIndex: public.NVIndex}.Execute(tpm.transport)
	if err != nil {
		return tpm2.TPM2BName{}, &errs.Detail{Err: ErrDevIDDelegation,
			Detail: fmt.Sprintf("NV_ReadPublic 0x%08x: %v", uint32(public.NVIndex), err)}
	}
	if !bytes.Equal(rsp.NVName.Buffer, written.Buffer) && !bytes.Equal(rsp.NVName.Buffer, unwritten.Buffer) {
		return tpm2.TPM2BName{}, &errs.Detail{Err: ErrDevIDPolicyNVIndex,
			Detail: fmt.Sprintf("index 0x%08x has Name %x; the specification's Table 18 Name is %x",
				uint32(public.NVIndex), rsp.NVName.Buffer, written.Buffer)}
	}
	return rsp.NVName, nil
}

// WriteDevIDDelegationPolicy writes a Delegation Policy into the Policy NV
// Index for a key kind and nameAlg, as the Privacy Administrator: "The
// Privacy Administrator chooses the desired IDevID/IAK Delegation Policy and
// writes that Delegation Policy into the NV index" (section 7.2.4). The
// index's authPolicy is PolicyUser, so the write runs under a
// PolicySecret(TPM_RH_ENDORSEMENT) session proving endorsementAuth; the
// stored value is the TPMT_HA DevIDDelegationPolicyPayload builds. The
// Delegation Policy "can be replaced by the Privacy Administrator at any
// time" (section 7.3.1), so the call overwrites whatever the index held.
//
// The index must already exist with the specification's Name
// (DefineDevIDPolicyNV); anything else is refused before the session opens.
func (tpm *TPM2) WriteDevIDDelegationPolicy(
	kind DevIDKeyKind,
	nameAlg tpm2.TPMAlgID,
	policyDigest []byte,
	endorsementAuth []byte) error {

	payload, err := DevIDDelegationPolicyPayload(nameAlg, policyDigest)
	if err != nil {
		return err
	}
	index, err := DevIDPolicyNVIndex(kind, nameAlg)
	if err != nil {
		return err
	}
	name, err := tpm.devidPolicyNVName(kind, nameAlg)
	if err != nil {
		return err
	}

	session, closer, err := tpm2.PolicySession(tpm.transport, nameAlg, 16)
	if err != nil {
		return &errs.Detail{Err: ErrDevIDDelegation, Detail: fmt.Sprintf("policy session: %v", err)}
	}
	defer func() {
		if closeErr := closer(); closeErr != nil {
			tpm.logger.Error("devid: failed to close the NV write policy session",
				slog.String("error", closeErr.Error()))
		}
	}()

	err = tpm.policySecret(tpm2.TPMRHEndorsement, endorsementAuth, session)
	if err != nil {
		return &errs.Detail{Err: ErrDevIDDelegation, Detail: fmt.Sprintf("PolicySecret(endorsement): %v", err)}
	}

	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: index,
			Name:   name,
			Auth:   session,
		},
		NVIndex: tpm2.NamedHandle{Handle: index, Name: name},
		Data:    tpm2.TPM2BMaxNVBuffer{Buffer: payload},
	}.Execute(tpm.transport)
	if err != nil {
		return &errs.Detail{Err: ErrDevIDDelegation, Detail: fmt.Sprintf("NV_Write 0x%08x: %v", uint32(index), err)}
	}

	tpm.logger.Info("devid: Delegation Policy written",
		slog.String("kind", kind.String()),
		slog.String("index", fmt.Sprintf("0x%08x", uint32(index))),
		slog.String("policy", fmt.Sprintf("%x", payload)))
	return nil
}

// DevIDDelegatedSession builds the policy session through which a delegated
// entity uses an IDevID or IAK (section 7.3): it satisfies the Delegation
// Policy in the session, executes TPM2_PolicyAuthorizeNV against the key
// kind's Policy NV Index -- which the TPM honours only if the index holds
// exactly the digest the session reached -- and completes the PolicyOR of
// the key policy. The result authorizes the key for whatever the Delegation
// Policy admits; the TPM refuses it for anything else. The caller must invoke
// the returned closer once the command has executed.
func (tpm *TPM2) DevIDDelegatedSession(
	kind DevIDKeyKind,
	nameAlg tpm2.TPMAlgID,
	delegation DevIDDelegation) (tpm2.Session, func() error, error) {

	if delegation.NameAlg != nameAlg {
		return nil, nil, &errs.Detail{Err: ErrDevIDPolicySession,
			Detail: fmt.Sprintf("the delegation policy is in 0x%04x but the key's nameAlg is 0x%04x", uint16(delegation.NameAlg), uint16(nameAlg))}
	}
	if delegation.Satisfy == nil {
		return nil, nil, &errs.Detail{Err: ErrDevIDPolicySession, Detail: "the delegation policy has no assertions to satisfy"}
	}
	index, err := DevIDPolicyNVIndex(kind, nameAlg)
	if err != nil {
		return nil, nil, err
	}
	name, err := DevIDPolicyNVName(kind, nameAlg)
	if err != nil {
		return nil, nil, err
	}

	return tpm.devidPolicySession(kind, nameAlg, "delegated USER", func(session tpm2.Session) error {
		if err := delegation.Satisfy(tpm.transport, session.Handle()); err != nil {
			return err
		}
		// The index is readable by anyone (TPMA_NV_AUTHREAD with an empty
		// authValue, Template I-0); the delegation is enforced by the digest
		// comparison inside the TPM, not by who may read it.
		_, err := tpm2.PolicyAuthorizeNV{
			AuthHandle: tpm2.AuthHandle{
				Handle: index,
				Name:   name,
				Auth:   tpm2.PasswordAuth(nil),
			},
			NVIndex:       tpm2.NamedHandle{Handle: index, Name: name},
			PolicySession: session.Handle(),
		}.Execute(tpm.transport)
		if err != nil {
			return devidPolicyStepError("PolicyAuthorizeNV", err)
		}
		return nil
	})
}

// devidPlatformDelegatedSession is the session createKeySession hands out for
// an IDevID or IAK whose configuration asks for platform binding and whose
// authValue is empty: the platform Delegation Policy satisfied against the
// live PCR, authorized through the key's Policy NV Index. The key's nameAlg
// is read from the object itself, because it is an input to the policy and
// nothing in the stored attributes is guaranteed to agree with it.
func (tpm *TPM2) devidPlatformDelegatedSession(
	kind DevIDKeyKind,
	keyAttrs *types.KeyAttributes) (tpm2.Session, func() error, error) {

	if keyAttrs.TPMAttributes == nil {
		return nil, nil, ErrInvalidKeyAttributes
	}
	rsp, err := tpm2.ReadPublic{ObjectHandle: keyAttrs.TPMAttributes.Handle}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrDevIDPolicySession,
			Detail: fmt.Sprintf("ReadPublic 0x%08x: %v", uint32(keyAttrs.TPMAttributes.Handle), err)}
	}
	public, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrDevIDPolicySession, Detail: fmt.Sprintf("public area: %v", err)}
	}
	delegation, err := tpm.DevIDPlatformDelegation(public.NameAlg)
	if err != nil {
		return nil, nil, err
	}
	return tpm.DevIDDelegatedSession(kind, public.NameAlg, delegation)
}

// provisionDevIDPlatformDelegation defines the Policy NV Index for a freshly
// created IDevID or IAK and writes the platform Delegation Policy into it.
// This is what PlatformPolicy on the key's configuration provisions: the key
// itself is Template H-0 regardless, and the platform binding lives in the
// index (section 7.2.4). Provision sets one authorization on the Owner and
// Endorsement hierarchies (SetHierarchyAuth), so hierarchyAuth serves both
// the Owner define and the Privacy Administrator write.
func (tpm *TPM2) provisionDevIDPlatformDelegation(
	kind DevIDKeyKind,
	nameAlg tpm2.TPMAlgID,
	hierarchyAuth []byte) error {

	if err := tpm.DefineDevIDPolicyNV(kind, nameAlg, hierarchyAuth); err != nil {
		return err
	}
	delegation, err := tpm.DevIDPlatformDelegation(nameAlg)
	if err != nil {
		return err
	}
	return tpm.WriteDevIDDelegationPolicy(kind, nameAlg, delegation.Digest, hierarchyAuth)
}

// devidPolicyStepError wraps a TPM refusal of one policy command as
// ErrDevIDPolicySession, naming the step and keeping the TPM's own response
// code in the chain so a caller can tell a digest mismatch (TPM_RC_VALUE at
// PolicyAuthorizeNV) from a moved platform (TPM_RC_VALUE at PolicyPCR) from
// a wrong authorization.
func devidPolicyStepError(step string, err error) error {
	return &errs.Joined{Lead: ErrDevIDPolicySession, Detail: step, Cause: err}
}
