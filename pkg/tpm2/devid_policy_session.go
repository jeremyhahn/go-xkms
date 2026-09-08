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
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// DevIDAdminSession builds the policy session that authorizes the ADMIN role
// of an IDevID or IAK key for exactly one command, as the Privacy
// Administrator. It walks the branch of the IDevID/IAK Key Policy that
// TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12 defines
// for that command:
//
//	TPM2_PolicySecret(TPM_RH_ENDORSEMENT)          -- section 7.3.6.1
//	TPM2_PolicyCommandCode(command)                -- section 7.3.6.2 / 7.3.6.3
//	TPM2_PolicyOR(User, Certify, ActivateCredential, DelegationNV)
//	                                               -- section 7.3.6.6
//
// After the PolicyOR the session's digest equals the key's authPolicy, so the
// TPM honours it for the ADMIN role of that one command and nothing else: a
// session built for TPM_CC_Certify cannot authorize TPM2_ActivateCredential,
// because the command-code statement is part of the digest. The caller must
// invoke the returned closer once the command has executed.
//
// Only TPM_CC_Certify and TPM_CC_ActivateCredential have branches in the
// policy; any other command is refused here rather than producing a session
// the TPM would reject with TPM_RC_POLICY_FAIL.
//
// endorsementAuth is the Endorsement Hierarchy authorization value the
// Privacy Administrator holds. PolicySecret proves knowledge of it to the TPM
// inside the session; it is never attached to the key.
func (tpm *TPM2) DevIDAdminSession(
	kind DevIDKeyKind,
	nameAlg tpm2.TPMAlgID,
	command tpm2.TPMCC,
	endorsementAuth []byte) (tpm2.Session, func() error, error) {

	switch command {
	case tpm2.TPMCCCertify, tpm2.TPMCCActivateCredential:
	default:
		return nil, nil, &errs.Detail{Err: ErrDevIDPolicySession,
			Detail: fmt.Sprintf("no ADMIN-role branch exists for command 0x%08x; the key policy admits only TPM_CC_Certify and TPM_CC_ActivateCredential", uint32(command))}
	}

	branches, err := DevIDKeyPolicyBranches(kind, nameAlg)
	if err != nil {
		return nil, nil, err
	}

	session, closer, err := tpm2.PolicySession(tpm.transport, nameAlg, 16)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrDevIDPolicySession, Detail: fmt.Sprintf("%v", err)}
	}
	fail := func(step string, stepErr error) (tpm2.Session, func() error, error) {
		if closeErr := closer(); closeErr != nil {
			tpm.logger.Error("devid: failed to close policy session after error",
				slog.String("step", step), slog.String("error", closeErr.Error()))
		}
		return nil, nil, &errs.Detail{Err: ErrDevIDPolicySession, Detail: fmt.Sprintf("%s: %v", step, stepErr)}
	}

	_, err = tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(endorsementAuth),
		},
		NonceTPM:      session.NonceTPM(),
		PolicySession: session.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		return fail("PolicySecret(endorsement)", err)
	}

	_, err = tpm2.PolicyCommandCode{
		PolicySession: session.Handle(),
		Code:          command,
	}.Execute(tpm.transport)
	if err != nil {
		return fail("PolicyCommandCode", err)
	}

	_, err = tpm2.PolicyOr{
		PolicySession: session.Handle(),
		PHashList:     branches,
	}.Execute(tpm.transport)
	if err != nil {
		return fail("PolicyOR", err)
	}

	tpm.logger.Debug("devid: ADMIN-role policy session built",
		slog.String("kind", kind.String()),
		slog.String("command", fmt.Sprintf("0x%08x", uint32(command))))

	return session, closer, nil
}

// devidKeyKindOf reports which TCG DevID key kind a key type is, or false for
// a key that is neither an IDevID nor an IAK and so carries no IDevID/IAK Key
// Policy.
func devidKeyKindOf(keyType types.KeyType) (DevIDKeyKind, bool) {
	switch keyType {
	case types.KeyTypeIDevID:
		return DevIDKeySigning, true
	case types.KeyTypeAttestation:
		return DevIDKeyAttestation, true
	default:
		return 0, false
	}
}
