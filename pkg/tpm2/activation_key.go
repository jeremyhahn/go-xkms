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

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
)

// ActivationKey is a transient key created purely to answer an EK
// credential challenge (see CreateActivationKey / AnswerCredentialChallenge).
// It carries no hierarchy auth and no object auth, and is never persisted:
// AnswerCredentialChallenge flushes it once the challenge has been answered,
// exactly like any other transient object.
type ActivationKey struct {
	// Handle is the transient object handle CreateActivationKey loaded the
	// key at. It is valid only until AnswerCredentialChallenge consumes it
	// (or the TPM session ends).
	Handle tpm2.TPMHandle

	// Name is the key's TPM Name (nameAlg || digest). A verifier computes
	// the same value from Public with ActivationKeyName and passes it to
	// NewCredentialChallenge as activationKeyName.
	Name tpm2.TPM2BName

	// Public is the key's public area, sent to the verifier so it can
	// independently recompute Name (ActivationKeyName) rather than trust
	// the device's claimed Name outright.
	Public tpm2.TPMTPublic
}

// CreateActivationKey creates a transient, unrestricted signing key in the
// TPM's null hierarchy (TPM2_CreatePrimary under TPM_RH_NULL) purely to
// answer an EK credential challenge (NewCredentialChallenge /
// AnswerCredentialChallenge). The null hierarchy's seed is re-randomized on
// every TPM reset (TCG TPM 2.0 Part 1, section 24.4) and needs no
// authorization to use, so the key needs, and gets, no hierarchy auth and no
// object auth: whatever proof of possession a caller needs from the key is
// established by the credential challenge itself, not by key persistence or
// a password.
//
// This is the primitive an install-time caller uses when no IAK exists yet
// (go-xkms#798) -- proving possession of a device's EK before any identity
// has been provisioned. ActivateCredential's hardcoded IAK path remains for
// the already-provisioned enrollment flow (enroll-01), which continues to
// use it.
func (tpm *TPM2) CreateActivationKey() (*ActivationKey, error) {
	template, err := tpm.KeyTemplate(KeyTemplateSpec{})
	if err != nil {
		return nil, &errs.Detail{Err: ErrActivationKeyCreate, Detail: fmt.Sprintf("build template: %v", err)}
	}

	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHNull,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(template),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, &errs.Detail{Err: ErrActivationKeyCreate, Detail: fmt.Sprintf("%v", err)}
	}

	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		tpm.flushSilent(rsp.ObjectHandle)
		return nil, &errs.Detail{Err: ErrActivationKeyCreate, Detail: fmt.Sprintf("read public area: %v", err)}
	}

	return &ActivationKey{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Public: *pub,
	}, nil
}

// AnswerCredentialChallenge answers a credential challenge built by
// NewCredentialChallenge, using an activation key this TPM created with
// CreateActivationKey. It generalises the flow ActivateCredential
// hard-codes to the IAK (go-xkms#798): both perform TPM2_ActivateCredential
// against this TPM's EK, differing only in which key answers and how that
// key's ADMIN-role authorization is satisfied -- key's own (empty) password
// auth here, versus the IAK's TCG Key Policy in ActivateCredential.
//
// The activation key is flushed before AnswerCredentialChallenge returns,
// whether or not activation succeeds: CreateActivationKey/
// AnswerCredentialChallenge is a single challenge-response round trip, not
// a key the caller reuses.
func (tpm *TPM2) AnswerCredentialChallenge(
	key *ActivationKey, challenge *CredentialChallenge) ([]byte, error) {

	if key == nil {
		return nil, ErrActivationKeyRequired
	}
	if challenge == nil {
		return nil, ErrCredentialChallengeRequired
	}
	defer tpm.flushSilent(key.Handle)

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return nil, err
	}

	return tpm.activateCredential(
		ekAttrs, key.Handle, key.Name, tpm2.PasswordAuth(nil),
		challenge.CredentialBlob, challenge.EncryptedSecret)
}
