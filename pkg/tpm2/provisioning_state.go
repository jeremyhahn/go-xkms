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
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
)

// ProvisioningState classifies a TPM's current provisioning progress: which
// hierarchy auths TPMA_PERMANENT reports set, which of this device's
// configured persistent handles already exist, and whether the persisted
// Platform SRK was created under the platform policy this device currently
// computes.
//
// State is a snapshot: every field reflects what State observed on the call
// that produced it and is not refreshed as the TPM changes underneath the
// caller.
type ProvisioningState struct {
	// OwnerAuthSet, EndorsementAuthSet and LockoutAuthSet report the
	// TPMA_PERMANENT ownerAuthSet, endorsementAuthSet and lockoutAuthSet
	// bits (TCG TPM 2.0 Part 2, section 8.3, Table 32) -- whether an
	// authorization value has ever been set for that hierarchy since the
	// last TPM2_Clear.
	OwnerAuthSet       bool
	EndorsementAuthSet bool
	LockoutAuthSet     bool

	// EKPresent, SSRKPresent, IAKPresent, IDevIDPresent and
	// PlatformSRKPresent report whether the persistent handle configured
	// for each key (Config.EK.Handle, Config.SSRK.Handle,
	// Config.IAK.Handle, Config.IDevID.Handle,
	// Config.PlatformSRK.SRKHandle) is occupied on this TPM right now.
	// False both when the corresponding Config section is nil and when the
	// handle is empty -- State does not distinguish "not configured" from
	// "configured but not yet created", since either way there is nothing
	// at the handle to use.
	EKPresent          bool
	SSRKPresent        bool
	IAKPresent         bool
	IDevIDPresent      bool
	PlatformSRKPresent bool

	// PlatformSRKPolicyCurrent is true only when the Platform SRK is
	// present AND its authPolicy equals the platform policy digest this
	// device computes right now (PlatformPolicyDigest) -- i.e. the key was
	// created under, or has since been reconciled to, the platform's
	// current PCR state. It is false both when the Platform SRK is absent
	// and when its authPolicy was computed under different PCR content;
	// callers that need to tell those two apart also check
	// PlatformSRKPresent.
	PlatformSRKPolicyCurrent bool
}

// State classifies the TPM's current provisioning progress so a caller can
// decide whether a fresh Install/Provision pass, a targeted repair, or no
// action at all is appropriate, without re-deriving the same TPMA_PERMANENT
// bit and persistent-handle checks itself (go-xkms#798).
func (tpm *TPM2) State() (*ProvisioningState, error) {
	fixed, err := tpm.FixedProperties()
	if err != nil {
		return nil, &errs.Detail{Err: ErrProvisioningStateRead, Detail: fmt.Sprintf("fixed properties: %v", err)}
	}

	state := &ProvisioningState{
		OwnerAuthSet:       fixed.Permanent&permanentOwnerAuthSet != 0,
		EndorsementAuthSet: fixed.Permanent&permanentEndorsementAuthSet != 0,
		LockoutAuthSet:     fixed.Permanent&permanentLockoutAuthSet != 0,
	}

	if tpm.config.EK != nil && tpm.config.EK.Handle != 0 {
		state.EKPresent = tpm.handlePresent(tpm2.TPMHandle(tpm.config.EK.Handle))
	}
	if tpm.config.SSRK != nil && tpm.config.SSRK.Handle != 0 {
		state.SSRKPresent = tpm.handlePresent(tpm2.TPMHandle(tpm.config.SSRK.Handle))
	}
	if tpm.config.IAK != nil && tpm.config.IAK.Handle != 0 {
		state.IAKPresent = tpm.handlePresent(tpm2.TPMHandle(tpm.config.IAK.Handle))
	}
	if tpm.config.IDevID != nil && tpm.config.IDevID.Handle != 0 {
		state.IDevIDPresent = tpm.handlePresent(tpm2.TPMHandle(tpm.config.IDevID.Handle))
	}

	if tpm.config.PlatformSRK != nil && tpm.config.PlatformSRK.SRKHandle != 0 {
		handle := tpm2.TPMHandle(tpm.config.PlatformSRK.SRKHandle)
		_, pub, readErr := tpm.ReadHandle(handle)
		if readErr == nil {
			state.PlatformSRKPresent = true

			current, digestErr := tpm.PlatformPolicyDigest()
			if digestErr != nil {
				return nil, &errs.Detail{Err: ErrProvisioningStateRead, Detail: fmt.Sprintf("platform policy digest: %v", digestErr)}
			}
			state.PlatformSRKPolicyCurrent = bytes.Equal(pub.AuthPolicy.Buffer, current.Buffer)
		}
	}

	return state, nil
}

// handlePresent reports whether a persistent handle is occupied, by
// attempting to read its public area. Any error -- TPM_RC_HANDLE for an
// empty slot, or any other transport/response failure -- is treated as
// absent; State surfaces only definite presence, never a guess.
func (tpm *TPM2) handlePresent(handle tpm2.TPMHandle) bool {
	_, _, err := tpm.ReadHandle(handle)
	return err == nil
}
