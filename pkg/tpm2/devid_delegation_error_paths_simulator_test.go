//go:build tpm_simulator
// +build tpm_simulator

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
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestDevidPlatformDelegatedSession_NoTPMAttributes proves the session
// builder refuses a key with no TPM attributes rather than dereferencing a
// nil Handle.
func TestDevidPlatformDelegatedSession_NoTPMAttributes(t *testing.T) {
	h := newDelegationHarness(t, nil)

	_, _, err := h.TPM.devidPlatformDelegatedSession(DevIDKeySigning, &types.KeyAttributes{})
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}

// TestDevidPlatformDelegatedSession_ReadPublicFault proves a handle that
// does not name a live object is surfaced as ErrDevIDPolicySession rather
// than the bare TPM response code, so callers can classify it alongside the
// package's other policy-session refusals.
func TestDevidPlatformDelegatedSession_ReadPublicFault(t *testing.T) {
	h := newDelegationHarness(t, nil)

	keyAttrs := &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{Handle: tpm2.TPMHandle(0x81FEFEFE)},
	}

	_, _, err := h.TPM.devidPlatformDelegatedSession(DevIDKeySigning, keyAttrs)
	assert.ErrorIs(t, err, ErrDevIDPolicySession)
}

// TestProvisionDevIDPlatformDelegation_DefineFault proves a wrong hierarchy
// auth is refused at the DefineDevIDPolicyNV step -- the first of
// provisionDevIDPlatformDelegation's three steps -- and that the refusal
// propagates as ErrDevIDDelegation rather than being swallowed.
func TestProvisionDevIDPlatformDelegation_DefineFault(t *testing.T) {
	h := newDelegationHarness(t, nil)

	wrongAuth := append([]byte("not-"), h.HierarchyAuth...)
	err := h.TPM.provisionDevIDPlatformDelegation(DevIDKeySigning, tpm2.TPMAlgSHA256, wrongAuth)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDevIDDelegation)
}

// TestProvisionDevIDPlatformDelegation_Succeeds pins the ordinary path: all
// three steps (define, compute the platform delegation, write it) succeed
// together and leave the index holding the platform Delegation Policy.
func TestProvisionDevIDPlatformDelegation_Succeeds(t *testing.T) {
	h := newDelegationHarness(t, nil)

	err := h.TPM.provisionDevIDPlatformDelegation(DevIDKeySigning, tpm2.TPMAlgSHA256, h.HierarchyAuth)
	require.NoError(t, err)

	public, _, _ := h.readPolicyNV(t, DevIDKeySigning)
	assert.True(t, public.Attributes.Written, "the platform delegation must have been written into the index")
}
