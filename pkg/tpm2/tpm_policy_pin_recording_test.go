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
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// policyPinRecordingBackend is a minimal store.KeyBackend double that records
// what recordPrimaryPolicyPin/recordKeyPolicyPin save, or fails on demand, so
// the error-propagation branches of both can be exercised without a real
// on-disk backend.
type policyPinRecordingBackend struct {
	store.KeyBackend
	saveErr  error
	saved    []byte
	overwrit bool
}

func (b *policyPinRecordingBackend) Save(attrs *types.KeyAttributes, data []byte, ext types.FSExtension, overwrite bool) error {
	if b.saveErr != nil {
		return b.saveErr
	}
	b.saved = data
	b.overwrit = overwrite
	return nil
}

// TestRecordPrimaryPolicyPin_NoTPMAttributes proves the function refuses to
// record a pin for a key that carries no TPM attributes -- there is no
// handle to qualify the record's name with, and no handle means no primary
// key could have used the pin in the first place.
func TestRecordPrimaryPolicyPin_NoTPMAttributes(t *testing.T) {
	tpm := &TPM2{logger: discardLogger()}
	keyAttrs := &types.KeyAttributes{CN: "no-tpm-attrs"}
	pin := &store.PlatformPolicyPin{PCRBank: uint16(tpm2.TPMAlgSHA256), PCRSelect: DefaultPlatformPCRs().Mask(), PCRDigest: make([]byte, 32)}

	err := tpm.recordPrimaryPolicyPin(keyAttrs, pin)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPlatformPolicyDigestCompute)
}

// TestRecordPrimaryPolicyPin_NilBackend proves a TPM2 with no key backend
// configured degrades gracefully: the pin simply is not recorded, logged as
// a warning, and the caller is not failed for a condition that only costs
// the password branch's platform-change survivability.
func TestRecordPrimaryPolicyPin_NilBackend(t *testing.T) {
	tpm := &TPM2{logger: discardLogger(), backend: nil}
	keyAttrs := &types.KeyAttributes{
		CN:            "no-backend",
		TPMAttributes: &types.TPMAttributes{Handle: tpm2.TPMHandle(0x81000099)},
	}
	pin := &store.PlatformPolicyPin{PCRBank: uint16(tpm2.TPMAlgSHA256), PCRSelect: DefaultPlatformPCRs().Mask(), PCRDigest: make([]byte, 32)}

	require.NoError(t, tpm.recordPrimaryPolicyPin(keyAttrs, pin))
}

// TestRecordPrimaryPolicyPin_MarshalError proves a pin that cannot be
// serialized (here, an empty PCR digest) is rejected before the backend is
// ever touched.
func TestRecordPrimaryPolicyPin_MarshalError(t *testing.T) {
	backend := &policyPinRecordingBackend{}
	tpm := &TPM2{logger: discardLogger(), backend: backend}
	keyAttrs := &types.KeyAttributes{
		CN:            "bad-pin",
		TPMAttributes: &types.TPMAttributes{Handle: tpm2.TPMHandle(0x81000099)},
	}
	pin := &store.PlatformPolicyPin{PCRBank: uint16(tpm2.TPMAlgSHA256), PCRSelect: DefaultPlatformPCRs().Mask()}

	err := tpm.recordPrimaryPolicyPin(keyAttrs, pin)
	require.Error(t, err)
	assert.Nil(t, backend.saved, "backend.Save must not be reached when MarshalBinary fails")
}

// TestRecordPrimaryPolicyPin_SaveError proves a backend failure is surfaced
// to the caller rather than being silently treated the same as "no backend
// configured".
func TestRecordPrimaryPolicyPin_SaveError(t *testing.T) {
	saveErr := errors.New("simulated backend save failure")
	backend := &policyPinRecordingBackend{saveErr: saveErr}
	tpm := &TPM2{logger: discardLogger(), backend: backend}
	keyAttrs := &types.KeyAttributes{
		CN:            "save-fails",
		TPMAttributes: &types.TPMAttributes{Handle: tpm2.TPMHandle(0x81000099)},
	}
	pin := &store.PlatformPolicyPin{PCRBank: uint16(tpm2.TPMAlgSHA256), PCRSelect: DefaultPlatformPCRs().Mask(), PCRDigest: make([]byte, 32)}

	err := tpm.recordPrimaryPolicyPin(keyAttrs, pin)
	require.Error(t, err)
	assert.ErrorIs(t, err, saveErr)
}

// TestRecordKeyPolicyPin_NilBackendFallsBackToTPMBackend proves that a nil
// backend argument falls back to tpm.backend rather than being treated as
// "record nothing" -- the two nil checks in recordKeyPolicyPin guard
// different things: the parameter falling back, and the fallback itself
// being absent.
func TestRecordKeyPolicyPin_NilBackendFallsBackToTPMBackend(t *testing.T) {
	fallback := &policyPinRecordingBackend{}
	tpm := &TPM2{logger: discardLogger(), backend: fallback}
	keyAttrs := &types.KeyAttributes{CN: "child-key"}
	pin := &store.PlatformPolicyPin{PCRBank: uint16(tpm2.TPMAlgSHA256), PCRSelect: DefaultPlatformPCRs().Mask(), PCRDigest: make([]byte, 32)}

	require.NoError(t, tpm.recordKeyPolicyPin(keyAttrs, nil, pin, true))
	assert.NotNil(t, fallback.saved, "the fallback tpm.backend must have received the save")
	assert.True(t, fallback.overwrit)
}

// TestRecordKeyPolicyPin_NoBackendAtAll proves that when both the argument
// and tpm.backend are nil, recordKeyPolicyPin degrades gracefully instead of
// panicking on a nil backend.Save call.
func TestRecordKeyPolicyPin_NoBackendAtAll(t *testing.T) {
	tpm := &TPM2{logger: discardLogger(), backend: nil}
	keyAttrs := &types.KeyAttributes{CN: "child-key"}
	pin := &store.PlatformPolicyPin{PCRBank: uint16(tpm2.TPMAlgSHA256), PCRSelect: DefaultPlatformPCRs().Mask(), PCRDigest: make([]byte, 32)}

	require.NoError(t, tpm.recordKeyPolicyPin(keyAttrs, nil, pin, true))
}

// TestRecordKeyPolicyPin_SaveError proves a backend failure on a child key's
// pin is surfaced to the caller.
func TestRecordKeyPolicyPin_SaveError(t *testing.T) {
	saveErr := errors.New("simulated child pin save failure")
	backend := &policyPinRecordingBackend{saveErr: saveErr}
	tpm := &TPM2{logger: discardLogger()}
	keyAttrs := &types.KeyAttributes{CN: "child-key"}
	pin := &store.PlatformPolicyPin{PCRBank: uint16(tpm2.TPMAlgSHA256), PCRSelect: DefaultPlatformPCRs().Mask(), PCRDigest: make([]byte, 32)}

	err := tpm.recordKeyPolicyPin(keyAttrs, backend, pin, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, saveErr)
}
