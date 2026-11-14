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

//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hierarchyCache returns every cached value that describes an object under
// the Owner or Endorsement hierarchy, keyed by field name.
func hierarchyCache(tpm *TPM2) map[string]any {
	return map[string]any{
		"ekAttrs":          tpm.ekAttrs,
		"ekECCPubKey":      tpm.ekECCPubKey,
		"ekRSAPubKey":      tpm.ekRSAPubKey,
		"iakAttrs":         tpm.iakAttrs,
		"idevidAttrs":      tpm.idevidAttrs,
		"lakAttrs":         tpm.lakAttrs,
		"platformSRKAttrs": tpm.platformSRKAttrs,
		"ssrkAttrs":        tpm.ssrkAttrs,
	}
}

// seedHierarchyCache fills every hierarchy cache field still empty with a
// sentinel, so a test sees each one dropped or kept.
func seedHierarchyCache(tpm *TPM2) {
	for _, attrs := range []**types.KeyAttributes{
		&tpm.ekAttrs, &tpm.iakAttrs, &tpm.idevidAttrs,
		&tpm.lakAttrs, &tpm.platformSRKAttrs, &tpm.ssrkAttrs,
	} {
		if *attrs == nil {
			*attrs = &types.KeyAttributes{}
		}
	}
	if tpm.ekECCPubKey == nil {
		tpm.ekECCPubKey = &ecdsa.PublicKey{}
	}
	if tpm.ekRSAPubKey == nil {
		tpm.ekRSAPubKey = &rsa.PublicKey{}
	}
}

func assertHierarchyCacheDropped(t *testing.T, tpm *TPM2) {
	t.Helper()
	for name, value := range hierarchyCache(tpm) {
		assert.Nil(t, value, "%s must be dropped", name)
	}
}

// defineManufacturerEKCertIndex defines the configured EK certificate index
// the way a manufacturer does, platform-created, so TPM2_Clear keeps it
// (TCG TPM 2.0 Part 3 §24.6 deletes only indexes without
// TPMA_NV_PLATFORMCREATE).
func defineManufacturerEKCertIndex(t *testing.T, tpm *TPM2) {
	t.Helper()
	platformAuth := tpm2.AuthHandle{Handle: tpm2.TPMRHPlatform, Auth: tpm2.PasswordAuth(nil)}
	nvIndex := tpm2.TPMHandle(tpm.config.EK.CertHandle)
	_, err := tpm2.NVDefineSpace{
		AuthHandle: platformAuth,
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: nvIndex,
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				PPWrite:        true,
				PPRead:         true,
				OwnerRead:      true,
				AuthRead:       true,
				NoDA:           true,
				PlatformCreate: true,
				NT:             tpm2.TPMNTOrdinary,
			},
			DataSize: 1024,
		}),
	}.Execute(tpm.transport)
	require.NoError(t, err)
	t.Cleanup(func() {
		readPub, err := tpm2.NVReadPublic{NVIndex: nvIndex}.Execute(tpm.transport)
		require.NoError(t, err)
		_, err = tpm2.NVUndefineSpace{
			AuthHandle: platformAuth,
			NVIndex:    tpm2.NamedHandle{Handle: nvIndex, Name: readPub.NVName},
		}.Execute(tpm.transport)
		require.NoError(t, err)
	})
}

// TestClear_ReDerivesEKAttributesFromConfig reproduces go-trusted-platform
// #973: TPM2_Clear flushes the persistent EK, so EKAttributes must stop
// answering from its pre-clear cache and re-derive the attributes, creation
// template included, from the config and the manufacturer's certificate.
func TestClear_ReDerivesEKAttributesFromConfig(t *testing.T) {
	tpmImpl := newEKCertSim(t)
	defineManufacturerEKCertIndex(t, tpmImpl)

	before, err := tpmImpl.EKAttributes()
	require.NoError(t, err)
	_, err = tpmImpl.EKRSA()
	require.NoError(t, err)
	seedHierarchyCache(tpmImpl)

	require.NoError(t, tpmImpl.Clear(nil))
	assertHierarchyCacheDropped(t, tpmImpl)

	after, err := tpmImpl.EKAttributes()
	require.NoError(t, err)
	assert.NotSame(t, before, after, "EKAttributes must not return the pre-clear value")
	assert.Equal(t, tpm2.RSAEKTemplate, after.TPMAttributes.Template,
		"the re-derived EK attributes carry the TCG default creation template")
}

// TestClearForReprovision_PlatformClearDropsCache covers the PLATFORM
// fallback, which runs TPM2_Clear without going through Clear.
func TestClearForReprovision_PlatformClearDropsCache(t *testing.T) {
	_, tpm := createSim(t, false)
	t.Cleanup(func() { _ = tpm.Close() })
	tpmImpl, ok := tpm.(*TPM2)
	require.True(t, ok)

	// A lockout auth the empty-auth LOCKOUT attempt does not hold sends
	// ClearForReprovision to the PLATFORM hierarchy.
	_, err := tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHLockout, Auth: tpm2.PasswordAuth(nil)},
		NewAuth:    tpm2.TPM2BAuth{Buffer: []byte("lockout-auth")},
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)
	seedHierarchyCache(tpmImpl)

	rebootRequired, err := tpmImpl.ClearForReprovision()
	require.NoError(t, err)
	assert.False(t, rebootRequired)
	assertHierarchyCacheDropped(t, tpmImpl)
}
