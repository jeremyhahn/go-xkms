// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package services

import (
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper: create a TPMService with mock, temp dataDir, and a real
// StaticPasswordService backed by an in-memory store.
// ---------------------------------------------------------------------------

func TestSurgTPM_GetPlatformSRKInfo_ConfigFallback(t *testing.T) {
	mock := defaultMockTPM()
	mock.config.PlatformSRK = &xkms.PlatformSRKConfig{
		SRKHandle: 0x81800002,
	}
	mock.platformKeyStore = &mockPlatformKeyStorer{
		initialized:   false,
		policyEnabled: false,
		srkAttrs:      nil, // nil -> skip L1185 block entirely
	}
	svc := newServiceWithMock(mock)

	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	// Handle should come from config fallback (L1201).
	assert.Equal(t, "0x81800002", info.Handle)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// GetPlatformSRKInfo: SRKAttributes with TPMAttributes but ReadHandle fails
// Covers L1190-1193 where readErr != nil -> result.Present stays false.
// ---------------------------------------------------------------------------

func TestSurgTPM_GetPlatformSRKInfo_ReadHandleError(t *testing.T) {
	mock := defaultMockTPM()
	mock.readHandleErr = errors.New("handle not found")
	mock.platformKeyStore = &mockPlatformKeyStorer{
		initialized:   true,
		policyEnabled: false,
		srkAttrs: &xkms.KeyAttributes{
			KeyAlgorithm: 1, // RSA
			TPMAttributes: &xkms.TPMAttributes{
				Handle: 0x81800003,
			},
		},
	}
	svc := newServiceWithMock(mock)

	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	// Handle is set from SRKAttributes.
	assert.Equal(t, "0x81800003", info.Handle)
	// Present should be false because ReadHandle returned error (L1191).
	assert.False(t, info.Present)
	// But since PKS is initialized, Initialized should be true (L1206-1207).
	assert.True(t, info.Initialized)
}

// ---------------------------------------------------------------------------
// GetPlatformSRKInfo: SRKAttributes with no TPMAttributes -> handle empty,
// falls through to config.PlatformSRK fallback, and PKS not initialized.
// ---------------------------------------------------------------------------

func TestSurgTPM_ChangeOwnerAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ChangeOwnerAuth("oldpw", "newpw")
	require.NoError(t, err)
}

func TestSurgTPM_ChangeEndorsementAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ChangeEndorsementAuth("oldpw", "newpw")
	require.NoError(t, err)
}

func TestSurgTPM_ChangeLockoutAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ChangeLockoutAuth("oldpw", "newpw")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// GetVerificationStatus: exercises the delegation to VerifyTPM
// ---------------------------------------------------------------------------

func TestSurgTPM_GetVerificationStatus_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	status, err := svc.GetVerificationStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
}

// ---------------------------------------------------------------------------
// ListKeys: a TPM holding no persistent objects lists no keys
// ---------------------------------------------------------------------------

func TestSurgTPM_ListKeys_NoPersistentObjects(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	keys, err := svc.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestSurgTPM_GetPlatformSRKInfo_NoTPMAttrsNoConfig(t *testing.T) {
	mock := defaultMockTPM()
	mock.config.PlatformSRK = nil // no fallback config
	mock.platformKeyStore = &mockPlatformKeyStorer{
		initialized:   false,
		policyEnabled: false,
		srkAttrs: &xkms.KeyAttributes{
			KeyAlgorithm:  1,
			TPMAttributes: nil, // nil -> L1187 skipped
		},
	}
	svc := newServiceWithMock(mock)

	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Empty(t, info.Handle) // No handle from either source.
	assert.False(t, info.Present)
	assert.False(t, info.Initialized)
}

func TestSurgTPM_GetInfo_AlgoFallbackToConfig(t *testing.T) {
	mock := defaultMockTPM()
	mock.supportedAlgos = nil
	mock.supportedAlgosErr = errors.New("not supported")
	mock.config.Hash = "SHA-384" // Fallback value (L819).

	svc := newServiceWithMock(mock)

	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, []string{"SHA-384"}, info.Algorithms)
}
