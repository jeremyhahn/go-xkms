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
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper: create TPMService with temp dataDir and mock
// ---------------------------------------------------------------------------

func TestFT_ChangeOwnerAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = nil
	svc := newServiceWithMock(mock)
	err := svc.ChangeOwnerAuth("old", "new")
	require.NoError(t, err)
}

func TestFT_ChangeOwnerAuth_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = errors.New("auth change failed")
	svc := newServiceWithMock(mock)
	err := svc.ChangeOwnerAuth("old", "new")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth change failed")
}

func TestFT_ChangeOwnerAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeOwnerAuth("old", "new")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_ChangeEndorsementAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = nil
	svc := newServiceWithMock(mock)
	err := svc.ChangeEndorsementAuth("old", "new")
	require.NoError(t, err)
}

func TestFT_ChangeEndorsementAuth_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = errors.New("endorsement fail")
	svc := newServiceWithMock(mock)
	err := svc.ChangeEndorsementAuth("old", "new")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endorsement fail")
}

func TestFT_ChangeEndorsementAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeEndorsementAuth("old", "new")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_ChangeLockoutAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = nil
	svc := newServiceWithMock(mock)
	err := svc.ChangeLockoutAuth("old", "new")
	require.NoError(t, err)
}

func TestFT_ChangeLockoutAuth_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = errors.New("lockout fail")
	svc := newServiceWithMock(mock)
	err := svc.ChangeLockoutAuth("old", "new")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lockout fail")
}

func TestFT_ChangeLockoutAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeLockoutAuth("old", "new")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// changeHierarchyAuth with empty auth strings (nil Password paths)
func TestFT_ChangeHierarchyAuth_EmptyAuths(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = nil
	svc := newServiceWithMock(mock)
	// Both empty -> both passwords are nil
	err := svc.ChangeOwnerAuth("", "")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// GetVerificationStatus (60%) - delegates to VerifyTPM
// ---------------------------------------------------------------------------

func TestFT_GetVerificationStatus_NoTPM(t *testing.T) {
	svc := NewTPMService()
	status, err := svc.GetVerificationStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Verified)
}

func TestFT_GetVerificationStatus_WithTPM(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	status, err := svc.GetVerificationStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	// Without a trust store loaded, verification fails gracefully
	assert.False(t, status.Verified)
}

// ---------------------------------------------------------------------------
// ListPolicies (60%) - only defer is uncovered
// ---------------------------------------------------------------------------

func TestFT_GetEKECCInfo_CertPresent(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertEC = &testECCCertForEKECC
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)

	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.NotEmpty(t, info.Algorithm)
	assert.NotEmpty(t, info.Certificate)
}

func TestFT_GetEKECCInfo_NoCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertEC = nil
	mock.ekCertECErr = errors.New("not available")
	svc := newServiceWithMock(mock)

	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestFT_GetEKECCInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// Test certificate with ECDSA key for EKECCInfo
var testECCCertForEKECC = *testECCCert()

// ---------------------------------------------------------------------------
// DefineNVCounter (80%) - getTPM error path
// ---------------------------------------------------------------------------

func TestFT_DefineNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVCounter(0x01500000, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_DefineNVCounter_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvDefineCounterErr = nil
	svc := newServiceWithMock(mock)
	err := svc.DefineNVCounter(0x01500000, "owner-auth")
	require.NoError(t, err)
}

func TestFT_DefineNVCounter_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvDefineCounterErr = errors.New("counter define failed")
	svc := newServiceWithMock(mock)
	err := svc.DefineNVCounter(0x01500000, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "counter define failed")
}

// ---------------------------------------------------------------------------
// DefineNVExtend (80%) - getTPM error path
// ---------------------------------------------------------------------------

func TestFT_DefineNVExtend_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVExtend(0x01500001, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_DefineNVExtend_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvDefineExtendErr = nil
	svc := newServiceWithMock(mock)
	err := svc.DefineNVExtend(0x01500001, "owner-auth")
	require.NoError(t, err)
}

func TestFT_DefineNVExtend_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvDefineExtendErr = errors.New("extend define failed")
	svc := newServiceWithMock(mock)
	err := svc.DefineNVExtend(0x01500001, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extend define failed")
}

// ---------------------------------------------------------------------------
// IncrementNVCounter (80%) - getTPM error path
// ---------------------------------------------------------------------------

func TestFT_IncrementNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.IncrementNVCounter(0x01500000, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_IncrementNVCounter_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIncrementResult = 42
	mock.nvIncrementErr = nil
	svc := newServiceWithMock(mock)
	val, err := svc.IncrementNVCounter(0x01500000, "auth")
	require.NoError(t, err)
	assert.Equal(t, uint64(42), val)
}

func TestFT_IncrementNVCounter_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIncrementErr = errors.New("increment failed")
	svc := newServiceWithMock(mock)
	_, err := svc.IncrementNVCounter(0x01500000, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "increment failed")
}

// ---------------------------------------------------------------------------
// ReadNVCounter (80%) - getTPM error path
// ---------------------------------------------------------------------------

func TestFT_ReadNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ReadNVCounter(0x01500000, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_ReadNVCounter_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadCounterResult = 99
	mock.nvReadCounterErr = nil
	svc := newServiceWithMock(mock)
	val, err := svc.ReadNVCounter(0x01500000, "auth")
	require.NoError(t, err)
	assert.Equal(t, uint64(99), val)
}

func TestFT_ReadNVCounter_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadCounterErr = errors.New("counter read failed")
	svc := newServiceWithMock(mock)
	_, err := svc.ReadNVCounter(0x01500000, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "counter read failed")
}

// ---------------------------------------------------------------------------
// DeleteNVIndex (80%) - getTPM error path
// ---------------------------------------------------------------------------

func TestFT_DeleteNVIndex_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DeleteNVIndex(0x01500000, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_DeleteNVIndex_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvUndefineErr = nil
	svc := newServiceWithMock(mock)
	err := svc.DeleteNVIndex(0x01500000, "auth")
	require.NoError(t, err)
}

func TestFT_ListTransientHandles_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ListTransientHandles()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_ListTransientHandles_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.transientHandles = []tpm2.TPMHandle{0x80000001, 0x80000002}
	svc := newServiceWithMock(mock)
	result, err := svc.ListTransientHandles()
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, "0x80000001", result[0].Handle)
	assert.Equal(t, "transient", result[0].Type)
}

func TestFT_GetPlatformPolicy_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetPlatformPolicy()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ExportEKCert (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ExportEKCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ExportEKCert("pem")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ExportEKECCCert (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ExportEKECCCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ExportEKECCCert("pem")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ExportIAKCert (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ExportIAKCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ExportIAKCert("pem")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ExportIDevIDCert (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ExportIDevIDCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ExportIDevIDCert("pem")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ImportEKCert (85.7%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ImportEKCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	certPEM, _ := testCertPEM(t)
	err := svc.ImportEKCert(certPEM)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ImportEKECCCert (85.7%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ImportEKECCCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	certPEM, _ := testCertPEM(t)
	err := svc.ImportEKECCCert(certPEM)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ImportIAKCert (86.7%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ImportIAKCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	certPEM, _ := testCertPEM(t)
	err := svc.ImportIAKCert(certPEM)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ImportIDevIDCert (86.7%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ImportIDevIDCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	certPEM, _ := testCertPEM(t)
	err := svc.ImportIDevIDCert(certPEM)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// GetLockoutInfo (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_GetLockoutInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetLockoutInfo()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ResetLockout (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ResetLockout_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ResetLockout("")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ForceResetLockout (83.3%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_ForceResetLockout_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ForceResetLockout("")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// GetNVSummary (89.5%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_GetSharedSRKInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetSharedSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestFT_GetSharedSRKInfo_SSRKAttrsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.ssrkAttrsErr = errors.New("no srk")
	mock.ssrkAttrs = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetSharedSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// GetIAKInfo (86.4%) - cover cert present
// ---------------------------------------------------------------------------

func TestFT_GetIAKInfo_WithCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.iakAttrs = &xkms.KeyAttributes{
		KeyAlgorithm: 1, // RSA
		RSAAttributes: &xkms.RSAAttributes{
			KeySize: 2048,
		},
		TPMAttributes: &xkms.TPMAttributes{
			Handle: 0x81020001,
		},
	}
	mock.iakAttrsErr = nil
	mock.iakCert = testCert()
	mock.iakCertErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.NotEmpty(t, info.Handle)
	assert.NotEmpty(t, info.Certificate)
}

func TestFT_GetIAKInfo_AttrsNil(t *testing.T) {
	mock := defaultMockTPM()
	mock.iakAttrs = nil
	mock.iakAttrsErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// GetIDevIDInfo (85.7%) - cover no TPM, attrs nil
// ---------------------------------------------------------------------------

func TestFT_GetIDevIDInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestFT_GetIDevIDInfo_AttrsNil(t *testing.T) {
	mock := defaultMockTPM()
	mock.idevidAttrs = nil
	mock.idevidAttrsErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// InitializePlatformKeyStore (83.3%) - no TPM path + pks nil
// ---------------------------------------------------------------------------

func TestFT_InitializePlatformKeyStore_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.InitializePlatformKeyStore("so", "user")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_InitializePlatformKeyStore_NilPKS(t *testing.T) {
	mock := defaultMockTPM()
	mock.platformKeyStore = nil
	svc := newServiceWithMock(mock)
	err := svc.InitializePlatformKeyStore("so", "user")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "platform key store not configured")
}

// ---------------------------------------------------------------------------
// InitializePlatformKeyStoreWithDefaults (83.3%) - no TPM path + pks nil
// ---------------------------------------------------------------------------

func TestFT_InitializePlatformKeyStoreWithDefaults_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.InitializePlatformKeyStoreWithDefaults()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_InitializePlatformKeyStoreWithDefaults_NilPKS(t *testing.T) {
	mock := defaultMockTPM()
	mock.platformKeyStore = nil
	svc := newServiceWithMock(mock)
	err := svc.InitializePlatformKeyStoreWithDefaults()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "platform key store not configured")
}

// ---------------------------------------------------------------------------
// FactoryReset (85.7%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_FactoryReset_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.FactoryReset("")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// saveHandleDescriptions (88.9%) - dataDir not set
// ---------------------------------------------------------------------------

func TestFT_SaveHandleDescriptions_NoDataDir(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	// No dataDir set
	err := svc.saveHandleDescriptions(map[string]string{"0x81000001": "test"})
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// ---------------------------------------------------------------------------
// GetPCRs (92.3%) - cover no TPM
// ---------------------------------------------------------------------------

func TestFT_GetPCRs_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetPCRs("sha256")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// GetEventLog (88.9%) - no TPM path
// ---------------------------------------------------------------------------

func TestFT_GetEventLog_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetEventLog()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ============================================================================
// PLATFORM POLICY SERVICE TESTS
// ============================================================================

// ---------------------------------------------------------------------------
// GetStatus (70%) - configured but TPM unavailable for verify
// ---------------------------------------------------------------------------

func TestFT_GetPlatformSRKInfo_NoPKS(t *testing.T) {
	mock := defaultMockTPM()
	mock.platformKeyStore = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestFT_GetPlatformSRKInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestFT_GetPlatformSRKInfo_WithPKS(t *testing.T) {
	mock := defaultMockTPM()
	mock.platformKeyStore = &mockPlatformKeyStorer{
		initialized:   true,
		policyEnabled: true,
		srkAttrs: &xkms.KeyAttributes{
			KeyAlgorithm: 1, // RSA
			TPMAttributes: &xkms.TPMAttributes{
				Handle: 0x81800001,
			},
		},
	}
	svc := newServiceWithMock(mock)
	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.True(t, info.PolicyEnabled)
	assert.True(t, info.Initialized)
}

// ---------------------------------------------------------------------------
// GetEKECCInfo with nil cert (not error but nil)
// ---------------------------------------------------------------------------

func TestFT_GetEKECCInfo_NilCertNoError(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertEC = nil
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// IDevIDInfo with cert
// ---------------------------------------------------------------------------

func TestFT_GetIDevIDInfo_WithCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.idevidAttrs = &xkms.KeyAttributes{
		KeyAlgorithm: 3, // ECDSA
		ECCAttributes: &xkms.ECCAttributes{
			Curve: elliptic.P256(),
		},
		TPMAttributes: &xkms.TPMAttributes{
			Handle: 0x81020000,
		},
	}
	mock.idevidAttrsErr = nil
	mock.idevidCert = &testIDevIDCertInstance
	mock.idevidCertErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.NotEmpty(t, info.Certificate)
}

var testIDevIDCertInstance = *testECCCert()

// ---------------------------------------------------------------------------
// ExtendNV (86.7%) - cover invalid hex, empty data
// ---------------------------------------------------------------------------

func TestFT_ExtendNV_InvalidHex(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ExtendNV(0x01500000, "NOT_VALID_HEX$$", "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestFT_ExtendNV_EmptyData(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ExtendNV(0x01500000, "", "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestFT_ExtendNV_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ExtendNV(0x01500000, "aabbccdd", "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ReadNVExtend (84.6%) - no TPM, success, error
// ---------------------------------------------------------------------------

func TestFT_ReadNVExtend_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ReadNVExtend(0x01500000, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_ReadNVExtend_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadExtendResult = []byte{0xDE, 0xAD}
	mock.nvReadExtendErr = nil
	svc := newServiceWithMock(mock)
	result, err := svc.ReadNVExtend(0x01500000, "")
	require.NoError(t, err)
	assert.Equal(t, "dead", result)
}

func TestFT_ReadNVExtend_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadExtendErr = errors.New("extend read fail")
	svc := newServiceWithMock(mock)
	_, err := svc.ReadNVExtend(0x01500000, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extend read fail")
}

// ---------------------------------------------------------------------------
// DefineNVOrdinary (84.6%) - invalid size
// ---------------------------------------------------------------------------

func TestFT_DefineNVOrdinary_InvalidSizeZero(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.DefineNVOrdinary(0x01500000, 0, "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
}

func TestFT_DefineNVOrdinary_InvalidSizeTooLarge(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.DefineNVOrdinary(0x01500000, 3000, "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
}

func TestFT_DefineNVOrdinary_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVOrdinary(0x01500000, 64, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// Provision (88.9%) - nil opts, invalid mode
// ---------------------------------------------------------------------------

func TestFT_Provision_NilOpts(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.Provision(nil)
	assert.ErrorIs(t, err, ErrTPMProvisionFailed)
}

func TestFT_Provision_InvalidMode(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.Provision(&ProvisionOptions{Mode: "invalid_mode"})
	assert.ErrorIs(t, err, ErrTPMInvalidProvisionMode)
}

func TestFT_Provision_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.Provision(&ProvisionOptions{Mode: "install"})
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// Install (87.5%) - no TPM, auth error
// ---------------------------------------------------------------------------

func TestFT_Install_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.Install("auth")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_Install_EmptyAuth(t *testing.T) {
	mock := defaultMockTPM()
	mock.installErr = nil
	svc := newServiceWithMock(mock)
	err := svc.Install("")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// WriteNVData (87.5%) - no TPM
// ---------------------------------------------------------------------------

func TestFT_WriteNVData_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.WriteNVData(0x01500000, "deadbeef", "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ReadNVData (90.9%) - no TPM
// ---------------------------------------------------------------------------

func TestFT_IsTPMAuthError_StringBased(t *testing.T) {
	assert.True(t, isTPMAuthError(errors.New("some AUTH_FAIL occurred")))
	assert.True(t, isTPMAuthError(errors.New("bad_auth detected")))
	assert.False(t, isTPMAuthError(errors.New("some random error")))
	assert.False(t, isTPMAuthError(nil))
}

// ---------------------------------------------------------------------------
// GetEKInfo with cert (covers certAlgorithmName, certKeySize branches)
// ---------------------------------------------------------------------------

func TestFT_GetEKInfo_WithECDSACert(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testECCCert()
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetEKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.NotEmpty(t, info.Certificate)
}

// ---------------------------------------------------------------------------
// GatherTPMInfo with FIPS error (fipsErr branch in GetInfo)
// ---------------------------------------------------------------------------

func TestFT_GetInfo_FIPSError(t *testing.T) {
	mock := defaultMockTPM()
	mock.fipsErr = errors.New("not supported")
	svc := newServiceWithMock(mock)
	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	// FIPS error is logged but doesn't cause failure
	assert.False(t, info.FIPSMode)
}

// ---------------------------------------------------------------------------
// GetInfo - fixedProperties error branch
// ---------------------------------------------------------------------------

func TestFT_GetInfo_FixedPropsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedPropsErr = errors.New("capability error")
	mock.fixedProps = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Empty(t, info.Manufacturer)
}

// ---------------------------------------------------------------------------
// GetInfo - no TPM
// ---------------------------------------------------------------------------

func TestFT_GetInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Empty(t, info.Manufacturer)
}

// ---------------------------------------------------------------------------
// GetEKECCInfo with ECC public key in cert
// ---------------------------------------------------------------------------

func TestFT_GetEKECCInfo_ECCSAKeyInCert(t *testing.T) {
	mock := defaultMockTPM()
	cert := testECCCert()
	cert.PublicKey = &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     big.NewInt(100), //nolint:staticcheck // synthetic test fixture; a fixed non-curve point is the input under test and a validating constructor would refuse to build it.
		Y:     big.NewInt(200), //nolint:staticcheck // synthetic test fixture; a fixed non-curve point is the input under test and a validating constructor would refuse to build it.
	}
	mock.ekCertEC = cert
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Present)
	assert.Equal(t, 384, info.KeySize)
}

func TestFT_DeleteNVIndex_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvUndefineErr = errors.New("undefine failed")
	svc := newServiceWithMock(mock)
	err := svc.DeleteNVIndex(0x01500000, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "undefine failed")
}

func TestFT_ListTransientHandles_TPMError(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedPropsErr = errors.New("transient list failed")
	mock.fixedProps = nil
	svc := newServiceWithMock(mock)
	_, err := svc.ListTransientHandles()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transient list failed")
}

func TestFT_GetNVSummary_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetNVSummary()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFT_ReadNVData_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ReadNVData(0x01500000, 64, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ftCreateService returns a TPMService over mock with a temporary data
// directory.
func ftCreateService(t *testing.T, mock *mockTPM) (*TPMService, string) {
	t.Helper()
	svc := newServiceWithMock(mock)
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)
	return svc, dataDir
}
