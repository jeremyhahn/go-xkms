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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock infrastructure with unique prefix "tf" to avoid conflicts.
// ---------------------------------------------------------------------------

func TestTF_SaveHandleDescriptions_WriteError(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir("/nonexistent/path")
	err := svc.saveHandleDescriptions(map[string]string{"0x81000001": "SRK"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMHandleDescriptionFailed)
}

// TestTF_ListKeys_NoPersistentObjects: the mock reports no persistent
// handles, so the TPM holds no keys to list.
func TestTF_ListKeys_NoPersistentObjects(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	keys, err := svc.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestTF_ReplayEventLog_NoTPM(t *testing.T) {
	svc := NewTPMService()
	result, err := svc.ReplayEventLog()
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ReplayEventLog_NoEventLog(t *testing.T) {
	mock := defaultMockTPM()
	mock.parsedEventsErr = errors.New("no event log")
	svc := newServiceWithMock(mock)
	result, err := svc.ReplayEventLog()
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMEventLogNotFound)
}

func TestTF_GenerateIDevIDCSR_NoTPM(t *testing.T) {
	svc := NewTPMService()
	result, err := svc.GenerateIDevIDCSR()
	assert.Empty(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_GenerateIDevIDCSR_NoEKCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertErr = errors.New("no EK cert")
	svc := newServiceWithMock(mock)
	result, err := svc.GenerateIDevIDCSR()
	assert.Empty(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EK certificate")
}

func TestTF_ChangeOwnerAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeOwnerAuth("old", "new")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ChangeEndorsementAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeEndorsementAuth("old", "new")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ChangeLockoutAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeLockoutAuth("old", "new")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_DefineNVOrdinary_InvalidSize(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.DefineNVOrdinary(0x01800001, 0, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
	err = svc.DefineNVOrdinary(0x01800001, 3000, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
}

func TestTF_DefineNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVCounter(0x01800001, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_DefineNVExtend_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVExtend(0x01800001, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ReadNVData_NoTPM(t *testing.T) {
	svc := NewTPMService()
	result, err := svc.ReadNVData(0x01800001, 0, "")
	assert.Empty(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_WriteNVData_InvalidHex(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.WriteNVData(0x01800001, "not-hex!", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestTF_WriteNVData_EmptyData(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.WriteNVData(0x01800001, "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestTF_ExtendNV_InvalidHex(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.ExtendNV(0x01800001, "zzzz", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestTF_ExtendNV_EmptyData(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.ExtendNV(0x01800001, "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestTF_IncrementNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	val, err := svc.IncrementNVCounter(0x01800001, "")
	assert.Zero(t, val)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ReadNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	val, err := svc.ReadNVCounter(0x01800001, "")
	assert.Zero(t, val)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ReadNVExtend_NoTPM(t *testing.T) {
	svc := NewTPMService()
	result, err := svc.ReadNVExtend(0x01800001, "")
	assert.Empty(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_DeleteNVIndex_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DeleteNVIndex(0x01800001, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTF_ImportManufacturerCA_InvalidPEM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ImportManufacturerCA("not a PEM")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidCACert)
}

func TestTF_VerifyTPM_NoTPM(t *testing.T) {
	svc := NewTPMService()
	status, err := svc.VerifyTPM()
	require.NoError(t, err)
	assert.False(t, status.Verified)
	assert.Contains(t, status.ErrorMessage, "not available")
}

func TestTF_GetVerificationStatus_NoTPM(t *testing.T) {
	svc := NewTPMService()
	status, err := svc.GetVerificationStatus()
	require.NoError(t, err)
	assert.False(t, status.Verified)
}

func TestTF_ParseCertificate_InvalidPEM(t *testing.T) {
	svc := NewTPMService()
	result, err := svc.ParseCertificate("not a cert")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}
