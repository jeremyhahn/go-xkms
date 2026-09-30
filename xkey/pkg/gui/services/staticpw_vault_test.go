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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

var errVaultServer = errors.New("vault: credential rejected")

func enrolledFactorResponse(recoveryCode string) *transport.PasswordVaultEnrollResponse {
	return &transport.PasswordVaultEnrollResponse{
		Factor: transport.PasswordVaultFactor{
			ID: "f-1", Factor: "passphrase", Label: "laptop", CreatedAt: "2026-09-30T00:00:00Z",
			CredentialID: []byte{0x01},
		},
		RecoveryCode: recoveryCode,
	}
}

func TestStaticPasswordService_SetClientNilDetaches(t *testing.T) {
	svc, _ := newTestStaticPWServiceWithClient(t)

	svc.SetClient(nil)

	_, err := svc.VaultStatus()
	assert.ErrorIs(t, err, ErrStaticPWNoClient, "a detached service must report no client, not dereference nil")
}

func TestStaticPasswordService_VaultStatus(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	mock.vaultStatusResp = &transport.PasswordVaultStatusResponse{
		Initialized: true,
		Unlocked:    false,
		Factors: []transport.PasswordVaultFactor{
			{ID: "f-1", Factor: "passphrase", Label: "laptop", CreatedAt: "2026-09-30T00:00:00Z"},
			{ID: "f-2", Factor: "passkey", Label: "yubikey", PRFSalt: make([]byte, 32)},
		},
	}

	status, err := svc.VaultStatus()
	require.NoError(t, err)
	assert.True(t, status.Initialized)
	assert.False(t, status.Unlocked)
	assert.Equal(t, []PasswordVaultFactor{
		{ID: "f-1", Factor: "passphrase", Label: "laptop", CreatedAt: "2026-09-30T00:00:00Z"},
		{ID: "f-2", Factor: "passkey", Label: "yubikey"},
	}, status.Factors)
}

func TestStaticPasswordService_VaultStatus_Errors(t *testing.T) {
	t.Run("no client", func(t *testing.T) {
		svc := NewStaticPasswordService(nil)
		_, err := svc.VaultStatus()
		assert.ErrorIs(t, err, ErrStaticPWNoClient)
	})
	t.Run("server error", func(t *testing.T) {
		svc, mock := newTestStaticPWServiceWithClient(t)
		mock.vaultStatusErr = errVaultServer
		_, err := svc.VaultStatus()
		assert.ErrorIs(t, err, errVaultServer)
	})
}

func TestStaticPasswordService_EnrollPassphrase(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	mock.vaultEnrollResp = enrolledFactorResponse("ABCD-EFGH")
	rec := &spwRecordingAuditLogger{}
	svc.SetAuditLogger(rec)

	result, err := svc.EnrollPassphrase("correct horse", "laptop")
	require.NoError(t, err)
	require.NotNil(t, mock.lastEnrollReq)
	assert.Equal(t, "passphrase", mock.lastEnrollReq.Factor)
	assert.Equal(t, "correct horse", mock.lastEnrollReq.Passphrase)
	assert.Equal(t, "laptop", mock.lastEnrollReq.Label)
	assert.Equal(t, "f-1", result.Factor.ID)
	assert.Equal(t, "ABCD-EFGH", result.RecoveryCode)
	assert.Equal(t, audit.OpPasswordVaultFactorEnrolled, rec.last().Operation)
	assert.True(t, rec.last().Success)
}

func TestStaticPasswordService_EnrollPassphrase_Errors(t *testing.T) {
	t.Run("empty passphrase", func(t *testing.T) {
		svc, mock := newTestStaticPWServiceWithClient(t)
		_, err := svc.EnrollPassphrase("", "laptop")
		assert.ErrorIs(t, err, ErrStaticPWPassphraseRequired)
		assert.Nil(t, mock.lastEnrollReq)
	})
	t.Run("server error is audited as a failure", func(t *testing.T) {
		svc, mock := newTestStaticPWServiceWithClient(t)
		mock.vaultEnrollErr = errVaultServer
		rec := &spwRecordingAuditLogger{}
		svc.SetAuditLogger(rec)
		_, err := svc.EnrollPassphrase("correct horse", "")
		assert.ErrorIs(t, err, errVaultServer)
		assert.Equal(t, audit.OpPasswordVaultFactorEnrolled, rec.last().Operation)
		assert.False(t, rec.last().Success)
	})
	t.Run("audit write failure fails the operation", func(t *testing.T) {
		svc, mock := newTestStaticPWServiceWithClient(t)
		mock.vaultEnrollResp = enrolledFactorResponse("ABCD-EFGH")
		svc.SetAuditLogger(&spwRecordingAuditLogger{logErr: errors.New("audit backend unavailable")})
		result, err := svc.EnrollPassphrase("correct horse", "")
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestStaticPasswordService_RotatePassphrase(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	mock.vaultEnrollResp = enrolledFactorResponse("")
	rec := &spwRecordingAuditLogger{}
	svc.SetAuditLogger(rec)

	result, err := svc.RotatePassphrase("f-0", "new phrase", "laptop")
	require.NoError(t, err)
	require.NotNil(t, mock.lastRotateReq)
	assert.Equal(t, "f-0", mock.lastRotateReq.FactorID)
	assert.Equal(t, "new phrase", mock.lastRotateReq.Passphrase)
	assert.Equal(t, "laptop", mock.lastRotateReq.Label)
	assert.Empty(t, result.RecoveryCode)
	assert.Equal(t, audit.OpPasswordVaultFactorRotated, rec.last().Operation)
}

func TestStaticPasswordService_RotatePassphrase_Errors(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	_, err := svc.RotatePassphrase("", "new phrase", "")
	assert.ErrorIs(t, err, ErrStaticPWFactorIDRequired)
	_, err = svc.RotatePassphrase("f-0", "", "")
	assert.ErrorIs(t, err, ErrStaticPWPassphraseRequired)
	assert.Nil(t, mock.lastRotateReq)

	mock.vaultEnrollErr = errVaultServer
	_, err = svc.RotatePassphrase("f-0", "new phrase", "")
	assert.ErrorIs(t, err, errVaultServer)
}

func TestStaticPasswordService_RemoveVaultFactor(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	rec := &spwRecordingAuditLogger{}
	svc.SetAuditLogger(rec)

	require.NoError(t, svc.RemoveVaultFactor("f-2"))
	require.NotNil(t, mock.lastRemoveReq)
	assert.Equal(t, "f-2", mock.lastRemoveReq.FactorID)
	assert.Equal(t, audit.OpPasswordVaultFactorRemoved, rec.last().Operation)
	assert.True(t, rec.last().Success)
}

func TestStaticPasswordService_RemoveVaultFactor_Errors(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	assert.ErrorIs(t, svc.RemoveVaultFactor(""), ErrStaticPWFactorIDRequired)
	assert.Nil(t, mock.lastRemoveReq)

	mock.vaultRemoveErr = errVaultServer
	assert.ErrorIs(t, svc.RemoveVaultFactor("f-2"), errVaultServer)

	detached := NewStaticPasswordService(nil)
	assert.ErrorIs(t, detached.RemoveVaultFactor("f-2"), ErrStaticPWNoClient)
}

func TestStaticPasswordService_RecoverWithPassphrase(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	mock.vaultEnrollResp = enrolledFactorResponse("NEW-CODE")
	rec := &spwRecordingAuditLogger{}
	svc.SetAuditLogger(rec)

	result, err := svc.RecoverWithPassphrase("OLD-CODE", "fresh phrase", "desktop")
	require.NoError(t, err)
	require.NotNil(t, mock.lastRecoverReq)
	assert.Equal(t, "OLD-CODE", mock.lastRecoverReq.RecoveryCode)
	assert.Equal(t, "fresh phrase", mock.lastRecoverReq.Passphrase)
	assert.Equal(t, "desktop", mock.lastRecoverReq.Label)
	assert.Equal(t, "NEW-CODE", result.RecoveryCode)
	assert.Equal(t, audit.OpPasswordVaultRecovered, rec.last().Operation)
}

func TestStaticPasswordService_RecoverWithPassphrase_Errors(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	_, err := svc.RecoverWithPassphrase("", "fresh phrase", "")
	assert.ErrorIs(t, err, ErrStaticPWRecoveryCodeRequired)
	_, err = svc.RecoverWithPassphrase("OLD-CODE", "", "")
	assert.ErrorIs(t, err, ErrStaticPWPassphraseRequired)
	assert.Nil(t, mock.lastRecoverReq)

	mock.vaultEnrollErr = errVaultServer
	_, err = svc.RecoverWithPassphrase("OLD-CODE", "fresh phrase", "")
	assert.ErrorIs(t, err, errVaultServer)

	detached := NewStaticPasswordService(nil)
	detached.SetContext(context.Background())
	_, err = detached.RecoverWithPassphrase("OLD-CODE", "fresh phrase", "")
	assert.ErrorIs(t, err, ErrStaticPWNoClient)
}
