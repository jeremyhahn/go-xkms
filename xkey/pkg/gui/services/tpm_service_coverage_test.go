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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock audit logger for testing SetAuditLogger and logTPMOperation.
// ---------------------------------------------------------------------------

type mockAuditLogger struct {
	tpmOps []mockTPMOp
}

type mockTPMOp struct {
	op      audit.OperationType
	success bool
	err     error
	details map[string]any
}

func (m *mockAuditLogger) Log(_ audit.Entry) error { return nil }
func (m *mockAuditLogger) LogKeyOperation(_ audit.OperationType, _, _ string, _ bool, _ error, _ int64) error {
	return nil
}
func (m *mockAuditLogger) LogCryptoOperation(_ audit.OperationType, _, _, _, _ string, _ bool, _ error, _ int64) error {
	return nil
}
func (m *mockAuditLogger) LogConnectionEvent(_ audit.OperationType, _, _ string, _ map[string]any) error {
	return nil
}
func (m *mockAuditLogger) LogServiceEvent(_ audit.OperationType, _ map[string]any) error { return nil }
func (m *mockAuditLogger) LogPINOperation(_ audit.OperationType, _ string, _ bool, _ error, _ map[string]any) error {
	return nil
}
func (m *mockAuditLogger) LogTPMOperation(op audit.OperationType, success bool, err error, details map[string]any) error {
	m.tpmOps = append(m.tpmOps, mockTPMOp{
		op:      op,
		success: success,
		err:     err,
		details: details,
	})
	return nil
}
func (m *mockAuditLogger) LogPasswordStoreOperation(_ audit.OperationType, _ string, _ bool, _ error, _ map[string]any) error {
	return nil
}
func (m *mockAuditLogger) LogUserPresenceEvent(_ audit.OperationType, _ string, _ bool, _ map[string]any) error {
	return nil
}

var _ audit.Logger = (*mockAuditLogger)(nil)

// ---------------------------------------------------------------------------
// mockTPMWithClear extends mockTPM to support Clear without panicking.
// ---------------------------------------------------------------------------

type mockTPMWithClear struct {
	*mockTPM
	clearErr error
}

func (m *mockTPMWithClear) Clear(_ []byte) error {
	return m.clearErr
}

// ---------------------------------------------------------------------------
// Helper: create a TPMService wired to a mock TPM.
// ---------------------------------------------------------------------------

func newCoverageTPMService(tpm xkms.TrustedPlatformModule) *TPMService {
	svc := NewTPMService()
	svc.SetContext(context.Background())
	if tpm != nil {
		accessor := NewTPMAccessor(func() xkms.TrustedPlatformModule { return tpm })
		svc.SetTPMAccessor(accessor)
	}
	return svc
}

// ---------------------------------------------------------------------------
// Test: SetAuditLogger
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_SetAuditLogger(t *testing.T) {
	svc := NewTPMService()

	t.Run("stores_audit_logger", func(t *testing.T) {
		logger := &mockAuditLogger{}
		svc.SetAuditLogger(logger)

		// Verify it was stored by loading it back.
		ptr := svc.auditLog.Load()
		require.NotNil(t, ptr)
		assert.Equal(t, logger, *ptr)
	})
}

// ---------------------------------------------------------------------------
// Test: logTPMOperation with and without audit logger.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_logTPMOperation(t *testing.T) {
	t.Run("nil_audit_logger_does_not_panic", func(t *testing.T) {
		svc := NewTPMService()
		// No audit logger set -- should be a no-op.
		svc.logTPMOperation(audit.OpTPMProvisioned, true, nil, nil)
	})

	t.Run("logs_to_audit_logger", func(t *testing.T) {
		svc := NewTPMService()
		logger := &mockAuditLogger{}
		svc.SetAuditLogger(logger)

		details := map[string]any{"mode": "install"}
		svc.logTPMOperation(audit.OpTPMProvisioned, true, nil, details)

		require.Len(t, logger.tpmOps, 1)
		assert.Equal(t, audit.OpTPMProvisioned, logger.tpmOps[0].op)
		assert.True(t, logger.tpmOps[0].success)
		assert.Nil(t, logger.tpmOps[0].err)
		assert.Equal(t, "install", logger.tpmOps[0].details["mode"])
	})

	t.Run("logs_error_to_audit_logger", func(t *testing.T) {
		svc := NewTPMService()
		logger := &mockAuditLogger{}
		svc.SetAuditLogger(logger)

		testErr := errors.New("test error")
		svc.logTPMOperation(audit.OpTPMAuthFailed, false, testErr, nil)

		require.Len(t, logger.tpmOps, 1)
		assert.Equal(t, audit.OpTPMAuthFailed, logger.tpmOps[0].op)
		assert.False(t, logger.tpmOps[0].success)
		assert.Equal(t, testErr, logger.tpmOps[0].err)
	})
}

// ---------------------------------------------------------------------------
// Test: ClearTPM
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ClearTPM(t *testing.T) {
	t.Run("nil_request_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.ClearTPM(nil)
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil clear request")
		assert.True(t, errors.Is(err, ErrTPMNilClearRequest))
	})

	t.Run("force_flag_delegates_to_ForceClearTPM", func(t *testing.T) {
		svc := NewTPMService()
		req := &TPMClearRequest{Force: true, SudoPassword: "fake"}
		result, err := svc.ClearTPM(req)
		// ForceClearTPM will check sudo availability which should fail in test env.
		assert.NotNil(t, result)
		assert.Error(t, err)
		assert.False(t, result.Success)
	})

	t.Run("no_tpm_accessor_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		req := &TPMClearRequest{LockoutAuth: "test"}
		result, err := svc.ClearTPM(req)
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTPMClearFailed)
	})

	t.Run("clear_success", func(t *testing.T) {
		mock := &mockTPMWithClear{
			mockTPM:  defaultMockTPM(),
			clearErr: nil,
		}
		svc := newCoverageTPMService(mock)
		req := &TPMClearRequest{LockoutAuth: "test123"}
		result, err := svc.ClearTPM(req)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Contains(t, result.Message, "cleared successfully")
	})

	t.Run("clear_generic_error", func(t *testing.T) {
		mock := &mockTPMWithClear{
			mockTPM:  defaultMockTPM(),
			clearErr: errors.New("clear failed"),
		}
		svc := newCoverageTPMService(mock)
		req := &TPMClearRequest{LockoutAuth: "bad"}
		result, err := svc.ClearTPM(req)
		assert.ErrorIs(t, err, ErrTPMClearFailed)
		require.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "clear failed")
	})

	t.Run("clear_auth_error", func(t *testing.T) {
		// Simulate a TPM auth error using a string-based fallback.
		mock := &mockTPMWithClear{
			mockTPM:  defaultMockTPM(),
			clearErr: errors.New("tpm: auth_fail: bad authorization"),
		}
		svc := newCoverageTPMService(mock)
		req := &TPMClearRequest{LockoutAuth: "wrong"}
		result, err := svc.ClearTPM(req)
		assert.ErrorIs(t, err, ErrTPMClearFailed)
		require.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "incorrect lockout authorization")
	})
}

// ---------------------------------------------------------------------------
// Test: ForceClearTPM
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ForceClearTPM(t *testing.T) {
	t.Run("nil_request_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.ForceClearTPM(nil)
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil clear request")
		assert.True(t, errors.Is(err, ErrTPMNilClearRequest))
	})

	t.Run("sudo_unavailable", func(t *testing.T) {
		svc := NewTPMService()
		// With an empty password, the sudo elevator should report unavailable
		// on systems where sudo is not accessible in tests.
		req := &TPMClearRequest{SudoPassword: ""}
		result, err := svc.ForceClearTPM(req)
		// On test environments without sudo, this should fail with ErrSudoUnavailable
		// or proceed to attempt the command and fail.
		assert.NotNil(t, result)
		assert.Error(t, err)
		assert.False(t, result.Success)
	})
}

// ---------------------------------------------------------------------------
// Test: hierarchyHandleToName coverage for platform and default cases.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_hierarchyHandleToName(t *testing.T) {
	svc := NewTPMService()

	t.Run("owner", func(t *testing.T) {
		assert.Equal(t, "owner", svc.hierarchyHandleToName(tpm2.TPMRHOwner))
	})

	t.Run("endorsement", func(t *testing.T) {
		assert.Equal(t, "endorsement", svc.hierarchyHandleToName(tpm2.TPMRHEndorsement))
	})

	t.Run("platform", func(t *testing.T) {
		assert.Equal(t, "platform", svc.hierarchyHandleToName(tpm2.TPMRHPlatform))
	})

	t.Run("lockout", func(t *testing.T) {
		assert.Equal(t, "lockout", svc.hierarchyHandleToName(tpm2.TPMRHLockout))
	})

	t.Run("unknown_handle_returns_hex", func(t *testing.T) {
		result := svc.hierarchyHandleToName(tpm2.TPMHandle(0x12345678))
		assert.Contains(t, result, "12345678")
	})
}

// ---------------------------------------------------------------------------
// Test: GetVerificationStatus (delegates to VerifyTPM).
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_GetVerificationStatus(t *testing.T) {
	t.Run("no_tpm_returns_unverified", func(t *testing.T) {
		svc := NewTPMService()
		status, err := svc.GetVerificationStatus()
		require.NoError(t, err)
		require.NotNil(t, status)
		assert.False(t, status.Verified)
	})

	t.Run("with_tpm_no_certs_returns_unverified", func(t *testing.T) {
		mock := defaultMockTPM()
		svc := newCoverageTPMService(mock)
		status, err := svc.GetVerificationStatus()
		require.NoError(t, err)
		require.NotNil(t, status)
		assert.False(t, status.Verified)
	})
}

// ---------------------------------------------------------------------------
// Test: ListPolicies panic recovery path.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ChangeAuthPanicRecovery(t *testing.T) {
	// These tests hit the panic recovery defer in Change*Auth methods (60% -> higher).
	// Without a TPM accessor, getTPM returns an error before any TPM interaction.

	t.Run("ChangeOwnerAuth_no_tpm", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.ChangeOwnerAuth("old", "new")
		assert.ErrorIs(t, err, ErrTPMNotAvailable)
	})

	t.Run("ChangeEndorsementAuth_no_tpm", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.ChangeEndorsementAuth("old", "new")
		assert.ErrorIs(t, err, ErrTPMNotAvailable)
	})

	t.Run("ChangeLockoutAuth_no_tpm", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.ChangeLockoutAuth("old", "new")
		assert.ErrorIs(t, err, ErrTPMNotAvailable)
	})

	t.Run("ChangeOwnerAuth_success", func(t *testing.T) {
		mock := defaultMockTPM()
		mock.setHierarchyAuthErr = nil
		svc := newCoverageTPMService(mock)

		err := svc.ChangeOwnerAuth("", "newpass")
		assert.NoError(t, err)
	})

	t.Run("ChangeEndorsementAuth_success", func(t *testing.T) {
		mock := defaultMockTPM()
		mock.setHierarchyAuthErr = nil
		svc := newCoverageTPMService(mock)

		err := svc.ChangeEndorsementAuth("", "newpass")
		assert.NoError(t, err)
	})

	t.Run("ChangeLockoutAuth_success", func(t *testing.T) {
		mock := defaultMockTPM()
		mock.setHierarchyAuthErr = nil
		svc := newCoverageTPMService(mock)

		err := svc.ChangeLockoutAuth("", "newpass")
		assert.NoError(t, err)
	})

	t.Run("ChangeOwnerAuth_auth_error", func(t *testing.T) {
		mock := defaultMockTPM()
		mock.setHierarchyAuthErr = errors.New("bad_auth: authorization failed")
		svc := newCoverageTPMService(mock)

		err := svc.ChangeOwnerAuth("wrong", "new")
		assert.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// Test: ChangeHierarchyAuth with audit logging.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ChangeHierarchyAuth_AuditLog(t *testing.T) {
	t.Run("success_logs_to_audit", func(t *testing.T) {
		mock := defaultMockTPM()
		mock.setHierarchyAuthErr = nil
		svc := newCoverageTPMService(mock)
		logger := &mockAuditLogger{}
		svc.SetAuditLogger(logger)

		err := svc.ChangeOwnerAuth("old", "new")
		require.NoError(t, err)

		require.Len(t, logger.tpmOps, 1)
		assert.Equal(t, audit.OpTPMHierarchyChanged, logger.tpmOps[0].op)
		assert.True(t, logger.tpmOps[0].success)
	})

	t.Run("failure_logs_to_audit", func(t *testing.T) {
		mock := defaultMockTPM()
		mock.setHierarchyAuthErr = errors.New("some error")
		svc := newCoverageTPMService(mock)
		logger := &mockAuditLogger{}
		svc.SetAuditLogger(logger)

		err := svc.ChangeOwnerAuth("old", "new")
		assert.Error(t, err)

		require.Len(t, logger.tpmOps, 1)
		assert.Equal(t, audit.OpTPMHierarchyChanged, logger.tpmOps[0].op)
		assert.False(t, logger.tpmOps[0].success)
	})

	t.Run("auth_error_logs_auth_failed", func(t *testing.T) {
		mock := defaultMockTPM()
		mock.setHierarchyAuthErr = errors.New("tpm: auth_fail: bad authorization")
		svc := newCoverageTPMService(mock)
		logger := &mockAuditLogger{}
		svc.SetAuditLogger(logger)

		err := svc.ChangeOwnerAuth("wrong", "new")
		assert.Error(t, err)

		require.Len(t, logger.tpmOps, 1)
		assert.Equal(t, audit.OpTPMAuthFailed, logger.tpmOps[0].op)
		assert.False(t, logger.tpmOps[0].success)
	})
}

// ---------------------------------------------------------------------------
// Test: saveHandleDescriptions error paths.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ImportManufacturerCA(t *testing.T) {
	t.Run("invalid_pem_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.ImportManufacturerCA("not-a-pem")
		assert.ErrorIs(t, err, ErrTPMInvalidCACert)
	})

	t.Run("wrong_pem_type_returns_error", func(t *testing.T) {
		block := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x01, 0x02}}
		err := NewTPMService().ImportManufacturerCA(string(pem.EncodeToMemory(block)))
		assert.ErrorIs(t, err, ErrTPMInvalidCACert)
	})

	t.Run("invalid_cert_der_returns_error", func(t *testing.T) {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01, 0x02}}
		err := NewTPMService().ImportManufacturerCA(string(pem.EncodeToMemory(block)))
		assert.ErrorIs(t, err, ErrTPMInvalidCACert)
	})

	t.Run("valid_cert_appends_to_mfg_certs", func(t *testing.T) {
		svc := NewTPMService()
		certPEM := tpmGenerateTestCertPEM(t)

		err := svc.ImportManufacturerCA(certPEM)
		require.NoError(t, err)
		assert.Len(t, svc.mfgCACerts, 1)

		// Import another.
		err = svc.ImportManufacturerCA(certPEM)
		require.NoError(t, err)
		assert.Len(t, svc.mfgCACerts, 2)
	})
}

// ---------------------------------------------------------------------------
// Test: ParseCertificate.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_SetHandleDescription(t *testing.T) {
	t.Run("no_data_dir_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.SetHandleDescription("0x81000001", "test")
		assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
	})

	t.Run("set_and_remove_description", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.SetHandleDescription("0x81000001", "My SRK")
		require.NoError(t, err)

		descriptions := svc.loadHandleDescriptions()
		assert.Equal(t, "My SRK", descriptions["0x81000001"])

		// Remove by setting empty.
		err = svc.SetHandleDescription("0x81000001", "")
		require.NoError(t, err)

		descriptions = svc.loadHandleDescriptions()
		assert.Empty(t, descriptions["0x81000001"])
	})
}

// ---------------------------------------------------------------------------
// Test: buildCapabilities with different info combinations.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_buildCapabilities(t *testing.T) {
	t.Run("fips_mode_included", func(t *testing.T) {
		info := &TPMInfo{
			MaxRSAKeySize: 2048,
			MaxECCKeySize: 256,
			FIPSMode:      true,
		}
		caps := buildCapabilities(info)
		assert.Contains(t, caps, "FIPS 140-2")
	})

	t.Run("no_nv_no_persistent_no_sessions", func(t *testing.T) {
		info := &TPMInfo{
			MaxRSAKeySize: 0,
			MaxECCKeySize: 0,
		}
		caps := buildCapabilities(info)
		// Should still have basic capabilities.
		assert.Contains(t, caps, "PCR Read/Extend")
		assert.Contains(t, caps, "Quoting")
	})

	t.Run("nv_and_persistent_and_sessions", func(t *testing.T) {
		info := &TPMInfo{
			MaxRSAKeySize:     2048,
			MaxECCKeySize:     384,
			NVIndexesMax:      32,
			NVIndexesDefined:  4,
			PersistentLoaded:  5,
			PersistentAvail:   7,
			ActiveSessionsMax: 64,
		}
		caps := buildCapabilities(info)
		found := false
		for _, c := range caps {
			if len(c) > 0 {
				found = true
			}
		}
		assert.True(t, found)
	})
}

// ---------------------------------------------------------------------------
// Test: formatFingerprint.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_formatFingerprint(t *testing.T) {
	t.Run("empty_hash", func(t *testing.T) {
		result := formatFingerprint([]byte{})
		assert.Equal(t, "", result)
	})

	t.Run("formats_correctly", func(t *testing.T) {
		result := formatFingerprint([]byte{0xAB, 0xCD, 0xEF})
		assert.Equal(t, "AB:CD:EF", result)
	})
}

// ---------------------------------------------------------------------------
// Test: publicKeyBitSize.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_publicKeyBitSize(t *testing.T) {
	t.Run("ecdsa_key", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		assert.Equal(t, 256, publicKeyBitSize(&key.PublicKey))
	})

	t.Run("unknown_key_type", func(t *testing.T) {
		assert.Equal(t, 0, publicKeyBitSize("not-a-key"))
	})
}

// ---------------------------------------------------------------------------
// Test: buildSubjectAltNames.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_buildSubjectAltNames(t *testing.T) {
	t.Run("empty_cert", func(t *testing.T) {
		cert := &x509.Certificate{}
		result := buildSubjectAltNames(cert)
		assert.Empty(t, result)
	})

	t.Run("with_dns_names", func(t *testing.T) {
		cert := &x509.Certificate{
			DNSNames: []string{"example.com", "test.example.com"},
		}
		result := buildSubjectAltNames(cert)
		assert.Contains(t, result, "DNS:example.com")
		assert.Contains(t, result, "DNS:test.example.com")
	})
}

// ---------------------------------------------------------------------------
// Test: algoDisplayName and keySize.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_algoDisplayName(t *testing.T) {
	t.Run("nil_attrs", func(t *testing.T) {
		assert.Equal(t, "Unknown", algoDisplayName(nil))
	})

	t.Run("rsa_ssa", func(t *testing.T) {
		attrs := &xkms.KeyAttributes{KeyAlgorithm: x509.RSA}
		assert.Equal(t, "RSA-SSA", algoDisplayName(attrs))
	})

	t.Run("ecdsa", func(t *testing.T) {
		attrs := &xkms.KeyAttributes{KeyAlgorithm: x509.ECDSA}
		assert.Equal(t, "ECDSA", algoDisplayName(attrs))
	})

	t.Run("ed25519", func(t *testing.T) {
		attrs := &xkms.KeyAttributes{KeyAlgorithm: x509.Ed25519}
		assert.Equal(t, "Ed25519", algoDisplayName(attrs))
	})
}

func TestTPMService_Coverage_keySize(t *testing.T) {
	t.Run("nil_attrs", func(t *testing.T) {
		assert.Equal(t, 0, keySize(nil))
	})

	t.Run("rsa_attrs", func(t *testing.T) {
		attrs := &xkms.KeyAttributes{
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &xkms.RSAAttributes{
				KeySize: 4096,
			},
		}
		assert.Equal(t, 4096, keySize(attrs))
	})

	t.Run("ecc_attrs", func(t *testing.T) {
		attrs := &xkms.KeyAttributes{
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &xkms.ECCAttributes{
				Curve: elliptic.P384(),
			},
		}
		assert.Equal(t, 384, keySize(attrs))
	})

	t.Run("rsa_fallback", func(t *testing.T) {
		attrs := &xkms.KeyAttributes{KeyAlgorithm: x509.RSA}
		assert.Equal(t, 2048, keySize(attrs))
	})

	t.Run("ecdsa_fallback", func(t *testing.T) {
		attrs := &xkms.KeyAttributes{KeyAlgorithm: x509.ECDSA}
		assert.Equal(t, 256, keySize(attrs))
	})
}

// ---------------------------------------------------------------------------
// Test: isTPMAuthError.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_isTPMAuthError(t *testing.T) {
	t.Run("nil_error", func(t *testing.T) {
		assert.False(t, isTPMAuthError(nil))
	})

	t.Run("auth_fail_string", func(t *testing.T) {
		assert.True(t, isTPMAuthError(errors.New("something auth_fail happened")))
	})

	t.Run("bad_auth_string", func(t *testing.T) {
		assert.True(t, isTPMAuthError(errors.New("something bad_auth happened")))
	})

	t.Run("unrelated_error", func(t *testing.T) {
		assert.False(t, isTPMAuthError(errors.New("timeout")))
	})
}

// ---------------------------------------------------------------------------
// Test: certToPEM.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_certToPEM(t *testing.T) {
	cert := &x509.Certificate{
		Raw: []byte{0x30, 0x82, 0x01, 0x22},
	}
	result := certToPEM(cert)
	assert.Contains(t, result, "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, result, "-----END CERTIFICATE-----")
}

// ---------------------------------------------------------------------------
// Test: detectPCRBanks.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_Provision_InvalidMode(t *testing.T) {
	mock := defaultMockTPM()
	svc := newCoverageTPMService(mock)

	err := svc.Provision(&ProvisionOptions{Mode: "invalid-mode"})
	assert.ErrorIs(t, err, ErrTPMInvalidProvisionMode)
}

// ---------------------------------------------------------------------------
// Test: DefineNVOrdinary validation.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_DefineNVOrdinary_InvalidSize(t *testing.T) {
	svc := NewTPMService()

	t.Run("size_too_small", func(t *testing.T) {
		err := svc.DefineNVOrdinary(0x01500000, 0, "")
		assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
	})

	t.Run("size_too_large", func(t *testing.T) {
		err := svc.DefineNVOrdinary(0x01500000, 3000, "")
		assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
	})
}

// ---------------------------------------------------------------------------
// Test: WriteNVData validation.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_WriteNVData_Validation(t *testing.T) {
	svc := NewTPMService()

	t.Run("invalid_hex_data", func(t *testing.T) {
		err := svc.WriteNVData(0x01500000, "not-hex", "")
		assert.ErrorIs(t, err, ErrTPMInvalidNVData)
	})

	t.Run("empty_data", func(t *testing.T) {
		err := svc.WriteNVData(0x01500000, "", "")
		assert.ErrorIs(t, err, ErrTPMInvalidNVData)
	})
}

// ---------------------------------------------------------------------------
// Test: ExtendNV validation.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ExtendNV_Validation(t *testing.T) {
	svc := NewTPMService()

	t.Run("invalid_hex_data", func(t *testing.T) {
		err := svc.ExtendNV(0x01500000, "not-hex", "")
		assert.ErrorIs(t, err, ErrTPMInvalidNVData)
	})

	t.Run("empty_data", func(t *testing.T) {
		err := svc.ExtendNV(0x01500000, "", "")
		assert.ErrorIs(t, err, ErrTPMInvalidNVData)
	})
}

// ---------------------------------------------------------------------------
// Test: GenerateQuote validation.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_GenerateQuote_Validation(t *testing.T) {
	t.Run("empty_pcrs", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.GenerateQuote("", nil, "sha256")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
	})

	t.Run("invalid_bank", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.GenerateQuote("", []int{0}, "md5")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidBank)
	})

	t.Run("invalid_nonce_hex", func(t *testing.T) {
		mock := defaultMockTPM()
		svc := newCoverageTPMService(mock)
		result, err := svc.GenerateQuote("not-hex-data!!!", []int{0}, "sha256")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidNonce)
	})

	t.Run("pcr_out_of_range", func(t *testing.T) {
		mock := defaultMockTPM()
		svc := newCoverageTPMService(mock)
		result, err := svc.GenerateQuote("", []int{25}, "sha256")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
	})

	t.Run("negative_pcr", func(t *testing.T) {
		mock := defaultMockTPM()
		svc := newCoverageTPMService(mock)
		result, err := svc.GenerateQuote("", []int{-1}, "sha256")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
	})
}

// ---------------------------------------------------------------------------
// Test: GetRandomBytes validation.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_GetRandomBytes_Validation(t *testing.T) {
	t.Run("too_small", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.GetRandomBytes(0)
		assert.Empty(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidLength)
	})

	t.Run("too_large", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.GetRandomBytes(1025)
		assert.Empty(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidLength)
	})
}

// ---------------------------------------------------------------------------
// Test: GetPCRs validation.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_GetPCRs_Validation(t *testing.T) {
	t.Run("invalid_bank", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.GetPCRs("md5")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidBank)
	})
}

// ---------------------------------------------------------------------------
// Test: ReadPCRs alias.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ReadPCRs(t *testing.T) {
	t.Run("delegates_to_GetPCRs", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.ReadPCRs("md5")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidBank)
	})
}

// ---------------------------------------------------------------------------
// Test: ImportEKCert validation.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ImportEKCert_Validation(t *testing.T) {
	svc := NewTPMService()

	t.Run("invalid_pem", func(t *testing.T) {
		err := svc.ImportEKCert("not pem")
		assert.ErrorIs(t, err, ErrTPMInvalidCert)
	})

	t.Run("wrong_pem_type", func(t *testing.T) {
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{0x01}}
		err := svc.ImportEKCert(string(pem.EncodeToMemory(block)))
		assert.ErrorIs(t, err, ErrTPMInvalidCert)
	})

	t.Run("unparseable_cert", func(t *testing.T) {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01, 0x02, 0x03}}
		err := svc.ImportEKCert(string(pem.EncodeToMemory(block)))
		assert.ErrorIs(t, err, ErrTPMInvalidCert)
	})
}

// ---------------------------------------------------------------------------
// Test: Provision nil opts.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_Provision_NilOpts(t *testing.T) {
	svc := NewTPMService()
	err := svc.Provision(nil)
	assert.ErrorIs(t, err, ErrTPMProvisionFailed)
}

// ---------------------------------------------------------------------------
// Helper: generate a PEM-encoded self-signed test certificate.
// ---------------------------------------------------------------------------

func tpmGenerateTestCertPEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))
}

func TestTPMService_Coverage_saveHandleDescriptions(t *testing.T) {
	t.Run("empty_data_dir_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.saveHandleDescriptions(map[string]string{"0x81000001": "test"})
		assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
	})

	t.Run("success", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		err := svc.saveHandleDescriptions(map[string]string{"0x81000001": "SRK"})
		assert.NoError(t, err)

		// Verify roundtrip.
		loaded := svc.loadHandleDescriptions()
		assert.Equal(t, "SRK", loaded["0x81000001"])
	})
}

func TestTPMService_Coverage_ParseCertificate(t *testing.T) {
	t.Run("invalid_pem", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.ParseCertificate("not-a-pem")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidCert)
	})

	t.Run("wrong_pem_type", func(t *testing.T) {
		svc := NewTPMService()
		block := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x01, 0x02}}
		result, err := svc.ParseCertificate(string(pem.EncodeToMemory(block)))
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidCert)
	})

	t.Run("invalid_der", func(t *testing.T) {
		svc := NewTPMService()
		block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01, 0x02}}
		result, err := svc.ParseCertificate(string(pem.EncodeToMemory(block)))
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidCert)
	})

	t.Run("valid_cert_returns_details", func(t *testing.T) {
		svc := NewTPMService()
		certPEM := tpmGenerateTestCertPEM(t)
		result, err := svc.ParseCertificate(certPEM)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.NotEmpty(t, result.SubjectCN)
		assert.NotEmpty(t, result.FingerprintSHA256)
		assertLegacyFingerprints(t, result.FingerprintSHA1, result.FingerprintMD5)
		assert.NotEmpty(t, result.SignatureAlgorithm)
		assert.Equal(t, "ECDSA P-256", result.PublicKeyAlgorithm)
	})
}

func TestTPMService_Coverage_loadHandleDescriptions_CorruptJSON(t *testing.T) {
	svc := NewTPMService()
	dir := t.TempDir()
	svc.SetDataDir(dir)

	err := os.WriteFile(filepath.Join(dir, handleDescriptionsFile), []byte("{bad"), 0600)
	require.NoError(t, err)

	descriptions := svc.loadHandleDescriptions()
	assert.Empty(t, descriptions)
}

func TestTPMService_Coverage_detectPCRBanks(t *testing.T) {
	t.Run("returns_sorted_banks", func(t *testing.T) {
		mock := defaultMockTPM()
		mock.pcrBanks = []xkms.PCRBank{
			{Algorithm: "SHA512", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x01}}}},
			{Algorithm: "SHA1", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x01}}}},
			{Algorithm: "SHA256", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x01}}}},
		}
		banks := detectPCRBanks(mock)
		require.Len(t, banks, 3)
		assert.Equal(t, "sha1", banks[0])
		assert.Equal(t, "sha256", banks[1])
		assert.Equal(t, "sha512", banks[2])
	})

	t.Run("read_error_returns_nil", func(t *testing.T) {
		mock := defaultMockTPM()
		mock.pcrBanksErr = errors.New("read failed")
		banks := detectPCRBanks(mock)
		assert.Nil(t, banks)
	})

	t.Run("sha384_variant", func(t *testing.T) {
		mock := defaultMockTPM()
		mock.pcrBanks = []xkms.PCRBank{
			{Algorithm: "SHA386", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x01}}}},
		}
		banks := detectPCRBanks(mock)
		require.Len(t, banks, 1)
		assert.Equal(t, "sha384", banks[0])
	})
}
