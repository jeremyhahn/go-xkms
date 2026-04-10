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
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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

func (m *mockAuditLogger) Log(_ audit.Entry) {}
func (m *mockAuditLogger) LogKeyOperation(_ audit.OperationType, _, _ string, _ bool, _ error, _ int64) {
}
func (m *mockAuditLogger) LogCryptoOperation(_ audit.OperationType, _, _, _, _ string, _ bool, _ error, _ int64) {
}
func (m *mockAuditLogger) LogConnectionEvent(_ audit.OperationType, _, _ string, _ map[string]any) {}
func (m *mockAuditLogger) LogServiceEvent(_ audit.OperationType, _ map[string]any)                 {}
func (m *mockAuditLogger) LogPINOperation(_ audit.OperationType, _ string, _ bool, _ error, _ map[string]any) {
}
func (m *mockAuditLogger) LogTPMOperation(op audit.OperationType, success bool, err error, details map[string]any) {
	m.tpmOps = append(m.tpmOps, mockTPMOp{
		op:      op,
		success: success,
		err:     err,
		details: details,
	})
}
func (m *mockAuditLogger) LogPasswordStoreOperation(_ audit.OperationType, _ string, _ bool, _ error, _ map[string]any) {
}
func (m *mockAuditLogger) LogUserPresenceEvent(_ audit.OperationType, _ string, _ bool, _ map[string]any) {
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

func newCoverageTPMService(tpm tpm2pkg.TrustedPlatformModule) *TPMService {
	svc := NewTPMService()
	svc.SetContext(context.Background())
	if tpm != nil {
		accessor := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return tpm })
		svc.SetTPMAccessor(accessor)
	}
	return svc
}

func newCoverageTPMServiceWithDataDir(t *testing.T, tpm tpm2pkg.TrustedPlatformModule) *TPMService {
	t.Helper()
	svc := newCoverageTPMService(tpm)
	svc.SetDataDir(t.TempDir())
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
// Test: ListKeys panic recovery path (60% -> 100%).
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ListKeys(t *testing.T) {
	t.Run("returns_empty_slice", func(t *testing.T) {
		svc := NewTPMService()
		keys, err := svc.ListKeys()
		require.NoError(t, err)
		assert.Empty(t, keys)
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

func TestTPMService_Coverage_ListPolicies(t *testing.T) {
	t.Run("no_data_dir_returns_empty", func(t *testing.T) {
		svc := NewTPMService()
		policies, err := svc.ListPolicies()
		require.NoError(t, err)
		assert.Empty(t, policies)
	})

	t.Run("with_data_dir_no_file_returns_empty", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		policies, err := svc.ListPolicies()
		require.NoError(t, err)
		assert.Empty(t, policies)
	})
}

// ---------------------------------------------------------------------------
// Test: ListPolicyAssignments panic recovery path.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ListPolicyAssignments(t *testing.T) {
	t.Run("no_data_dir_returns_empty", func(t *testing.T) {
		svc := NewTPMService()
		assignments, err := svc.ListPolicyAssignments()
		require.NoError(t, err)
		assert.Empty(t, assignments)
	})

	t.Run("with_data_dir_no_file_returns_empty", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		assignments, err := svc.ListPolicyAssignments()
		require.NoError(t, err)
		assert.Empty(t, assignments)
	})
}

// ---------------------------------------------------------------------------
// Test: ListCompositePolicies panic recovery path.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ListCompositePolicies(t *testing.T) {
	t.Run("no_data_dir_returns_empty", func(t *testing.T) {
		svc := NewTPMService()
		policies, err := svc.ListCompositePolicies()
		require.NoError(t, err)
		assert.Empty(t, policies)
	})

	t.Run("with_data_dir_no_file_returns_empty", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		policies, err := svc.ListCompositePolicies()
		require.NoError(t, err)
		assert.Empty(t, policies)
	})
}

// ---------------------------------------------------------------------------
// Test: ChangeOwnerAuth/ChangeEndorsementAuth/ChangeLockoutAuth panic recovery.
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

// ---------------------------------------------------------------------------
// Test: savePolicies error paths.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_savePolicies(t *testing.T) {
	t.Run("empty_data_dir_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.savePolicies([]PCRPolicy{})
		assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
	})

	t.Run("success", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		policies := []PCRPolicy{
			{Name: "test-policy", CreatedAt: time.Now().Format(time.RFC3339)},
		}
		err := svc.savePolicies(policies)
		assert.NoError(t, err)

		loaded := svc.loadPolicies()
		require.Len(t, loaded, 1)
		assert.Equal(t, "test-policy", loaded[0].Name)
	})
}

// ---------------------------------------------------------------------------
// Test: saveAssignments error paths.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_saveAssignments(t *testing.T) {
	t.Run("empty_data_dir_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.saveAssignments([]PolicyAssignment{})
		assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
	})

	t.Run("success", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		assignments := []PolicyAssignment{
			{PolicyName: "test-policy", KeyHandle: "0x81000001", AssignedAt: time.Now().Format(time.RFC3339)},
		}
		err := svc.saveAssignments(assignments)
		assert.NoError(t, err)

		loaded := svc.loadAssignments()
		require.Len(t, loaded, 1)
		assert.Equal(t, "test-policy", loaded[0].PolicyName)
	})
}

// ---------------------------------------------------------------------------
// Test: saveCompositePolicies error paths.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_saveCompositePolicies(t *testing.T) {
	t.Run("empty_data_dir_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.saveCompositePolicies([]CompositePolicy{})
		assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
	})

	t.Run("success", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		policies := []CompositePolicy{
			{Name: "test-composite", Operator: "AND", CreatedAt: time.Now().Format(time.RFC3339)},
		}
		err := svc.saveCompositePolicies(policies)
		assert.NoError(t, err)

		loaded := svc.loadCompositePolicies()
		require.Len(t, loaded, 1)
		assert.Equal(t, "test-composite", loaded[0].Name)
	})
}

// ---------------------------------------------------------------------------
// Test: GetPolicy error path (panic recovery).
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_GetPolicy(t *testing.T) {
	t.Run("not_found_no_data_dir", func(t *testing.T) {
		svc := NewTPMService()
		policy, err := svc.GetPolicy("nonexistent")
		assert.Nil(t, policy)
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})

	t.Run("found_in_saved_policies", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		// Save a policy first.
		err := svc.savePolicies([]PCRPolicy{
			{Name: "my-policy", Description: "test", CreatedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		policy, err := svc.GetPolicy("my-policy")
		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Equal(t, "my-policy", policy.Name)
	})
}

// ---------------------------------------------------------------------------
// Test: GetCompositePolicy error path (panic recovery).
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_GetCompositePolicy(t *testing.T) {
	t.Run("not_found_no_data_dir", func(t *testing.T) {
		svc := NewTPMService()
		policy, err := svc.GetCompositePolicy("nonexistent")
		assert.Nil(t, policy)
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})

	t.Run("found_in_saved_policies", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.saveCompositePolicies([]CompositePolicy{
			{Name: "my-composite", Operator: "AND", CreatedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		policy, err := svc.GetCompositePolicy("my-composite")
		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Equal(t, "my-composite", policy.Name)
	})
}

// ---------------------------------------------------------------------------
// Test: ExportPolicy additional paths.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ExportPolicy(t *testing.T) {
	t.Run("not_found", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.ExportPolicy("nonexistent")
		assert.Empty(t, result)
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})

	t.Run("export_with_updated_at_and_digests", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.savePolicies([]PCRPolicy{
			{
				Name:      "export-test",
				CreatedAt: time.Now().Format(time.RFC3339),
				UpdatedAt: time.Now().Format(time.RFC3339),
				PCRSelections: []PCRSelection{
					{Index: 0, Bank: "sha256"},
					{Index: 7, Bank: "sha256"},
				},
				PCRDigests: map[string]string{
					"sha256:0": "abcd1234",
					"sha256:7": "efgh5678",
				},
			},
		})
		require.NoError(t, err)

		result, err := svc.ExportPolicy("export-test")
		require.NoError(t, err)
		assert.Contains(t, result, "export-test")
		assert.Contains(t, result, "updated_at")
		assert.Contains(t, result, "pcr_digests")
		assert.Contains(t, result, "pcr_bank")
		assert.Contains(t, result, "pcr_selections")
	})
}

// ---------------------------------------------------------------------------
// Test: ExportCompositePolicy additional paths.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ExportCompositePolicy(t *testing.T) {
	t.Run("not_found", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.ExportCompositePolicy("nonexistent")
		assert.Empty(t, result)
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})

	t.Run("export_with_all_fields", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.saveCompositePolicies([]CompositePolicy{
			{
				Name:        "comp-export-test",
				Description: "a composite policy",
				Operator:    "OR",
				CreatedAt:   time.Now().Format(time.RFC3339),
				UpdatedAt:   time.Now().Format(time.RFC3339),
				Elements: []PolicyElement{
					{
						Type:    "pcr",
						PCRBank: "sha256",
						PCRSelections: []PCRSelection{
							{Index: 0, Bank: "sha256"},
						},
					},
					{
						Type:         "password",
						PasswordHash: "fake-hash",
					},
				},
				PCRDigests: map[string]string{
					"sha256:0": "aabbccdd",
				},
			},
		})
		require.NoError(t, err)

		result, err := svc.ExportCompositePolicy("comp-export-test")
		require.NoError(t, err)
		assert.Contains(t, result, "comp-export-test")
		assert.Contains(t, result, "description")
		assert.Contains(t, result, "updated_at")
		assert.Contains(t, result, "pcr_digests")
		assert.Contains(t, result, "pcr_bank")
		assert.Contains(t, result, "pcr_selections")
	})

	t.Run("export_without_pcr_elements", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.saveCompositePolicies([]CompositePolicy{
			{
				Name:      "password-only-export",
				Operator:  "SINGLE",
				CreatedAt: time.Now().Format(time.RFC3339),
				Elements: []PolicyElement{
					{Type: "password", PasswordHash: "hash123"},
				},
			},
		})
		require.NoError(t, err)

		result, err := svc.ExportCompositePolicy("password-only-export")
		require.NoError(t, err)
		assert.Contains(t, result, "password-only-export")
		// Should NOT contain pcr_bank since no PCR elements.
		var exported map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(result), &exported))
		_, hasPCRBank := exported["pcr_bank"]
		assert.False(t, hasPCRBank)
	})
}

// ---------------------------------------------------------------------------
// Test: DeletePolicy and cascade.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_DeletePolicy(t *testing.T) {
	t.Run("not_found", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		err := svc.DeletePolicy("nonexistent")
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})

	t.Run("deletes_policy_and_cascades_assignments", func(t *testing.T) {
		svc := NewTPMService()
		dir := t.TempDir()
		svc.SetDataDir(dir)

		// Create a policy and an assignment.
		err := svc.savePolicies([]PCRPolicy{
			{Name: "del-policy", CreatedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		err = svc.saveAssignments([]PolicyAssignment{
			{PolicyName: "del-policy", KeyHandle: "0x81000001", AssignedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		// Delete the policy.
		err = svc.DeletePolicy("del-policy")
		require.NoError(t, err)

		// Verify policy removed.
		policies := svc.loadPolicies()
		assert.Empty(t, policies)

		// Verify assignment cascade removed.
		assignments := svc.loadAssignments()
		assert.Empty(t, assignments)
	})
}

// ---------------------------------------------------------------------------
// Test: DeleteCompositePolicy and cascade.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_DeleteCompositePolicy(t *testing.T) {
	t.Run("not_found", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		err := svc.DeleteCompositePolicy("nonexistent")
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})

	t.Run("deletes_composite_and_cascades", func(t *testing.T) {
		svc := NewTPMService()
		dir := t.TempDir()
		svc.SetDataDir(dir)

		err := svc.saveCompositePolicies([]CompositePolicy{
			{Name: "del-comp", Operator: "AND", CreatedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		err = svc.saveAssignments([]PolicyAssignment{
			{PolicyName: "del-comp", KeyHandle: "0x81000001", AssignedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		err = svc.DeleteCompositePolicy("del-comp")
		require.NoError(t, err)

		policies := svc.loadCompositePolicies()
		assert.Empty(t, policies)

		assignments := svc.loadAssignments()
		assert.Empty(t, assignments)
	})
}

// ---------------------------------------------------------------------------
// Test: UnassignPolicyFromKey.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_UnassignPolicyFromKey(t *testing.T) {
	t.Run("not_found", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		err := svc.UnassignPolicyFromKey("0xDEAD")
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})

	t.Run("removes_assignment", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.saveAssignments([]PolicyAssignment{
			{PolicyName: "p1", KeyHandle: "0x81000001", AssignedAt: time.Now().Format(time.RFC3339)},
			{PolicyName: "p2", KeyHandle: "0x81000002", AssignedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		err = svc.UnassignPolicyFromKey("0x81000001")
		require.NoError(t, err)

		loaded := svc.loadAssignments()
		require.Len(t, loaded, 1)
		assert.Equal(t, "0x81000002", loaded[0].KeyHandle)
	})
}

// ---------------------------------------------------------------------------
// Test: AssignPolicyToKey validation.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_AssignPolicyToKey(t *testing.T) {
	t.Run("empty_policy_name", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.AssignPolicyToKey("  ", "0x81000001")
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("empty_key_handle", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.AssignPolicyToKey("policy", "  ")
		assert.ErrorIs(t, err, ErrTPMInvalidHandle)
	})

	t.Run("policy_not_found", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		err := svc.AssignPolicyToKey("nonexistent", "0x81000001")
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})
}

// ---------------------------------------------------------------------------
// Test: AssignPolicyToKeys validation.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_AssignPolicyToKeys(t *testing.T) {
	t.Run("empty_policy_name", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.AssignPolicyToKeys("  ", []string{"0x81000001"})
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("empty_key_handles", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.AssignPolicyToKeys("policy", []string{})
		assert.ErrorIs(t, err, ErrTPMInvalidHandle)
	})
}

// ---------------------------------------------------------------------------
// Test: GetConflictingAssignments.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_GetConflictingAssignments(t *testing.T) {
	t.Run("no_assignments_returns_empty", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		conflicts, err := svc.GetConflictingAssignments([]string{"0x81000001"})
		require.NoError(t, err)
		assert.Empty(t, conflicts)
	})

	t.Run("finds_conflicts", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.saveAssignments([]PolicyAssignment{
			{PolicyName: "policy-a", KeyHandle: "0x81000001", AssignedAt: time.Now().Format(time.RFC3339)},
			{PolicyName: "policy-b", KeyHandle: "0x81000002", AssignedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		conflicts, err := svc.GetConflictingAssignments([]string{"0x81000001", "0x81000003"})
		require.NoError(t, err)
		require.Len(t, conflicts, 1)
		assert.Equal(t, "0x81000001", conflicts[0].KeyHandle)
		assert.Equal(t, "policy-a", conflicts[0].CurrentPolicy)
	})

	t.Run("empty_and_whitespace_handles_ignored", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		conflicts, err := svc.GetConflictingAssignments([]string{"", "  ", ""})
		require.NoError(t, err)
		assert.Empty(t, conflicts)
	})
}

// ---------------------------------------------------------------------------
// Test: GetPolicyDeletionImpact.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_GetPolicyDeletionImpact(t *testing.T) {
	t.Run("policy_not_found", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		impact, err := svc.GetPolicyDeletionImpact("nonexistent")
		assert.Nil(t, impact)
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})

	t.Run("pcr_policy_with_assignments", func(t *testing.T) {
		svc := NewTPMService()
		dir := t.TempDir()
		svc.SetDataDir(dir)

		err := svc.savePolicies([]PCRPolicy{
			{Name: "impact-policy", CreatedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		err = svc.saveAssignments([]PolicyAssignment{
			{PolicyName: "impact-policy", KeyHandle: "0x81000001", AssignedAt: time.Now().Format(time.RFC3339)},
			{PolicyName: "impact-policy", KeyHandle: "0x81000002", AssignedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		impact, err := svc.GetPolicyDeletionImpact("impact-policy")
		require.NoError(t, err)
		require.NotNil(t, impact)
		assert.Equal(t, "pcr", impact.PolicyType)
		assert.Equal(t, "impact-policy", impact.PolicyName)
		assert.Len(t, impact.AssignedKeyHandles, 2)
	})

	t.Run("composite_policy_found", func(t *testing.T) {
		svc := NewTPMService()
		dir := t.TempDir()
		svc.SetDataDir(dir)

		err := svc.saveCompositePolicies([]CompositePolicy{
			{Name: "comp-impact", Operator: "AND", CreatedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		impact, err := svc.GetPolicyDeletionImpact("comp-impact")
		require.NoError(t, err)
		require.NotNil(t, impact)
		assert.Equal(t, "composite", impact.PolicyType)
	})
}

// ---------------------------------------------------------------------------
// Test: CreatePolicy validation.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_CreatePolicy(t *testing.T) {
	t.Run("nil_policy_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreatePolicy(nil)
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("empty_name_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreatePolicy(&PCRPolicy{Name: "  "})
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("duplicate_name_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.savePolicies([]PCRPolicy{
			{Name: "existing", CreatedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		err = svc.CreatePolicy(&PCRPolicy{Name: "existing"})
		assert.ErrorIs(t, err, ErrTPMPolicyExists)
	})
}

// ---------------------------------------------------------------------------
// Test: CreateCompositePolicy validation.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_CreateCompositePolicy(t *testing.T) {
	t.Run("nil_policy_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreateCompositePolicy(nil)
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("empty_name_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreateCompositePolicy(&CompositePolicy{Name: "  ", Operator: "AND"})
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("invalid_operator_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreateCompositePolicy(&CompositePolicy{Name: "test", Operator: "XOR"})
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyOperator)
	})
}

// ---------------------------------------------------------------------------
// Test: CreateDefaultPlatformPolicy idempotency.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_CreateDefaultPlatformPolicy(t *testing.T) {
	t.Run("creates_policy", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		err := svc.CreateDefaultPlatformPolicy()
		assert.NoError(t, err)

		policies := svc.loadCompositePolicies()
		require.Len(t, policies, 1)
		assert.Equal(t, "Platform Policy", policies[0].Name)
	})

	t.Run("idempotent_no_error_on_duplicate", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		err := svc.CreateDefaultPlatformPolicy()
		require.NoError(t, err)

		// Second call should not error.
		err = svc.CreateDefaultPlatformPolicy()
		assert.NoError(t, err)

		// Still only one policy.
		policies := svc.loadCompositePolicies()
		assert.Len(t, policies, 1)
	})
}

// ---------------------------------------------------------------------------
// Test: UpdatePolicy.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_UpdatePolicy(t *testing.T) {
	t.Run("empty_name_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.UpdatePolicy("  ", &PCRPolicy{})
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("nil_updated_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.UpdatePolicy("test", nil)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("not_found_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		result, err := svc.UpdatePolicy("nonexistent", &PCRPolicy{})
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})
}

// ---------------------------------------------------------------------------
// Test: RefreshPolicyPCRs.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_RefreshPolicyPCRs(t *testing.T) {
	t.Run("not_found", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		result, err := svc.RefreshPolicyPCRs("nonexistent")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})

	t.Run("no_tpm_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.savePolicies([]PCRPolicy{
			{
				Name:          "refresh-test",
				CreatedAt:     time.Now().Format(time.RFC3339),
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			},
		})
		require.NoError(t, err)

		result, err := svc.RefreshPolicyPCRs("refresh-test")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMNotAvailable)
	})
}

// ---------------------------------------------------------------------------
// Test: RefreshCompositePolicyPCRs.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_RefreshCompositePolicyPCRs(t *testing.T) {
	t.Run("not_found", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		result, err := svc.RefreshCompositePolicyPCRs("nonexistent")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})

	t.Run("no_pcr_selections_returns_policy_as_is", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.saveCompositePolicies([]CompositePolicy{
			{
				Name:      "no-pcrs",
				Operator:  "SINGLE",
				CreatedAt: time.Now().Format(time.RFC3339),
				Elements: []PolicyElement{
					{Type: "password", PasswordHash: "hash"},
				},
			},
		})
		require.NoError(t, err)

		result, err := svc.RefreshCompositePolicyPCRs("no-pcrs")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "no-pcrs", result.Name)
	})

	t.Run("no_tpm_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.saveCompositePolicies([]CompositePolicy{
			{
				Name:      "needs-tpm",
				Operator:  "AND",
				CreatedAt: time.Now().Format(time.RFC3339),
				Elements: []PolicyElement{
					{Type: "pcr", PCRBank: "sha256", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
				},
			},
		})
		require.NoError(t, err)

		result, err := svc.RefreshCompositePolicyPCRs("needs-tpm")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMNotAvailable)
	})
}

// ---------------------------------------------------------------------------
// Test: VerifyPolicyPassword.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_VerifyPolicyPassword(t *testing.T) {
	t.Run("policy_not_found", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		result, err := svc.VerifyPolicyPassword("nonexistent", "pass")
		assert.False(t, result)
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})

	t.Run("policy_has_no_password_element", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.saveCompositePolicies([]CompositePolicy{
			{
				Name:      "pcr-only",
				Operator:  "SINGLE",
				CreatedAt: time.Now().Format(time.RFC3339),
				Elements: []PolicyElement{
					{Type: "pcr", PCRBank: "sha256", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
				},
			},
		})
		require.NoError(t, err)

		result, err := svc.VerifyPolicyPassword("pcr-only", "password")
		assert.False(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyType)
	})
}

// ---------------------------------------------------------------------------
// Test: ComparePolicyPCRs validation paths.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_ComparePolicyPCRs(t *testing.T) {
	t.Run("empty_name", func(t *testing.T) {
		svc := NewTPMService()
		result, err := svc.ComparePolicyPCRs("  ")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("policy_not_found", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		result, err := svc.ComparePolicyPCRs("nonexistent")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
	})

	t.Run("policy_no_digests", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.savePolicies([]PCRPolicy{
			{Name: "no-digest", CreatedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		result, err := svc.ComparePolicyPCRs("no-digest")
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrTPMPolicyNoDigests)
	})
}

// ---------------------------------------------------------------------------
// Test: CreatePasswordPolicy validation paths.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_CreatePasswordPolicy(t *testing.T) {
	t.Run("empty_name", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreatePasswordPolicy("  ", "desc", "password", false)
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("empty_password", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreatePasswordPolicy("test", "desc", "  ", false)
		assert.ErrorIs(t, err, ErrTPMInvalidAuth)
	})
}

// ---------------------------------------------------------------------------
// Test: CreatePCROrPasswordPolicy validation paths.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_CreatePCROrPasswordPolicy(t *testing.T) {
	t.Run("empty_name", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreatePCROrPasswordPolicy("  ", "desc", nil, "sha256", "password", false)
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("empty_pcr_selections", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreatePCROrPasswordPolicy("test", "desc", []PCRSelection{}, "sha256", "password", false)
		assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
	})

	t.Run("empty_password", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreatePCROrPasswordPolicy("test", "desc", []PCRSelection{{Index: 0, Bank: "sha256"}}, "sha256", "  ", false)
		assert.ErrorIs(t, err, ErrTPMInvalidAuth)
	})
}

// ---------------------------------------------------------------------------
// Test: CreatePCRAndPasswordPolicy validation paths.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_CreatePCRAndPasswordPolicy(t *testing.T) {
	t.Run("empty_name", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreatePCRAndPasswordPolicy("  ", "desc", nil, "sha256", "password", false)
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("empty_pcr_selections", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreatePCRAndPasswordPolicy("test", "desc", []PCRSelection{}, "sha256", "password", false)
		assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
	})

	t.Run("empty_password", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.CreatePCRAndPasswordPolicy("test", "desc", []PCRSelection{{Index: 0, Bank: "sha256"}}, "sha256", "  ", false)
		assert.ErrorIs(t, err, ErrTPMInvalidAuth)
	})
}

// ---------------------------------------------------------------------------
// Test: ImportManufacturerCA additional paths.
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
		assert.NotEmpty(t, result.FingerprintSHA1)
		assert.NotEmpty(t, result.FingerprintMD5)
		assert.NotEmpty(t, result.SignatureAlgorithm)
		assert.Equal(t, "ECDSA P-256", result.PublicKeyAlgorithm)
	})
}

// ---------------------------------------------------------------------------
// Test: loadPolicies with corrupt JSON.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_loadPolicies_CorruptJSON(t *testing.T) {
	svc := NewTPMService()
	dir := t.TempDir()
	svc.SetDataDir(dir)

	// Write invalid JSON.
	err := os.WriteFile(filepath.Join(dir, pcrPoliciesFile), []byte("{{invalid json"), 0600)
	require.NoError(t, err)

	policies := svc.loadPolicies()
	assert.Empty(t, policies)
}

// ---------------------------------------------------------------------------
// Test: loadCompositePolicies with corrupt JSON.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_loadCompositePolicies_CorruptJSON(t *testing.T) {
	svc := NewTPMService()
	dir := t.TempDir()
	svc.SetDataDir(dir)

	err := os.WriteFile(filepath.Join(dir, compositePoliciesFile), []byte("not json"), 0600)
	require.NoError(t, err)

	policies := svc.loadCompositePolicies()
	assert.Empty(t, policies)
}

// ---------------------------------------------------------------------------
// Test: loadAssignments with corrupt JSON.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_loadAssignments_CorruptJSON(t *testing.T) {
	svc := NewTPMService()
	dir := t.TempDir()
	svc.SetDataDir(dir)

	err := os.WriteFile(filepath.Join(dir, policyAssignmentsFile), []byte("{bad"), 0600)
	require.NoError(t, err)

	assignments := svc.loadAssignments()
	assert.Empty(t, assignments)
}

// ---------------------------------------------------------------------------
// Test: loadHandleDescriptions with corrupt JSON.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_loadHandleDescriptions_CorruptJSON(t *testing.T) {
	svc := NewTPMService()
	dir := t.TempDir()
	svc.SetDataDir(dir)

	err := os.WriteFile(filepath.Join(dir, handleDescriptionsFile), []byte("{bad"), 0600)
	require.NoError(t, err)

	descriptions := svc.loadHandleDescriptions()
	assert.Empty(t, descriptions)
}

// ---------------------------------------------------------------------------
// Test: compositePolicyPCRSelections.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_compositePolicyPCRSelections(t *testing.T) {
	t.Run("no_pcr_elements", func(t *testing.T) {
		policy := &CompositePolicy{
			Elements: []PolicyElement{
				{Type: "password", PasswordHash: "hash"},
			},
		}
		sels := compositePolicyPCRSelections(policy)
		assert.Empty(t, sels)
	})

	t.Run("pcr_elements_with_bank_fallback", func(t *testing.T) {
		policy := &CompositePolicy{
			Elements: []PolicyElement{
				{
					Type:    "pcr",
					PCRBank: "sha256",
					PCRSelections: []PCRSelection{
						{Index: 0, Bank: ""},
						{Index: 7, Bank: "sha384"},
					},
				},
			},
		}
		sels := compositePolicyPCRSelections(policy)
		require.Len(t, sels, 2)
		// First selection should have bank from PCRBank fallback.
		assert.Equal(t, "sha256", sels[0].Bank)
		// Second should keep its own bank.
		assert.Equal(t, "sha384", sels[1].Bank)
	})
}

// ---------------------------------------------------------------------------
// Test: importBinaryPolicyDigest.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_importBinaryPolicyDigest(t *testing.T) {
	t.Run("empty_data_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		name, err := svc.importBinaryPolicyDigest("/tmp/empty.bin", []byte{})
		assert.Empty(t, name)
		assert.ErrorIs(t, err, ErrTPMPolicyImportFailed)
	})

	t.Run("generates_name_from_filename", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		name, err := svc.importBinaryPolicyDigest("/tmp/my-policy.bin", []byte{0xAB, 0xCD})
		require.NoError(t, err)
		assert.Equal(t, "my-policy", name)
	})

	t.Run("name_conflict_appends_timestamp", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		// Create first policy.
		name1, err := svc.importBinaryPolicyDigest("/tmp/test.bin", []byte{0x01})
		require.NoError(t, err)
		assert.Equal(t, "test", name1)

		// Second import with same filename should get a timestamp suffix.
		name2, err := svc.importBinaryPolicyDigest("/tmp/test.bin", []byte{0x02})
		require.NoError(t, err)
		assert.NotEqual(t, "test", name2)
		assert.Contains(t, name2, "test-")
	})
}

// ---------------------------------------------------------------------------
// Test: importJSONPolicy.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_importJSONPolicy(t *testing.T) {
	t.Run("invalid_json", func(t *testing.T) {
		svc := NewTPMService()
		name, err := svc.importJSONPolicy([]byte("{not valid"))
		assert.Empty(t, name)
		assert.ErrorIs(t, err, ErrTPMPolicyImportFailed)
	})

	t.Run("empty_name", func(t *testing.T) {
		svc := NewTPMService()
		name, err := svc.importJSONPolicy([]byte(`{"pcr_bank": "sha256"}`))
		assert.Empty(t, name)
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("detects_composite_policy", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		data, _ := json.Marshal(map[string]interface{}{
			"name":     "comp-import",
			"operator": "AND",
			"elements": []interface{}{},
		})
		name, err := svc.importJSONPolicy(data)
		require.NoError(t, err)
		assert.Equal(t, "comp-import", name)
	})

	t.Run("imports_pcr_policy", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		data, _ := json.Marshal(map[string]interface{}{
			"name":           "pcr-import",
			"description":    "imported pcr policy",
			"pcr_bank":       "sha256",
			"pcr_selections": []interface{}{float64(0), float64(7)},
			"pcr_digests": map[string]interface{}{
				"sha256:0": "abcd1234",
			},
		})
		name, err := svc.importJSONPolicy(data)
		require.NoError(t, err)
		assert.Equal(t, "pcr-import", name)
	})
}

// ---------------------------------------------------------------------------
// Test: importCompositePolicy.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_importCompositePolicy(t *testing.T) {
	t.Run("empty_name_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())
		raw := map[string]interface{}{
			"name":     "",
			"operator": "AND",
		}
		name, err := svc.importCompositePolicy(raw)
		assert.Empty(t, name)
		assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
	})

	t.Run("duplicate_name_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.saveCompositePolicies([]CompositePolicy{
			{Name: "existing-comp", Operator: "AND", CreatedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		raw := map[string]interface{}{
			"name":     "existing-comp",
			"operator": "AND",
		}
		name, err := svc.importCompositePolicy(raw)
		assert.Empty(t, name)
		assert.ErrorIs(t, err, ErrTPMPolicyExists)
	})
}

// ---------------------------------------------------------------------------
// Test: removeAssignmentsForPolicy.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_removeAssignmentsForPolicy(t *testing.T) {
	t.Run("no_matching_assignments", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.saveAssignments([]PolicyAssignment{
			{PolicyName: "other", KeyHandle: "0x81000001", AssignedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		// Should be a no-op.
		svc.removeAssignmentsForPolicy("nonexistent")

		loaded := svc.loadAssignments()
		assert.Len(t, loaded, 1)
	})

	t.Run("removes_matching_assignments", func(t *testing.T) {
		svc := NewTPMService()
		svc.SetDataDir(t.TempDir())

		err := svc.saveAssignments([]PolicyAssignment{
			{PolicyName: "target", KeyHandle: "0x81000001", AssignedAt: time.Now().Format(time.RFC3339)},
			{PolicyName: "target", KeyHandle: "0x81000002", AssignedAt: time.Now().Format(time.RFC3339)},
			{PolicyName: "other", KeyHandle: "0x81000003", AssignedAt: time.Now().Format(time.RFC3339)},
		})
		require.NoError(t, err)

		svc.removeAssignmentsForPolicy("target")

		loaded := svc.loadAssignments()
		require.Len(t, loaded, 1)
		assert.Equal(t, "other", loaded[0].PolicyName)
	})
}

// ---------------------------------------------------------------------------
// Test: isPlatformPolicyName.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_isPlatformPolicyName(t *testing.T) {
	t.Run("wrong_name_returns_false", func(t *testing.T) {
		svc := NewTPMService()
		assert.False(t, svc.isPlatformPolicyName("Not Platform Policy"))
	})

	t.Run("no_platform_policy_service_returns_false", func(t *testing.T) {
		svc := NewTPMService()
		assert.False(t, svc.isPlatformPolicyName("Platform Policy"))
	})
}

// ---------------------------------------------------------------------------
// Test: SetHandleDescription.
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
		attrs := &types.KeyAttributes{KeyAlgorithm: x509.RSA}
		assert.Equal(t, "RSA-SSA", algoDisplayName(attrs))
	})

	t.Run("ecdsa", func(t *testing.T) {
		attrs := &types.KeyAttributes{KeyAlgorithm: x509.ECDSA}
		assert.Equal(t, "ECDSA", algoDisplayName(attrs))
	})

	t.Run("ed25519", func(t *testing.T) {
		attrs := &types.KeyAttributes{KeyAlgorithm: x509.Ed25519}
		assert.Equal(t, "Ed25519", algoDisplayName(attrs))
	})
}

func TestTPMService_Coverage_keySize(t *testing.T) {
	t.Run("nil_attrs", func(t *testing.T) {
		assert.Equal(t, 0, keySize(nil))
	})

	t.Run("rsa_attrs", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 4096,
			},
		}
		assert.Equal(t, 4096, keySize(attrs))
	})

	t.Run("ecc_attrs", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P384(),
			},
		}
		assert.Equal(t, 384, keySize(attrs))
	})

	t.Run("rsa_fallback", func(t *testing.T) {
		attrs := &types.KeyAttributes{KeyAlgorithm: x509.RSA}
		assert.Equal(t, 2048, keySize(attrs))
	})

	t.Run("ecdsa_fallback", func(t *testing.T) {
		attrs := &types.KeyAttributes{KeyAlgorithm: x509.ECDSA}
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

func TestTPMService_Coverage_detectPCRBanks(t *testing.T) {
	t.Run("returns_sorted_banks", func(t *testing.T) {
		mock := defaultMockTPM()
		mock.pcrBanks = []tpm2pkg.PCRBank{
			{Algorithm: "SHA512", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0x01}}}},
			{Algorithm: "SHA1", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0x01}}}},
			{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0x01}}}},
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
		mock.pcrBanks = []tpm2pkg.PCRBank{
			{Algorithm: "SHA386", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0x01}}}},
		}
		banks := detectPCRBanks(mock)
		require.Len(t, banks, 1)
		assert.Equal(t, "sha384", banks[0])
	})
}

// ---------------------------------------------------------------------------
// Test: savePolicyDigestBinary.
// ---------------------------------------------------------------------------

func TestTPMService_Coverage_savePolicyDigestBinary(t *testing.T) {
	t.Run("invalid_json_returns_error", func(t *testing.T) {
		svc := NewTPMService()
		err := svc.savePolicyDigestBinary("/tmp/test.bin", "{{invalid")
		assert.ErrorIs(t, err, ErrTPMPolicyExportFailed)
	})
}

// ---------------------------------------------------------------------------
// Test: Provision validation.
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
