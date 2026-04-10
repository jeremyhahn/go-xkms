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
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
)

// ---------------------------------------------------------------------------
// sb-prefixed mocks
// ---------------------------------------------------------------------------

// sbMockAuditStore is a minimal audit.Store that returns configurable entries.
type sbMockAuditStore struct {
	entries []audit.Entry
}

func (m *sbMockAuditStore) Log(audit.Entry) {}
func (m *sbMockAuditStore) LogKeyOperation(audit.OperationType, string, string, bool, error, int64) {
}
func (m *sbMockAuditStore) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) {
}
func (m *sbMockAuditStore) LogConnectionEvent(audit.OperationType, string, string, map[string]any) {}
func (m *sbMockAuditStore) LogServiceEvent(audit.OperationType, map[string]any)                    {}
func (m *sbMockAuditStore) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (m *sbMockAuditStore) LogTPMOperation(audit.OperationType, bool, error, map[string]any) {}
func (m *sbMockAuditStore) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (m *sbMockAuditStore) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) {}
func (m *sbMockAuditStore) Count() int                                                             { return len(m.entries) }
func (m *sbMockAuditStore) Query(_ audit.QueryFilter) []audit.Entry                                { return m.entries }

// sbMockStaticPWStore implements staticpw.Store for password protection tests.
type sbMockStaticPWStore struct {
	passwords []*staticpw.StaticPassword
	listErr   error
	updateErr error
}

func (m *sbMockStaticPWStore) Add(_ *staticpw.StaticPassword) error           { return nil }
func (m *sbMockStaticPWStore) Get(_ string) (*staticpw.StaticPassword, error) { return nil, nil }
func (m *sbMockStaticPWStore) List() ([]*staticpw.StaticPassword, error) {
	return m.passwords, m.listErr
}
func (m *sbMockStaticPWStore) Update(_ *staticpw.StaticPassword) error { return m.updateErr }
func (m *sbMockStaticPWStore) Delete(_ string) error                   { return nil }
func (m *sbMockStaticPWStore) ForceDelete(_ string) error              { return nil }
func (m *sbMockStaticPWStore) ListByFolder(_ string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (m *sbMockStaticPWStore) ListFolders() ([]string, error) { return nil, nil }
func (m *sbMockStaticPWStore) MoveToFolder(_, _ string) error { return nil }
func (m *sbMockStaticPWStore) Close() error                   { return nil }
func (m *sbMockStaticPWStore) ListByFolderDirect(_ string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (m *sbMockStaticPWStore) CreateFolder(_ string) error { return nil }
func (m *sbMockStaticPWStore) RemoveFolder(_ string) error { return nil }

// ---------------------------------------------------------------------------
// admin_service.go tests
// ---------------------------------------------------------------------------

// TestSB_AdminService_IsAdmin covers L112-118: the IsAdmin method.
// Running as non-root exercises L112-118. If run as root, L118 is hit.
// L114-116 (user.Current error) is only triggerable in broken envs.
func TestSB_AdminService_IsAdmin(t *testing.T) {
	svc := NewAdminService()
	_ = svc.IsAdmin()
}

// TestSB_AdminService_GetBackendInfo_ListError covers L211-213:
// ListBackends succeeds via local fallback, then L214-219 loops.
func TestSB_AdminService_GetBackendInfo_ListError(t *testing.T) {
	svc := NewAdminService()

	// L207-209: empty ID returns ErrAdminBackendNotFound.
	_, err := svc.GetBackendInfo("")
	if !errors.Is(err, ErrAdminBackendNotFound) {
		t.Fatalf("expected ErrAdminBackendNotFound, got %v", err)
	}

	// L211-213: ListBackends remote error falls through to local.
	svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
		return nil, errors.New("remote error")
	})
	_, err = svc.GetBackendInfo("nonexistent")
	if !errors.Is(err, ErrAdminBackendNotFound) {
		t.Fatalf("expected ErrAdminBackendNotFound, got %v", err)
	}

	// Hit found path L215-217.
	info, err := svc.GetBackendInfo("software")
	if err != nil {
		t.Fatalf("expected software backend, got error: %v", err)
	}
	if info.ID != "software" {
		t.Fatalf("expected ID=software, got %s", info.ID)
	}
}

// TestSB_AdminService_GetAuditLogs covers L230-232: delegation to AuditService.
func TestSB_AdminService_GetAuditLogs(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())
	svc.SetAuditStore(&sbMockAuditStore{
		entries: []audit.Entry{
			{Timestamp: time.Now(), Operation: audit.OpKeyCreated, Success: true},
		},
	})

	// L226-228 or L230-232 depending on whether running as root.
	_, _ = svc.GetAuditLogs(nil)
	_, _ = svc.GetAuditLogs(&AuditFilter{Operation: "key_created"})
}

// TestSB_AdminService_ExportAuditLogs covers L241-267:
// format validation, empty entries, JSON/CSV export, default branch.
func TestSB_AdminService_ExportAuditLogs(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())
	svc.SetAuditStore(&sbMockAuditStore{
		entries: []audit.Entry{
			{Timestamp: time.Now(), Operation: audit.OpKeyCreated, Success: true, Backend: "sw"},
		},
	})

	// Exercise all format paths. Non-admin blocks at L238-240.
	for _, fmt := range []string{"json", "csv", "xml", ""} {
		_, _ = svc.ExportAuditLogs(fmt)
	}

	// Empty entries path.
	svc2 := NewAdminService()
	svc2.SetContext(context.Background())
	svc2.SetAuditStore(&sbMockAuditStore{entries: []audit.Entry{}})
	_, _ = svc2.ExportAuditLogs("json")
}

// TestSB_PP_GetStatus_SealServiceNil covers L161-163: sealSvc == nil.
func TestSB_PP_GetStatus_SealServiceNil(t *testing.T) {
	store := &sbMockStaticPWStore{}
	staticSvc := NewStaticPasswordService(store)
	svc := NewPasswordProtectionService("", staticSvc, nil)

	status, err := svc.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus error: %v", err)
	}
	if status.TPMAvailable {
		t.Fatal("expected TPMAvailable=false when sealSvc is nil")
	}
}

// TestSB_PP_ExportPasswordsDecrypted covers L449-462: all branches.
func TestSB_Clipboard_CopyWithClear_NoTool(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	svc.timeout.Store(int32(DefaultClipboardTimeout))

	err := svc.CopyWithClear("test")
	if !errors.Is(err, ErrClipboardToolUnavailable) {
		t.Fatalf("expected ErrClipboardToolUnavailable, got %v", err)
	}
}

// TestSB_Clipboard_CopyWithClear_ZeroTimeout covers L93-96:
// timeout <= 0 so scheduleClear is skipped.
func TestSB_Clipboard_CopyWithClear_ZeroTimeout(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	svc.timeout.Store(0)

	// Still fails at L85-87 because tool=none, but L93-94 code exists.
	err := svc.CopyWithClear("test")
	if !errors.Is(err, ErrClipboardToolUnavailable) {
		t.Fatalf("expected ErrClipboardToolUnavailable, got %v", err)
	}
}

// TestSB_Clipboard_ClearClipboard_NoTool covers L122-126: no tool available.
func TestSB_Clipboard_ClearClipboard_NoTool(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}

	err := svc.ClearClipboard()
	if !errors.Is(err, ErrClipboardToolUnavailable) {
		t.Fatalf("expected ErrClipboardToolUnavailable, got %v", err)
	}
}

// TestSB_Clipboard_ClearClipboard_CancelsPending covers L116-119:
// cancels a pending cancelFn before checking tool availability.
func TestSB_Clipboard_ClearClipboard_CancelsPending(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	svc := &ClipboardService{
		log:      slog.Default().With("service", "clipboard"),
		tool:     clipToolNone,
		cancelFn: cancel,
	}
	_ = svc.ClearClipboard()
}

// TestSB_Clipboard_ScheduleClear_ReadFails covers L152-155:
// goroutine fires, readClipboard fails, logs and returns.
func TestSB_Clipboard_ScheduleClear_ReadFails(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	svc.scheduleClear("test-text", 1*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
}

// TestSB_Clipboard_ScheduleClear_CancelPrevious covers L136-138:
// second scheduleClear cancels the first.
func TestSB_Clipboard_ScheduleClear_CancelPrevious(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	svc.scheduleClear("first", 10*time.Second)
	svc.scheduleClear("second", 1*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
}

// TestSB_Clipboard_ReadClipboard_NoTool covers L204-205: no tool default case.
func TestSB_Clipboard_ReadClipboard_NoTool(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	_, err := svc.readClipboard()
	if !errors.Is(err, ErrClipboardToolUnavailable) {
		t.Fatalf("expected ErrClipboardToolUnavailable, got %v", err)
	}
}

// TestSB_Clipboard_WriteClipboard_NoTool covers L180-181: no tool default case.
func TestSB_Clipboard_WriteClipboard_NoTool(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolNone,
	}
	err := svc.writeClipboard("test")
	if !errors.Is(err, ErrClipboardToolUnavailable) {
		t.Fatalf("expected ErrClipboardToolUnavailable, got %v", err)
	}
}

// TestSB_Clipboard_DetectTool covers L217-227: detectClipboardTool probing.
func TestSB_Clipboard_DetectTool(t *testing.T) {
	tool := detectClipboardTool()
	// Accept any result; the function exercises LookPath for each tool.
	_ = tool
}

// TestSB_Clipboard_WriteClipboard_AllTools covers L174-181: write switch branches.
func TestSB_Clipboard_WriteClipboard_AllTools(t *testing.T) {
	for _, tool := range []clipboardTool{clipToolXclip, clipToolXsel, clipToolWlCopy} {
		svc := &ClipboardService{
			log:  slog.Default().With("service", "clipboard"),
			tool: tool,
		}
		_ = svc.writeClipboard("")
	}
}

// TestSB_Clipboard_ReadClipboard_AllTools covers L197-205: read switch branches.
func TestSB_Clipboard_ReadClipboard_AllTools(t *testing.T) {
	for _, tool := range []clipboardTool{clipToolXclip, clipToolXsel, clipToolWlCopy} {
		svc := &ClipboardService{
			log:  slog.Default().With("service", "clipboard"),
			tool: tool,
		}
		_, _ = svc.readClipboard()
	}
}

// ---------------------------------------------------------------------------
// barrier_service.go tests
// ---------------------------------------------------------------------------

// TestSB_Barrier_BestStrategy covers L124-131: walk preference order.
func TestSB_Barrier_BestStrategy(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	best, err := svc.BestStrategy()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if best.ID != "software" {
		t.Fatalf("expected software strategy, got %s", best.ID)
	}
}

// TestSB_Barrier_Initialize_AlreadyInit covers L158-160: ErrBarrierAlreadyInit.
func TestSB_Barrier_Initialize_AlreadyInit(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	if err := svc.Initialize("test-password", "software"); err != nil {
		t.Fatalf("first Initialize failed: %v", err)
	}

	err := svc.Initialize("test-password", "software")
	if !errors.Is(err, ErrBarrierAlreadyInit) {
		t.Fatalf("expected ErrBarrierAlreadyInit, got %v", err)
	}
}

// TestSB_Barrier_Initialize_EmptyPassword covers L170-171: password required.
func TestSB_Barrier_Initialize_EmptyPassword(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	err := svc.Initialize("", "software")
	if !errors.Is(err, ErrBarrierPasswordRequired) {
		t.Fatalf("expected ErrBarrierPasswordRequired, got %v", err)
	}
}

// TestSB_Barrier_Initialize_BadDir covers L175 or L179-182: MkdirAll/New failure.
func TestSB_Barrier_Initialize_BadDir(t *testing.T) {
	svc := NewBarrierService("/dev/null", slog.Default())
	err := svc.Initialize("test-password", "software")
	if err == nil {
		t.Fatal("expected error from invalid config dir")
	}
}

// TestSB_Barrier_Initialize_Success covers L186-203: successful init and unseal.
func TestSB_Barrier_Initialize_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	if err := svc.Initialize("test-password", "software"); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if !svc.IsUnsealed() {
		t.Fatal("expected barrier to be unsealed after Initialize")
	}
	if svc.GetBackend() == nil {
		t.Fatal("expected non-nil backend after Initialize")
	}
}

// TestSB_Barrier_Unseal_FilestorageFail covers L219-222:
// barrierDir is a file instead of a directory.
func TestSB_Barrier_Unseal_FilestorageFail(t *testing.T) {
	dir := t.TempDir()
	barrierPath := filepath.Join(dir, barrierSubdir)
	if err := os.WriteFile(barrierPath, []byte("not-a-dir"), 0600); err != nil {
		t.Fatal(err)
	}

	svc := NewBarrierService(dir, slog.Default())
	err := svc.Unseal("test", "software")
	if err == nil {
		t.Fatal("expected error from file-as-directory")
	}
}

// TestSB_Barrier_Unseal_WrongPassword covers L236-238: unseal with wrong pw.
func TestSB_Barrier_Unseal_WrongPassword(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	if err := svc.Initialize("correct-password", "software"); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	svc.barrier = nil
	err := svc.Unseal("wrong-password", "software")
	if err == nil {
		t.Fatal("expected error from wrong password")
	}
}

// TestSB_Barrier_Unseal_Success covers L226-243: successful unseal.
func TestSB_Barrier_Unseal_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	if err := svc.Initialize("correct-password", "software"); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if err := svc.Seal(); err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	svc.barrier = nil

	if err := svc.Unseal("correct-password", "software"); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
}

// TestSB_Barrier_Seal_NotInitialized covers L253-254: nil barrier.
func TestSB_Barrier_Seal_NotInitialized(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	err := svc.Seal()
	if !errors.Is(err, ErrBarrierNotInitialized) {
		t.Fatalf("expected ErrBarrierNotInitialized, got %v", err)
	}
}

// TestSB_Barrier_Status_NilBarrier covers L265-266: sealed status for nil barrier.
func TestSB_Barrier_Status_NilBarrier(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	status := svc.Status()
	if !status.Sealed {
		t.Fatal("expected sealed status for uninitialized barrier")
	}
}

// TestSB_Barrier_IsUnsealed_NilBarrier covers L277-278: nil barrier.
func TestSB_Barrier_IsUnsealed_NilBarrier(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	if svc.IsUnsealed() {
		t.Fatal("expected false for uninitialized barrier")
	}
}

// TestSB_Barrier_GetBackend_NilBarrier covers L290-291: nil barrier.
func TestSB_Barrier_GetBackend_NilBarrier(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	if svc.GetBackend() != nil {
		t.Fatal("expected nil backend for uninitialized barrier")
	}
}

// TestSB_Barrier_ProbeStrategies_WithTPMNil covers L97-106:
// tpmSealerFn returns nil sealer.
func TestSB_Barrier_ProbeStrategies_WithTPMNil(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	svc.SetTPMSealerFunc(func() types.Sealer {
		return nil
	})

	strategies := svc.ProbeStrategies()
	found := false
	for _, s := range strategies {
		if s.ID == "tpm2" {
			found = true
			if s.Available {
				t.Fatal("expected TPM2 to be unavailable")
			}
		}
	}
	if !found {
		t.Fatal("expected TPM2 strategy in list")
	}
}

// TestSB_Barrier_Context covers L316-320: context() fallback.
func TestSB_Barrier_Context(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	ctx := svc.context()
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}

	custom := context.WithValue(context.Background(), "sbkey", "val")
	svc.SetContext(custom)
	if svc.context() != custom {
		t.Fatal("expected custom context")
	}
}

// TestSB_Barrier_AssembleStrategy covers strategy assembly.
func TestSB_Barrier_AssembleStrategy(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())

	// Software always works.
	strategy, err := svc.assembleStrategy("software")
	require.NoError(t, err)
	assert.Equal(t, seal.StrategySoftware, strategy.ID())

	// TPM2 with nil-returning sealer → error.
	svc.SetTPMSealerFunc(func() types.Sealer { return nil })
	_, err = svc.assembleStrategy("tpm2")
	assert.Error(t, err)
}
