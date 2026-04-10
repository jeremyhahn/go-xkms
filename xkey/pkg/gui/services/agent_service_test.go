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
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// mockCAService implements agent.CAService for testing.
type mockCAService struct {
	signCSRFunc    func(csrPEM []byte) ([]byte, error)
	getCACertFunc  func() ([]byte, error)
	revokeCertFunc func(serialNumber string) error
}

func (m *mockCAService) SignCSR(csrPEM []byte) ([]byte, error) {
	if m.signCSRFunc != nil {
		return m.signCSRFunc(csrPEM)
	}
	return []byte("-----BEGIN CERTIFICATE-----\nfake-cert\n-----END CERTIFICATE-----\n"), nil
}

func (m *mockCAService) GetCACertificate() ([]byte, error) {
	if m.getCACertFunc != nil {
		return m.getCACertFunc()
	}
	return []byte("-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----\n"), nil
}

func (m *mockCAService) RevokeCertificate(serialNumber string) error {
	if m.revokeCertFunc != nil {
		return m.revokeCertFunc(serialNumber)
	}
	return nil
}

// mockEventCollector captures emitted events for test assertions.
type mockEventCollector struct {
	mu     sync.Mutex
	events []events.Event
}

func (m *mockEventCollector) emit(evt events.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, evt)
}

func (m *mockEventCollector) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func (m *mockEventCollector) hasEventType(et events.EventType) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.events {
		if e.Type == et {
			return true
		}
	}
	return false
}

// setupAgentService creates an AgentService with a context and event collector.
func setupAgentService(t *testing.T) (*AgentService, *mockEventCollector) {
	t.Helper()
	svc := NewAgentService()
	svc.SetContext(context.Background())
	collector := &mockEventCollector{}
	svc.SetEventEmitter(collector.emit)
	return svc, collector
}

// setupAgentServiceWithEnrollment creates an AgentService with a fully
// configured enrollment service and memory store.
func setupAgentServiceWithEnrollment(t *testing.T) (*AgentService, *mockEventCollector, *agent.EnrollmentService, *agent.MemoryStore) {
	t.Helper()
	svc, collector := setupAgentService(t)

	cfg := agent.DefaultConfig()
	cfg.ListenAddress = ":0"
	cfg.EnrollmentMethods = []agent.EnrollmentMethod{
		agent.EnrollOneTimeCode,
		agent.EnrollAdminApproval,
	}

	ca := &mockCAService{}
	store := agent.NewMemoryStore()

	enrollment, err := agent.NewEnrollmentService(cfg, ca, store, slog.Default())
	if err != nil {
		t.Fatalf("failed to create enrollment service: %v", err)
	}

	svc.SetEnrollmentService(enrollment)
	svc.SetEnrollmentStore(store)
	return svc, collector, enrollment, store
}

func TestNewAgentService(t *testing.T) {
	svc := NewAgentService()
	if svc == nil {
		t.Fatal("NewAgentService returned nil")
	}
}

func TestNewAgentService_DefaultStatus(t *testing.T) {
	svc := NewAgentService()
	status := svc.GetServerStatus()
	if status == nil {
		t.Fatal("expected non-nil status from fresh service")
	}
	if status.Running {
		t.Error("fresh service should report not running")
	}
}

func TestAgentService_SetContext(t *testing.T) {
	svc := NewAgentService()
	ctx := context.WithValue(context.Background(), struct{ key string }{key: "test"}, "value")
	svc.SetContext(ctx)

	// Verify service works after SetContext.
	status := svc.GetServerStatus()
	if status == nil {
		t.Fatal("expected non-nil status after SetContext")
	}
}

func TestAgentService_SetContext_Nil(t *testing.T) {
	svc := NewAgentService()
	// Setting nil context should not panic.
	svc.SetContext(nil)
}

func TestAgentService_SetEventEmitter(t *testing.T) {
	svc := NewAgentService()
	called := false
	svc.SetEventEmitter(func(evt events.Event) {
		called = true
	})
	if called {
		t.Error("emitter should not have been called yet")
	}
}

func TestAgentService_SetEventEmitter_Nil(t *testing.T) {
	svc := NewAgentService()
	// Setting nil emitter should not panic.
	svc.SetEventEmitter(nil)
}

func TestAgentService_GetServerStatus_NotStarted(t *testing.T) {
	svc, _ := setupAgentService(t)

	status := svc.GetServerStatus()
	if status == nil {
		t.Fatal("expected non-nil status")
	}
	if status.Running {
		t.Error("server should not be running")
	}
	if status.ListenAddress != "" {
		t.Errorf("address should be empty, got %q", status.ListenAddress)
	}
	if status.ConnectedCount != 0 {
		t.Errorf("connected count should be 0, got %d", status.ConnectedCount)
	}
	if status.EnrolledCount != 0 {
		t.Errorf("enrolled count should be 0, got %d", status.EnrolledCount)
	}
}

func TestAgentService_StartServer_NoEnrollmentService(t *testing.T) {
	svc, _ := setupAgentService(t)

	err := svc.StartServer(":0")
	if err == nil {
		t.Fatal("expected error when starting without enrollment service")
	}
	if !errors.Is(err, ErrAgentServiceNotReady) {
		t.Errorf("expected ErrAgentServiceNotReady, got %v", err)
	}
}

func TestAgentService_StartServer_EmptyAddress(t *testing.T) {
	svc, _ := setupAgentService(t)

	err := svc.StartServer("")
	if err == nil {
		t.Fatal("expected error for empty address")
	}
	if !errors.Is(err, ErrAgentInvalidAddress) {
		t.Errorf("expected ErrAgentInvalidAddress, got %v", err)
	}
}

func TestAgentService_StartServer_Success(t *testing.T) {
	svc, collector, _, _ := setupAgentServiceWithEnrollment(t)

	err := svc.StartServer(":0")
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer svc.StopServer()

	// Allow the goroutine to start.
	time.Sleep(50 * time.Millisecond)

	status := svc.GetServerStatus()
	if !status.Running {
		t.Error("server should be running after StartServer")
	}
	if status.ListenAddress == "" {
		t.Error("server address should not be empty after start")
	}

	// Verify start event was emitted.
	if !collector.hasEventType(events.EventAgentServerStarted) {
		t.Error("expected EventAgentServerStarted event to be emitted")
	}
}

func TestAgentService_StartServer_AlreadyRunning(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	if err := svc.StartServer(":0"); err != nil {
		t.Fatalf("first StartServer failed: %v", err)
	}
	defer svc.StopServer()

	time.Sleep(50 * time.Millisecond)

	err := svc.StartServer(":0")
	if err == nil {
		t.Fatal("expected error when starting already-running server")
	}
	if !errors.Is(err, ErrAgentServerAlreadyRunning) {
		t.Errorf("expected ErrAgentServerAlreadyRunning, got %v", err)
	}
}

func TestAgentService_StopServer_NotStarted(t *testing.T) {
	svc, _ := setupAgentService(t)

	err := svc.StopServer()
	if err == nil {
		t.Fatal("expected error when stopping server that was not started")
	}
	if !errors.Is(err, ErrAgentServerNotStarted) {
		t.Errorf("expected ErrAgentServerNotStarted, got %v", err)
	}
}

func TestAgentService_StopServer_Success(t *testing.T) {
	svc, collector, _, _ := setupAgentServiceWithEnrollment(t)

	if err := svc.StartServer(":0"); err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	err := svc.StopServer()
	if err != nil {
		t.Fatalf("StopServer failed: %v", err)
	}

	status := svc.GetServerStatus()
	if status.Running {
		t.Error("server should not be running after StopServer")
	}

	if !collector.hasEventType(events.EventAgentServerStopped) {
		t.Error("expected EventAgentServerStopped event to be emitted")
	}
}

func TestAgentService_GenerateEnrollmentCode_NoEnrollment(t *testing.T) {
	svc, _ := setupAgentService(t)

	_, err := svc.GenerateEnrollmentCode()
	if err == nil {
		t.Fatal("expected error when generating code without enrollment service")
	}
	if !errors.Is(err, ErrAgentServiceNotReady) {
		t.Errorf("expected ErrAgentServiceNotReady, got %v", err)
	}
}

func TestAgentService_GenerateEnrollmentCode_Success(t *testing.T) {
	svc, collector, _, _ := setupAgentServiceWithEnrollment(t)

	info, err := svc.GenerateEnrollmentCode()
	if err != nil {
		t.Fatalf("GenerateEnrollmentCode failed: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil EnrollmentCodeInfo")
	}
	if info.Code == "" {
		t.Error("generated code should not be empty")
	}
	if info.ExpiresAt == "" {
		t.Error("expiry time should not be empty")
	}

	if !collector.hasEventType(events.EventAgentCodeGenerated) {
		t.Error("expected EventAgentCodeGenerated event to be emitted")
	}
}

func TestAgentService_GenerateEnrollmentCode_Uniqueness(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	codes := make(map[string]struct{})
	for i := 0; i < 50; i++ {
		info, err := svc.GenerateEnrollmentCode()
		if err != nil {
			t.Fatalf("GenerateEnrollmentCode failed on iteration %d: %v", i, err)
		}
		if _, ok := codes[info.Code]; ok {
			t.Errorf("duplicate code generated: %q", info.Code)
		}
		codes[info.Code] = struct{}{}
	}
}

func TestAgentService_ListPendingEnrollments_Empty(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	pending, err := svc.ListPendingEnrollments()
	if err != nil {
		t.Fatalf("ListPendingEnrollments failed: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected empty pending list, got %d", len(pending))
	}
}

func TestAgentService_ListPendingEnrollments_NoEnrollment(t *testing.T) {
	svc, _ := setupAgentService(t)

	_, err := svc.ListPendingEnrollments()
	if err == nil {
		t.Fatal("expected error when listing pending without enrollment service")
	}
	if !errors.Is(err, ErrAgentServiceNotReady) {
		t.Errorf("expected ErrAgentServiceNotReady, got %v", err)
	}
}

func TestAgentService_ListAgents_Empty(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	agents, err := svc.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents failed: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("expected empty agent list, got %d", len(agents))
	}
}

func TestAgentService_ListAgents_NoStore(t *testing.T) {
	svc, _ := setupAgentService(t)

	_, err := svc.ListAgents()
	if err == nil {
		t.Fatal("expected error when listing agents without enrollment store")
	}
	if !errors.Is(err, ErrAgentNilStore) {
		t.Errorf("expected ErrAgentNilStore, got %v", err)
	}
}

func TestAgentService_ListAgents_WithAgents(t *testing.T) {
	svc, _, _, store := setupAgentServiceWithEnrollment(t)

	now := time.Now()
	if err := store.SaveAgent(&agent.AgentInfo{
		ID:                     "agent-001",
		Name:                   "test-agent-1",
		Address:                "192.168.1.10:9443",
		CertificateFingerprint: "abc123",
		EnrolledAt:             now,
		LastSeen:               now,
		Status:                 "active",
	}); err != nil {
		t.Fatalf("failed to save agent: %v", err)
	}

	if err := store.SaveAgent(&agent.AgentInfo{
		ID:                     "agent-002",
		Name:                   "test-agent-2",
		Address:                "192.168.1.11:9443",
		CertificateFingerprint: "def456",
		EnrolledAt:             now,
		LastSeen:               now,
		Status:                 "active",
	}); err != nil {
		t.Fatalf("failed to save agent: %v", err)
	}

	agents, err := svc.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents failed: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}

	ids := make(map[string]bool)
	for _, a := range agents {
		ids[a.ID] = true
		if a.Name == "" {
			t.Error("agent name should not be empty")
		}
		if a.Status != "active" {
			t.Errorf("expected status 'active', got %q", a.Status)
		}
	}
	if !ids["agent-001"] {
		t.Error("agent-001 not found in list")
	}
	if !ids["agent-002"] {
		t.Error("agent-002 not found in list")
	}
}

func TestAgentService_RemoveAgent_EmptyID(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	err := svc.RemoveAgent("")
	if err == nil {
		t.Fatal("expected error for empty agent ID")
	}
	if !errors.Is(err, ErrAgentEmptyID) {
		t.Errorf("expected ErrAgentEmptyID, got %v", err)
	}
}

func TestAgentService_RemoveAgent_NotFound(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	err := svc.RemoveAgent("nonexistent-agent")
	if err == nil {
		t.Fatal("expected error for unknown agent ID")
	}
	if !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("expected ErrAgentNotFound, got %v", err)
	}
}

func TestAgentService_RemoveAgent_NoStore(t *testing.T) {
	svc, _ := setupAgentService(t)

	err := svc.RemoveAgent("some-id")
	if err == nil {
		t.Fatal("expected error when removing agent without store")
	}
	if !errors.Is(err, ErrAgentNilStore) {
		t.Errorf("expected ErrAgentNilStore, got %v", err)
	}
}

func TestAgentService_RemoveAgent_Success(t *testing.T) {
	svc, collector, _, store := setupAgentServiceWithEnrollment(t)

	if err := store.SaveAgent(&agent.AgentInfo{
		ID:         "agent-to-remove",
		Name:       "removable",
		Status:     "active",
		EnrolledAt: time.Now(),
		LastSeen:   time.Now(),
	}); err != nil {
		t.Fatalf("failed to save agent: %v", err)
	}

	// Verify it exists.
	agents, err := svc.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents failed: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent before removal, got %d", len(agents))
	}

	// Remove it.
	if err := svc.RemoveAgent("agent-to-remove"); err != nil {
		t.Fatalf("RemoveAgent failed: %v", err)
	}

	// Verify it was removed.
	agents, err = svc.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents after removal failed: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("expected 0 agents after removal, got %d", len(agents))
	}

	if !collector.hasEventType(events.EventAgentRemoved) {
		t.Error("expected EventAgentRemoved event to be emitted")
	}
}

func TestAgentService_ApproveEnrollment_EmptyRequestID(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	err := svc.ApproveEnrollment("")
	if err == nil {
		t.Fatal("expected error for empty request ID")
	}
	if !errors.Is(err, ErrAgentEmptyRequestID) {
		t.Errorf("expected ErrAgentEmptyRequestID, got %v", err)
	}
}

func TestAgentService_ApproveEnrollment_NoEnrollment(t *testing.T) {
	svc, _ := setupAgentService(t)

	err := svc.ApproveEnrollment("some-request-id")
	if err == nil {
		t.Fatal("expected error when approving without enrollment service")
	}
	if !errors.Is(err, ErrAgentServiceNotReady) {
		t.Errorf("expected ErrAgentServiceNotReady, got %v", err)
	}
}

func TestAgentService_RejectEnrollment_EmptyRequestID(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	err := svc.RejectEnrollment("", "no reason")
	if err == nil {
		t.Fatal("expected error for empty request ID")
	}
	if !errors.Is(err, ErrAgentEmptyRequestID) {
		t.Errorf("expected ErrAgentEmptyRequestID, got %v", err)
	}
}

func TestAgentService_RejectEnrollment_NoEnrollment(t *testing.T) {
	svc, _ := setupAgentService(t)

	err := svc.RejectEnrollment("some-request-id", "reason")
	if err == nil {
		t.Fatal("expected error when rejecting without enrollment service")
	}
	if !errors.Is(err, ErrAgentServiceNotReady) {
		t.Errorf("expected ErrAgentServiceNotReady, got %v", err)
	}
}

func TestAgentService_EventsEmitted_NoEmitter(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	// Clear the emitter to verify no panic when events are emitted
	// without an emitter configured.
	svc.SetEventEmitter(nil)

	if err := svc.StartServer(":0"); err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer svc.StopServer()

	time.Sleep(50 * time.Millisecond)

	// Generate code without emitter -- should not panic.
	info, err := svc.GenerateEnrollmentCode()
	if err != nil {
		t.Fatalf("GenerateEnrollmentCode failed: %v", err)
	}
	if info.Code == "" {
		t.Error("code should not be empty even without emitter")
	}
}

func TestAgentService_StartStop_Lifecycle(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	// Start -> Stop -> Start -> Stop should work without errors.
	if err := svc.StartServer(":0"); err != nil {
		t.Fatalf("first StartServer failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if err := svc.StopServer(); err != nil {
		t.Fatalf("first StopServer failed: %v", err)
	}

	// Start again after stopping.
	if err := svc.StartServer(":0"); err != nil {
		t.Fatalf("second StartServer failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if err := svc.StopServer(); err != nil {
		t.Fatalf("second StopServer failed: %v", err)
	}

	// Verify final state.
	status := svc.GetServerStatus()
	if status.Running {
		t.Error("server should not be running after final stop")
	}
}

func TestAgentService_RemoveAgent_VerifyStoreState(t *testing.T) {
	svc, _, _, store := setupAgentServiceWithEnrollment(t)

	for _, id := range []string{"keep-1", "remove-me", "keep-2"} {
		if err := store.SaveAgent(&agent.AgentInfo{
			ID:         id,
			Name:       id,
			Status:     "active",
			EnrolledAt: time.Now(),
			LastSeen:   time.Now(),
		}); err != nil {
			t.Fatalf("failed to save agent %q: %v", id, err)
		}
	}

	// Remove one agent.
	if err := svc.RemoveAgent("remove-me"); err != nil {
		t.Fatalf("RemoveAgent failed: %v", err)
	}

	// Verify store state: 2 agents remaining.
	remaining, err := store.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents failed: %v", err)
	}
	if len(remaining) != 2 {
		t.Fatalf("expected 2 remaining agents, got %d", len(remaining))
	}

	ids := make(map[string]bool)
	for _, a := range remaining {
		ids[a.ID] = true
	}
	if ids["remove-me"] {
		t.Error("removed agent should not be in store")
	}
	if !ids["keep-1"] {
		t.Error("keep-1 should still be in store")
	}
	if !ids["keep-2"] {
		t.Error("keep-2 should still be in store")
	}
}

func TestAgentService_SetEnrollmentService_Nil(t *testing.T) {
	svc, _ := setupAgentService(t)

	// Setting nil enrollment service should not panic.
	svc.SetEnrollmentService(nil)

	// Operations should return the appropriate error.
	err := svc.StartServer(":0")
	if !errors.Is(err, ErrAgentServiceNotReady) {
		t.Errorf("expected ErrAgentServiceNotReady after setting nil enrollment, got %v", err)
	}
}

func TestAgentService_SetEnrollmentStore_Nil(t *testing.T) {
	svc, _ := setupAgentService(t)

	// Setting nil store should not panic.
	svc.SetEnrollmentStore(nil)

	// Operations that need the store should return an error.
	_, err := svc.ListAgents()
	if !errors.Is(err, ErrAgentNilStore) {
		t.Errorf("expected ErrAgentNilStore after setting nil store, got %v", err)
	}
}
