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
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// Agent service errors.
var (
	ErrAgentServiceNotReady      = errors.New("agent_service: not initialized")
	ErrAgentServerNotStarted     = errors.New("agent_service: server not started")
	ErrAgentServerAlreadyRunning = errors.New("agent_service: server already running")
	ErrAgentInvalidAddress       = errors.New("agent_service: invalid listen address")
	ErrAgentNilCAService         = errors.New("agent_service: CA service required")
	ErrAgentNilStore             = errors.New("agent_service: enrollment store required")
	ErrAgentEnrollmentFailed     = errors.New("agent_service: enrollment operation failed")
	ErrAgentNotFound             = errors.New("agent_service: agent not found")
	ErrAgentEmptyID              = errors.New("agent_service: agent ID is empty")
	ErrAgentEmptyRequestID       = errors.New("agent_service: request ID is empty")
)

// AgentDeviceInfo describes an enrolled agent for the Devices page.
type AgentDeviceInfo struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	Address                string `json:"address"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
	EnrolledAt             string `json:"enrolled_at"`
	LastSeen               string `json:"last_seen"`
	Status                 string `json:"status"` // "active", "revoked", "connected"
	Connected              bool   `json:"connected"`
}

// AgentServerStatus describes the current agent server state.
type AgentServerStatus struct {
	Running           bool     `json:"running"`
	ListenAddress     string   `json:"listen_address"`
	ConnectedCount    int      `json:"connected_count"`
	EnrolledCount     int      `json:"enrolled_count"`
	EnrollmentMethods []string `json:"enrollment_methods"`
}

// PendingEnrollmentInfo describes a pending enrollment request for the UI.
type PendingEnrollmentInfo struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	RequestedAt string `json:"requested_at"`
	Status      string `json:"status"`
}

// EnrollmentCodeInfo describes a generated one-time enrollment code.
type EnrollmentCodeInfo struct {
	Code      string `json:"code"`
	ExpiresAt string `json:"expires_at"`
}

// AgentService manages the network agent server and enrolled agents.
// It exposes agent server lifecycle, enrollment management, and device
// listing to the Wails frontend. All exported methods are safe for
// concurrent use.
type AgentService struct {
	ctx        context.Context
	log        *slog.Logger
	mu         sync.RWMutex
	server     *agent.Server
	enrollment *agent.EnrollmentService
	store      agent.EnrollmentStore
	emitter    func(events.Event)
}

// NewAgentService creates a new AgentService.
func NewAgentService() *AgentService {
	return &AgentService{
		log: slog.Default().With("component", "agent_service"),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *AgentService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetEventEmitter sets the event callback for frontend notifications.
func (s *AgentService) SetEventEmitter(fn func(events.Event)) {
	s.emitter = fn
}

// SetEnrollmentService sets the enrollment service used for managing
// agent enrollment operations.
func (s *AgentService) SetEnrollmentService(svc *agent.EnrollmentService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrollment = svc
}

// SetEnrollmentStore sets the backing enrollment store for agent persistence.
func (s *AgentService) SetEnrollmentStore(store agent.EnrollmentStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = store
}

// StartServer creates and starts the agent server on the given listen address.
// It configures the server with default enrollment methods (one_time_code and
// admin_approval) and emits an "agent:server_started" event on success.
func (s *AgentService) StartServer(listenAddress string) error {
	if listenAddress == "" {
		return ErrAgentInvalidAddress
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.server != nil && s.server.IsRunning() {
		return ErrAgentServerAlreadyRunning
	}

	if s.enrollment == nil {
		return ErrAgentServiceNotReady
	}

	cfg := agent.DefaultConfig()
	cfg.ListenAddress = listenAddress
	cfg.EnrollmentMethods = []agent.EnrollmentMethod{
		agent.EnrollOneTimeCode,
		agent.EnrollAdminApproval,
	}

	server, err := agent.NewServer(cfg, s.enrollment, s.log)
	if err != nil {
		s.log.Error("failed to create agent server", "error", err)
		return ErrAgentServiceNotReady
	}

	if err := server.Start(); err != nil {
		s.log.Error("failed to start agent server", "address", listenAddress, "error", err)
		return ErrAgentServerNotStarted
	}

	s.server = server

	s.log.Info("agent server started", "address", listenAddress)
	s.emit(events.EventAgentServerStarted, events.AgentServerStartedPayload{
		ListenAddress: listenAddress,
	})

	return nil
}

// StopServer stops the running agent server and emits an
// "agent:server_stopped" event on success.
func (s *AgentService) StopServer() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.server == nil || !s.server.IsRunning() {
		return ErrAgentServerNotStarted
	}

	if err := s.server.Stop(); err != nil {
		s.log.Error("failed to stop agent server", "error", err)
		return ErrAgentServerNotStarted
	}

	s.log.Info("agent server stopped")
	s.emit(events.EventAgentServerStopped, events.AgentServerStoppedPayload{})

	s.server = nil

	return nil
}

// GetServerStatus returns the current state of the agent server including
// running status, connected agent count, enrolled agent count, and the
// configured enrollment methods.
func (s *AgentService) GetServerStatus() *AgentServerStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := &AgentServerStatus{}

	if s.server == nil || !s.server.IsRunning() {
		return status
	}

	status.Running = true
	status.ListenAddress = s.server.Addr()
	status.ConnectedCount = len(s.server.ConnectedAgents())

	// Count enrolled agents from the store.
	if s.store != nil {
		agents, err := s.store.ListAgents()
		if err == nil {
			status.EnrolledCount = len(agents)
		} else {
			s.log.Warn("failed to count enrolled agents", "error", err)
		}
	}

	// Report configured enrollment methods.
	status.EnrollmentMethods = []string{
		string(agent.EnrollOneTimeCode),
		string(agent.EnrollAdminApproval),
	}

	return status
}

// GenerateEnrollmentCode generates a one-time enrollment code using the
// configured default validity period. Emits an "agent:code_generated" event
// on success.
func (s *AgentService) GenerateEnrollmentCode() (*EnrollmentCodeInfo, error) {
	s.mu.RLock()
	enrollment := s.enrollment
	s.mu.RUnlock()

	if enrollment == nil {
		return nil, ErrAgentServiceNotReady
	}

	otc, err := enrollment.GenerateOneTimeCode(0)
	if err != nil {
		s.log.Error("failed to generate enrollment code", "error", err)
		return nil, ErrAgentEnrollmentFailed
	}

	info := &EnrollmentCodeInfo{
		Code:      otc.Code,
		ExpiresAt: otc.ExpiresAt.Format(time.RFC3339),
	}

	s.log.Info("enrollment code generated", "expires_at", info.ExpiresAt)
	s.emit(events.EventAgentCodeGenerated, events.AgentCodeGeneratedPayload{
		ExpiresAt: info.ExpiresAt,
	})

	return info, nil
}

// ListPendingEnrollments returns all pending enrollment requests awaiting
// administrator approval.
func (s *AgentService) ListPendingEnrollments() ([]PendingEnrollmentInfo, error) {
	s.mu.RLock()
	enrollment := s.enrollment
	s.mu.RUnlock()

	if enrollment == nil {
		return nil, ErrAgentServiceNotReady
	}

	pending, err := enrollment.ListPending()
	if err != nil {
		s.log.Error("failed to list pending enrollments", "error", err)
		return nil, ErrAgentEnrollmentFailed
	}

	infos := make([]PendingEnrollmentInfo, 0, len(pending))
	for _, p := range pending {
		infos = append(infos, PendingEnrollmentInfo{
			ID:          p.ID,
			Fingerprint: p.Fingerprint,
			RequestedAt: p.RequestedAt.Format(time.RFC3339),
			Status:      p.Status,
		})
	}

	return infos, nil
}

// ApproveEnrollment approves a pending enrollment request identified by
// the given request ID. Emits an "agent:enrollment_approved" event on success.
func (s *AgentService) ApproveEnrollment(requestID string) error {
	if requestID == "" {
		return ErrAgentEmptyRequestID
	}

	s.mu.RLock()
	enrollment := s.enrollment
	s.mu.RUnlock()

	if enrollment == nil {
		return ErrAgentServiceNotReady
	}

	_, _, err := enrollment.ApproveEnrollment(requestID)
	if err != nil {
		s.log.Error("failed to approve enrollment", "request_id", requestID, "error", err)
		return ErrAgentEnrollmentFailed
	}

	s.log.Info("enrollment approved", "request_id", requestID)
	s.emit(events.EventAgentEnrollmentApproved, events.AgentEnrollmentPayload{
		RequestID: requestID,
	})

	return nil
}

// RejectEnrollment rejects a pending enrollment request with the given reason.
// Emits an "agent:enrollment_rejected" event on success.
func (s *AgentService) RejectEnrollment(requestID, reason string) error {
	if requestID == "" {
		return ErrAgentEmptyRequestID
	}

	s.mu.RLock()
	enrollment := s.enrollment
	s.mu.RUnlock()

	if enrollment == nil {
		return ErrAgentServiceNotReady
	}

	if err := enrollment.RejectEnrollment(requestID, reason); err != nil {
		s.log.Error("failed to reject enrollment",
			"request_id", requestID, "reason", reason, "error", err)
		return ErrAgentEnrollmentFailed
	}

	s.log.Info("enrollment rejected", "request_id", requestID, "reason", reason)
	s.emit(events.EventAgentEnrollmentRejected, events.AgentEnrollmentPayload{
		RequestID: requestID,
		Reason:    reason,
	})

	return nil
}

// ListAgents returns all enrolled agents with their connected state resolved
// against the server's active connections.
func (s *AgentService) ListAgents() ([]AgentDeviceInfo, error) {
	s.mu.RLock()
	store := s.store
	server := s.server
	s.mu.RUnlock()

	if store == nil {
		return nil, ErrAgentNilStore
	}

	agents, err := store.ListAgents()
	if err != nil {
		s.log.Error("failed to list agents", "error", err)
		return nil, ErrAgentEnrollmentFailed
	}

	// Build a set of connected agent IDs for O(1) lookup.
	connectedIDs := make(map[string]struct{})
	if server != nil && server.IsRunning() {
		for _, ca := range server.ConnectedAgents() {
			if ca.Info != nil {
				connectedIDs[ca.Info.ID] = struct{}{}
			}
		}
	}

	infos := make([]AgentDeviceInfo, 0, len(agents))
	for _, a := range agents {
		_, isConnected := connectedIDs[a.ID]

		status := a.Status
		if isConnected {
			status = "connected"
		}

		infos = append(infos, AgentDeviceInfo{
			ID:                     a.ID,
			Name:                   a.Name,
			Address:                a.Address,
			CertificateFingerprint: a.CertificateFingerprint,
			EnrolledAt:             a.EnrolledAt.Format(time.RFC3339),
			LastSeen:               a.LastSeen.Format(time.RFC3339),
			Status:                 status,
			Connected:              isConnected,
		})
	}

	return infos, nil
}

// RemoveAgent removes an enrolled agent from the store by its ID.
// Emits an "agent:removed" event on success.
func (s *AgentService) RemoveAgent(agentID string) error {
	if agentID == "" {
		return ErrAgentEmptyID
	}

	s.mu.RLock()
	store := s.store
	s.mu.RUnlock()

	if store == nil {
		return ErrAgentNilStore
	}

	if err := store.DeleteAgent(agentID); err != nil {
		s.log.Error("failed to remove agent", "agent_id", agentID, "error", err)
		return ErrAgentNotFound
	}

	s.log.Info("agent removed", "agent_id", agentID)
	s.emit(events.EventAgentRemoved, events.AgentRemovedPayload{
		AgentID: agentID,
	})

	return nil
}

// emit sends an event to the frontend if an emitter is registered.
func (s *AgentService) emit(eventType events.EventType, payload any) {
	if s.emitter != nil {
		s.emitter(events.Event{
			Type:    eventType,
			Payload: payload,
			Time:    time.Now(),
		})
	}
}
