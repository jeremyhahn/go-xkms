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
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// CustodianGroupInfo is the frontend-visible custodian group metadata.
type CustodianGroupInfo struct {
	ID        string                `json:"id"`
	TenantID  string                `json:"tenant_id,omitempty"`
	Name      string                `json:"name"`
	Purpose   string                `json:"purpose"`
	Threshold int                   `json:"threshold"`
	Total     int                   `json:"total"`
	Members   []CustodianMemberInfo `json:"members"`
	CreatedAt string                `json:"created_at"`
	UpdatedAt string                `json:"updated_at"`
}

// CustodianMemberInfo is the frontend-visible custodian member metadata.
type CustodianMemberInfo struct {
	ShareIndex int    `json:"share_index"`
	UserID     string `json:"user_id"`
	Username   string `json:"username"`
	AssignedAt string `json:"assigned_at"`
	ReceivedAt string `json:"received_at,omitempty"`
	Method     string `json:"method"`
}

// CustodianService manages custodian groups for Shamir secret sharing
// ceremonies. It wraps the SDK CustodianGroupService interface and provides
// frontend-safe types and event emission.
type CustodianService struct {
	ctx     context.Context
	log     *slog.Logger
	client  atomic.Pointer[transport.Client]
	emitter func(events.Event)
}

// NewCustodianService creates a new CustodianService.
func NewCustodianService() *CustodianService {
	return &CustodianService{
		log: slog.Default().With("component", "custodian_service"),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *CustodianService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetEventEmitter sets the event callback for frontend notifications.
func (s *CustodianService) SetEventEmitter(fn func(events.Event)) {
	s.emitter = fn
}

// SetClient sets the transport client used to communicate with the server.
func (s *CustodianService) SetClient(c transport.Client) {
	s.client.Store(&c)
}

// getClient returns the current transport client or an error.
func (s *CustodianService) getClient() (transport.Client, error) {
	ptr := s.client.Load()
	if ptr == nil {
		return nil, ErrCustodianServiceNoClient
	}
	return *ptr, nil
}

// CreateGroup creates a new custodian group on the server.
func (s *CustodianService) CreateGroup(name, purpose string, threshold, total int) (*CustodianGroupInfo, error) {
	if name == "" {
		return nil, ErrCustodianGroupNameRequired
	}
	if threshold < 1 {
		return nil, ErrCustodianInvalidThreshold
	}
	if total < threshold {
		return nil, ErrCustodianInvalidTotal
	}

	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	resp, err := client.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		Name:      name,
		Purpose:   purpose,
		Threshold: threshold,
		Total:     total,
	})
	if err != nil {
		s.log.Error("failed to create custodian group", "name", name, "error", err)
		return nil, err
	}

	info := transportGroupToInfo(&resp.Group)
	s.emit(events.EventCustodianGroupCreated, info)
	s.log.Info("custodian group created", "id", resp.Group.ID, "name", name)
	return info, nil
}

// GetGroup retrieves a custodian group by ID.
func (s *CustodianService) GetGroup(groupID string) (*CustodianGroupInfo, error) {
	if groupID == "" {
		return nil, ErrCustodianGroupIDRequired
	}

	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	resp, err := client.GetCustodianGroup(ctx, groupID)
	if err != nil {
		s.log.Error("failed to get custodian group", "group_id", groupID, "error", err)
		return nil, err
	}

	return transportGroupToInfo(&resp.Group), nil
}

// ListGroups lists all custodian groups.
func (s *CustodianService) ListGroups() ([]CustodianGroupInfo, error) {
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	resp, err := client.ListCustodianGroups(ctx)
	if err != nil {
		s.log.Error("failed to list custodian groups", "error", err)
		return nil, err
	}

	groups := make([]CustodianGroupInfo, 0, len(resp.Groups))
	for i := range resp.Groups {
		groups = append(groups, *transportGroupToInfo(&resp.Groups[i]))
	}
	return groups, nil
}

// DeleteGroup deletes a custodian group.
func (s *CustodianService) DeleteGroup(groupID string) error {
	if groupID == "" {
		return ErrCustodianGroupIDRequired
	}

	client, err := s.getClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	if err := client.DeleteCustodianGroup(ctx, groupID); err != nil {
		s.log.Error("failed to delete custodian group", "group_id", groupID, "error", err)
		return err
	}

	s.emit(events.EventCustodianGroupDeleted, map[string]string{"group_id": groupID})
	s.log.Info("custodian group deleted", "group_id", groupID)
	return nil
}

// AddMember adds a member to a custodian group.
func (s *CustodianService) AddMember(groupID, userID, username, method string) (*CustodianMemberInfo, error) {
	if groupID == "" {
		return nil, ErrCustodianGroupIDRequired
	}
	if userID == "" {
		return nil, ErrCustodianUserIDRequired
	}

	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	resp, err := client.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID:  groupID,
		UserID:   userID,
		Username: username,
		Method:   method,
	})
	if err != nil {
		s.log.Error("failed to add custodian member", "group_id", groupID, "user_id", userID, "error", err)
		return nil, err
	}

	info := transportMemberToInfo(&resp.Member)
	s.emit(events.EventCustodianMemberAdded, map[string]any{
		"group_id": groupID,
		"member":   info,
	})
	s.log.Info("custodian member added", "group_id", groupID, "user_id", userID)
	return info, nil
}

// RemoveMember removes a member from a custodian group.
func (s *CustodianService) RemoveMember(groupID, userID string) error {
	if groupID == "" {
		return ErrCustodianGroupIDRequired
	}
	if userID == "" {
		return ErrCustodianUserIDRequired
	}

	client, err := s.getClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	if err := client.RemoveCustodianMember(ctx, &transport.RemoveCustodianMemberRequest{
		GroupID: groupID,
		UserID:  userID,
	}); err != nil {
		s.log.Error("failed to remove custodian member", "group_id", groupID, "user_id", userID, "error", err)
		return err
	}

	s.emit(events.EventCustodianMemberRemoved, map[string]string{
		"group_id": groupID,
		"user_id":  userID,
	})
	s.log.Info("custodian member removed", "group_id", groupID, "user_id", userID)
	return nil
}

// DistributeShares triggers Shamir share distribution to all group members.
func (s *CustodianService) DistributeShares(groupID string) (int, error) {
	if groupID == "" {
		return 0, ErrCustodianGroupIDRequired
	}

	client, err := s.getClient()
	if err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	resp, err := client.DistributeShares(ctx, &transport.DistributeSharesRequest{
		GroupID: groupID,
	})
	if err != nil {
		s.log.Error("failed to distribute shares", "group_id", groupID, "error", err)
		return 0, err
	}

	s.emit(events.EventCustodianSharesDistributed, map[string]any{
		"group_id":    groupID,
		"distributed": resp.Distributed,
	})
	s.log.Info("shares distributed", "group_id", groupID, "distributed", resp.Distributed)
	return resp.Distributed, nil
}

// emit sends an event to the frontend if an emitter is registered.
func (s *CustodianService) emit(eventType events.EventType, payload any) {
	if s.emitter != nil {
		s.emitter(events.Event{
			Type:    eventType,
			Payload: payload,
			Time:    time.Now(),
		})
	}
}

// transportGroupToInfo converts a transport CustodianGroupInfo to a frontend-safe CustodianGroupInfo.
func transportGroupToInfo(g *transport.CustodianGroupInfo) *CustodianGroupInfo {
	members := make([]CustodianMemberInfo, 0, len(g.Members))
	for i := range g.Members {
		members = append(members, *transportMemberToInfo(&g.Members[i]))
	}
	return &CustodianGroupInfo{
		ID:        g.ID,
		TenantID:  g.TenantID,
		Name:      g.Name,
		Purpose:   g.Purpose,
		Threshold: g.Threshold,
		Total:     g.Total,
		Members:   members,
		CreatedAt: g.CreatedAt.Format(time.RFC3339),
		UpdatedAt: g.UpdatedAt.Format(time.RFC3339),
	}
}

// transportMemberToInfo converts a transport CustodianMemberInfo to a frontend-safe CustodianMemberInfo.
func transportMemberToInfo(m *transport.CustodianMemberInfo) *CustodianMemberInfo {
	info := &CustodianMemberInfo{
		ShareIndex: m.ShareIndex,
		UserID:     m.UserID,
		Username:   m.Username,
		AssignedAt: m.AssignedAt.Format(time.RFC3339),
		Method:     m.Method,
	}
	if m.ReceivedAt != nil {
		info.ReceivedAt = m.ReceivedAt.Format(time.RFC3339)
	}
	return info
}
