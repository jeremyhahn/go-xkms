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

// TenantInfo is the frontend-visible tenant metadata.
type TenantInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// TenantService manages multi-tenant operations and per-tenant barriers.
// It wraps the SDK TenantService interface and provides frontend-safe types
// and event emission.
type TenantService struct {
	ctx     context.Context
	log     *slog.Logger
	client  atomic.Pointer[transport.Client]
	emitter func(events.Event)
}

// NewTenantService creates a new TenantService.
func NewTenantService() *TenantService {
	return &TenantService{
		log: slog.Default().With("component", "tenant_service"),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *TenantService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetEventEmitter sets the event callback for frontend notifications.
func (s *TenantService) SetEventEmitter(fn func(events.Event)) {
	s.emitter = fn
}

// SetClient sets the transport client used to communicate with the server.
func (s *TenantService) SetClient(c transport.Client) {
	s.client.Store(&c)
}

// getClient returns the current transport client or an error.
func (s *TenantService) getClient() (transport.Client, error) {
	ptr := s.client.Load()
	if ptr == nil {
		return nil, ErrTenantServiceNoClient
	}
	return *ptr, nil
}

// CreateTenant creates a new tenant on the server.
func (s *TenantService) CreateTenant(name string) (*TenantInfo, error) {
	if name == "" {
		return nil, ErrTenantNameRequired
	}

	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	resp, err := client.CreateTenant(ctx, &transport.CreateTenantRequest{
		Name: name,
	})
	if err != nil {
		s.log.Error("failed to create tenant", "name", name, "error", err)
		return nil, err
	}

	info := transportTenantToInfo(&resp.Tenant)
	s.emit(events.EventTenantCreated, info)
	s.log.Info("tenant created", "id", resp.Tenant.ID, "name", name)
	return info, nil
}

// GetTenant retrieves a tenant by ID.
func (s *TenantService) GetTenant(tenantID string) (*TenantInfo, error) {
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	resp, err := client.GetTenant(ctx, tenantID)
	if err != nil {
		s.log.Error("failed to get tenant", "tenant_id", tenantID, "error", err)
		return nil, err
	}

	return transportTenantToInfo(&resp.Tenant), nil
}

// ListTenants lists all tenants.
func (s *TenantService) ListTenants() ([]TenantInfo, error) {
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	resp, err := client.ListTenants(ctx)
	if err != nil {
		s.log.Error("failed to list tenants", "error", err)
		return nil, err
	}

	tenants := make([]TenantInfo, 0, len(resp.Tenants))
	for i := range resp.Tenants {
		tenants = append(tenants, *transportTenantToInfo(&resp.Tenants[i]))
	}
	return tenants, nil
}

// DeleteTenant deletes a tenant.
func (s *TenantService) DeleteTenant(tenantID string) error {
	if tenantID == "" {
		return ErrTenantIDRequired
	}

	client, err := s.getClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	if err := client.DeleteTenant(ctx, tenantID); err != nil {
		s.log.Error("failed to delete tenant", "tenant_id", tenantID, "error", err)
		return err
	}

	s.emit(events.EventTenantDeleted, map[string]string{"tenant_id": tenantID})
	s.log.Info("tenant deleted", "tenant_id", tenantID)
	return nil
}

// BarrierInit initializes a per-tenant barrier.
func (s *TenantService) BarrierInit(tenantID string, threshold, shares int) error {
	if tenantID == "" {
		return ErrTenantIDRequired
	}

	client, err := s.getClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	if err := client.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID:  tenantID,
		Threshold: threshold,
		Shares:    shares,
	}); err != nil {
		s.log.Error("failed to init tenant barrier", "tenant_id", tenantID, "error", err)
		return err
	}

	s.emit(events.EventTenantBarrierInited, map[string]string{"tenant_id": tenantID})
	s.log.Info("tenant barrier initialized", "tenant_id", tenantID)
	return nil
}

// BarrierUnseal unseals a per-tenant barrier with a share or key.
func (s *TenantService) BarrierUnseal(tenantID string, share, key []byte) error {
	if tenantID == "" {
		return ErrTenantIDRequired
	}

	client, err := s.getClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	if err := client.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: tenantID,
		Share:    share,
		Key:      key,
	}); err != nil {
		s.log.Error("failed to unseal tenant barrier", "tenant_id", tenantID, "error", err)
		return err
	}

	s.emit(events.EventTenantBarrierUnsealed, map[string]string{"tenant_id": tenantID})
	s.log.Info("tenant barrier unsealed", "tenant_id", tenantID)
	return nil
}

// emit sends an event to the frontend if an emitter is registered.
func (s *TenantService) emit(eventType events.EventType, payload any) {
	if s.emitter != nil {
		s.emitter(events.Event{
			Type:    eventType,
			Payload: payload,
			Time:    time.Now(),
		})
	}
}

// transportTenantToInfo converts a transport TenantInfo to a frontend-safe TenantInfo.
func transportTenantToInfo(t *transport.TenantInfo) *TenantInfo {
	return &TenantInfo{
		ID:        t.ID,
		Name:      t.Name,
		CreatedAt: t.CreatedAt.Format(time.RFC3339),
		UpdatedAt: t.UpdatedAt.Format(time.RFC3339),
	}
}
