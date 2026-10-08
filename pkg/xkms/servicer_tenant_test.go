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

package xkms

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
)

// Request-validation guards run before the TenantService check, and are
// exercised here against a service with no TenantService wired: the
// validation error, not ErrTenantServiceNotConfigured, must win.

func TestCreateTenant_NilRequest(t *testing.T) {
	svc := &XKMSService{}
	_, err := svc.CreateTenant(context.Background(), nil)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestCreateTenant_EmptyID(t *testing.T) {
	svc := &XKMSService{}
	_, err := svc.CreateTenant(context.Background(), &transport.CreateTenantRequest{Name: "Acme"})
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestCreateTenant_EmptyName(t *testing.T) {
	svc := &XKMSService{}
	_, err := svc.CreateTenant(context.Background(), &transport.CreateTenantRequest{ID: "acme"})
	assert.ErrorIs(t, err, ErrTenantNameRequired)
}

// TestCreateTenant_RequiresTenantService is the compat-removal gate: a
// service with no TenantService wired fails closed with a typed error
// instead of falling back to direct barrier-registry operations.
func TestCreateTenant_RequiresTenantService(t *testing.T) {
	svc := &XKMSService{}
	_, err := svc.CreateTenant(context.Background(), &transport.CreateTenantRequest{ID: "acme", Name: "Acme"})
	assert.ErrorIs(t, err, ErrTenantServiceNotConfigured)
}

func TestGetTenant_EmptyID(t *testing.T) {
	svc := &XKMSService{}
	_, err := svc.GetTenant(context.Background(), "")
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestGetTenant_RequiresTenantService(t *testing.T) {
	svc := &XKMSService{}
	_, err := svc.GetTenant(context.Background(), "acme")
	assert.ErrorIs(t, err, ErrTenantServiceNotConfigured)
}

func TestListTenants_RequiresTenantService(t *testing.T) {
	svc := &XKMSService{}
	_, err := svc.ListTenants(context.Background())
	assert.ErrorIs(t, err, ErrTenantServiceNotConfigured)
}

func TestDeleteTenant_EmptyID(t *testing.T) {
	svc := &XKMSService{}
	err := svc.DeleteTenant(context.Background(), "")
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestDeleteTenant_RequiresTenantService(t *testing.T) {
	svc := &XKMSService{}
	err := svc.DeleteTenant(context.Background(), "acme")
	assert.ErrorIs(t, err, ErrTenantServiceNotConfigured)
}

func TestUpdateTenantQuotas_RequiresTenantService(t *testing.T) {
	svc := &XKMSService{}
	_, err := svc.UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{TenantID: "acme"})
	assert.ErrorIs(t, err, ErrTenantServiceNotConfigured)
}
