// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package grpc

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

// TestAdminRoutes_DottedServiceNames verifies that dotted admin service names are routed correctly.
func TestAdminRoutes_DottedServiceNames(t *testing.T) {
	t.Parallel()

	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)

	adminServices := []string{
		"admin.tenant",
		"admin.eab",
		"admin.role",
		"admin.user",
		"admin.certificate",
		"admin.account",
		"admin.status",
		"admin.order",
		"admin.tenant.ca",
	}

	for _, svc := range adminServices {
		handler, ok := grpcTransport.handlers[svc]
		if !ok {
			t.Errorf("missing handler for admin service: %s", svc)
			continue
		}
		if handler == nil {
			t.Errorf("nil handler for admin service: %s", svc)
		}
	}
}

// TestAdminRoutes_DottedServiceNames_NotACME verifies that dotted admin services are not treated as ACME.
func TestAdminRoutes_DottedServiceNames_NotACME(t *testing.T) {
	t.Parallel()

	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)

	adminServices := []string{
		"admin.tenant",
		"admin.certificate",
		"admin.account",
		"admin.order",
	}

	for _, svc := range adminServices {
		if grpcTransport.isACMEService(svc) {
			t.Errorf("admin service %q should not be classified as ACME", svc)
		}
	}
}

// TestAdminRoutes_BareServiceNames verifies that bare admin service names still work.
func TestAdminRoutes_BareServiceNames(t *testing.T) {
	t.Parallel()

	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)

	bareServices := []string{
		ServiceAdmin,
		ServiceTenant,
		ServiceEAB,
		ServiceCertificate,
		ServiceStatus,
	}

	for _, svc := range bareServices {
		if _, ok := grpcTransport.handlers[svc]; !ok {
			t.Errorf("missing handler for bare service name: %s", svc)
		}
	}
}

// TestAdminRoutes_UnknownDottedService verifies that unknown dotted services return an error.
func TestAdminRoutes_UnknownDottedService(t *testing.T) {
	t.Parallel()

	cfg := &transport.Config{
		Address:   "localhost:9443",
		Insecure:  true,
		TLSConfig: insecureTestTLSConfig(),
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	defer tr.Close()

	grpcTransport := tr.(*Transport)
	if _, ok := grpcTransport.handlers["admin.nonexistent"]; ok {
		t.Error("unexpected handler for admin.nonexistent service")
	}

	_, err = tr.Request(t.Context(), "admin.nonexistent", "get", nil)
	if err == nil {
		t.Fatal("expected error for unknown dotted service")
	}
	if !errors.IsInvalidInput(err) {
		t.Errorf("expected invalid input error, got: %v", err)
	}
}
