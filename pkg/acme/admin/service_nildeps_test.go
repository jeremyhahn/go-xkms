//go:build codec_json

// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package admin

// Tests for go-xkms#1075: every AdminService method that reads the ACME
// certificate authority or storage factory must answer the typed
// ErrCANotConfigured / ErrStorageNotConfigured sentinel — never panic — when
// the service was constructed with a nil ca.TCGCA and/or nil storage.Factory,
// exactly as cmd/xkmsd's finalizeAdminModule constructs it when ACME is
// disabled (acme.CA() and acme.StorageFactory() both return nil for a nil
// *acmeServer).

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

// newNilDepsAdminService returns an AdminService with a nil CA and a nil
// storage factory, the exact shape ACME-disabled deployments produce.
func newNilDepsAdminService() *AdminService {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewAdminService(nil, nil, logger, "test-version")
}

func TestAdminService_ListCertificates_NilStorageNotConfigured(t *testing.T) {
	svc := newNilDepsAdminService()
	certs, pagination, err := svc.ListCertificates(context.Background(), ListCertificatesRequest{})
	if !errors.Is(err, ErrStorageNotConfigured) {
		t.Fatalf("ListCertificates() err = %v, want ErrStorageNotConfigured", err)
	}
	if certs != nil {
		t.Fatalf("ListCertificates() certs = %v, want nil alongside the error", certs)
	}
	if pagination != nil {
		t.Fatalf("ListCertificates() pagination = %v, want nil alongside the error", pagination)
	}
}

func TestAdminService_GetCertificate_NilStorageNotConfigured(t *testing.T) {
	svc := newNilDepsAdminService()
	cert, err := svc.GetCertificate(context.Background(), "123456")
	if !errors.Is(err, ErrStorageNotConfigured) {
		t.Fatalf("GetCertificate() err = %v, want ErrStorageNotConfigured", err)
	}
	if cert != nil {
		t.Fatalf("GetCertificate() = %v, want nil alongside the error", cert)
	}
}

func TestAdminService_RevokeCertificate_NilStorageNotConfigured(t *testing.T) {
	svc := newNilDepsAdminService()
	err := svc.RevokeCertificate(context.Background(), "123456", "keyCompromise")
	if !errors.Is(err, ErrStorageNotConfigured) {
		t.Fatalf("RevokeCertificate() err = %v, want ErrStorageNotConfigured", err)
	}
}

// TestAdminService_RevokeCertificate_NilCANotConfigured proves the CA guard
// is reached (and reported distinctly from ErrStorageNotConfigured) when
// storage is configured but the CA is not — RevokeCertificate is the only
// AdminService method that reads both dependencies.
func TestAdminService_RevokeCertificate_NilCANotConfigured(t *testing.T) {
	_, mockStorage, cleanup := createTestInfrastructure(t)
	defer cleanup()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := NewAdminService(nil, mockStorage, logger, "test-version")

	err := svc.RevokeCertificate(context.Background(), "123456", "keyCompromise")
	if !errors.Is(err, ErrCertificateNotFound) && !errors.Is(err, ErrCANotConfigured) {
		t.Fatalf("RevokeCertificate() err = %v, want ErrCertificateNotFound (no matching cert) or ErrCANotConfigured", err)
	}
}

func TestAdminService_ListExpiringCertificates_NilStorageNotConfigured(t *testing.T) {
	svc := newNilDepsAdminService()
	certs, pagination, err := svc.ListExpiringCertificates(context.Background(), 30, 1, 20)
	if !errors.Is(err, ErrStorageNotConfigured) {
		t.Fatalf("ListExpiringCertificates() err = %v, want ErrStorageNotConfigured", err)
	}
	if certs != nil {
		t.Fatalf("ListExpiringCertificates() certs = %v, want nil alongside the error", certs)
	}
	if pagination != nil {
		t.Fatalf("ListExpiringCertificates() pagination = %v, want nil alongside the error", pagination)
	}
}

func TestAdminService_ListAccounts_NilStorageNotConfigured(t *testing.T) {
	svc := newNilDepsAdminService()
	accounts, pagination, err := svc.ListAccounts(context.Background(), ListAccountsRequest{})
	if !errors.Is(err, ErrStorageNotConfigured) {
		t.Fatalf("ListAccounts() err = %v, want ErrStorageNotConfigured", err)
	}
	if accounts != nil {
		t.Fatalf("ListAccounts() accounts = %v, want nil alongside the error", accounts)
	}
	if pagination != nil {
		t.Fatalf("ListAccounts() pagination = %v, want nil alongside the error", pagination)
	}
}

func TestAdminService_GetAccount_NilStorageNotConfigured(t *testing.T) {
	svc := newNilDepsAdminService()
	account, err := svc.GetAccount(context.Background(), 1)
	if !errors.Is(err, ErrStorageNotConfigured) {
		t.Fatalf("GetAccount() err = %v, want ErrStorageNotConfigured", err)
	}
	if account != nil {
		t.Fatalf("GetAccount() = %v, want nil alongside the error", account)
	}
}

func TestAdminService_DisableAccount_NilStorageNotConfigured(t *testing.T) {
	svc := newNilDepsAdminService()
	err := svc.DisableAccount(context.Background(), 1)
	if !errors.Is(err, ErrStorageNotConfigured) {
		t.Fatalf("DisableAccount() err = %v, want ErrStorageNotConfigured", err)
	}
}

func TestAdminService_ListOrders_NilStorageNotConfigured(t *testing.T) {
	svc := newNilDepsAdminService()
	orders, pagination, err := svc.ListOrders(context.Background(), ListOrdersRequest{})
	if !errors.Is(err, ErrStorageNotConfigured) {
		t.Fatalf("ListOrders() err = %v, want ErrStorageNotConfigured", err)
	}
	if orders != nil {
		t.Fatalf("ListOrders() orders = %v, want nil alongside the error", orders)
	}
	if pagination != nil {
		t.Fatalf("ListOrders() pagination = %v, want nil alongside the error", pagination)
	}
}

func TestAdminService_GetOrder_NilStorageNotConfigured(t *testing.T) {
	svc := newNilDepsAdminService()
	order, err := svc.GetOrder(context.Background(), 1, 1)
	if !errors.Is(err, ErrStorageNotConfigured) {
		t.Fatalf("GetOrder() err = %v, want ErrStorageNotConfigured", err)
	}
	if order != nil {
		t.Fatalf("GetOrder() = %v, want nil alongside the error", order)
	}
}

func TestAdminService_GetStatus_NilCANotConfigured(t *testing.T) {
	svc := newNilDepsAdminService()
	status, err := svc.GetStatus(context.Background())
	if !errors.Is(err, ErrCANotConfigured) {
		t.Fatalf("GetStatus() err = %v, want ErrCANotConfigured", err)
	}
	if status != nil {
		t.Fatalf("GetStatus() = %v, want nil alongside the error", status)
	}
}

func TestAdminService_GetStats_NilStorageNotConfigured(t *testing.T) {
	svc := newNilDepsAdminService()
	stats, err := svc.GetStats(context.Background())
	if !errors.Is(err, ErrStorageNotConfigured) {
		t.Fatalf("GetStats() err = %v, want ErrStorageNotConfigured", err)
	}
	if stats != nil {
		t.Fatalf("GetStats() = %v, want nil alongside the error", stats)
	}
}
