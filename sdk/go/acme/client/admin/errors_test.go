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

package admin

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

func TestTypedErrors(t *testing.T) {
	t.Run("TenantNotFoundError", func(t *testing.T) {
		err := NewTenantNotFound("test.op", "tenant xyz not found")
		if err.Code != errors.CodeNotFound {
			t.Errorf("expected CodeNotFound, got %v", err.Code)
		}
		if err.Op != "test.op" {
			t.Errorf("expected op test.op, got %s", err.Op)
		}
		// Verify it implements error interface
		var _ error = err
	})

	t.Run("TenantAlreadyExistsError", func(t *testing.T) {
		err := NewTenantAlreadyExists("test.op", "tenant already exists")
		if err.Code != errors.CodeAlreadyExists {
			t.Errorf("expected CodeAlreadyExists, got %v", err.Code)
		}
	})

	t.Run("EABNotFoundError", func(t *testing.T) {
		err := NewEABNotFound("test.op", "eab not found")
		if err.Code != errors.CodeNotFound {
			t.Errorf("expected CodeNotFound, got %v", err.Code)
		}
	})

	t.Run("RoleNotFoundError", func(t *testing.T) {
		err := NewRoleNotFound("test.op", "role not found")
		if err.Code != errors.CodeNotFound {
			t.Errorf("expected CodeNotFound, got %v", err.Code)
		}
	})

	t.Run("UserNotFoundError", func(t *testing.T) {
		err := NewUserNotFound("test.op", "user not found")
		if err.Code != errors.CodeNotFound {
			t.Errorf("expected CodeNotFound, got %v", err.Code)
		}
	})

	t.Run("CertificateNotFoundError", func(t *testing.T) {
		err := NewCertificateNotFound("test.op", "certificate not found")
		if err.Code != errors.CodeNotFound {
			t.Errorf("expected CodeNotFound, got %v", err.Code)
		}
	})

	t.Run("AccountNotFoundError", func(t *testing.T) {
		err := NewAccountNotFound("test.op", "account not found")
		if err.Code != errors.CodeNotFound {
			t.Errorf("expected CodeNotFound, got %v", err.Code)
		}
	})

	t.Run("OrderNotFoundError", func(t *testing.T) {
		err := NewOrderNotFound("test.op", "order not found")
		if err.Code != errors.CodeNotFound {
			t.Errorf("expected CodeNotFound, got %v", err.Code)
		}
	})

	t.Run("TenantRootCAExistsError", func(t *testing.T) {
		err := NewTenantRootCAExists("test.op", "root CA already exists")
		if err.Code != errors.CodeAlreadyExists {
			t.Errorf("expected CodeAlreadyExists, got %v", err.Code)
		}
	})

	t.Run("TenantRootCANotFoundError", func(t *testing.T) {
		err := NewTenantRootCANotFound("test.op", "root CA not found")
		if err.Code != errors.CodeNotFound {
			t.Errorf("expected CodeNotFound, got %v", err.Code)
		}
	})

	t.Run("IntermediateCANotFoundError", func(t *testing.T) {
		err := NewIntermediateCANotFound("test.op", "intermediate CA not found")
		if err.Code != errors.CodeNotFound {
			t.Errorf("expected CodeNotFound, got %v", err.Code)
		}
	})

	t.Run("IntermediateCAExistsError", func(t *testing.T) {
		err := NewIntermediateCAExists("test.op", "intermediate CA already exists")
		if err.Code != errors.CodeAlreadyExists {
			t.Errorf("expected CodeAlreadyExists, got %v", err.Code)
		}
	})

	t.Run("RevocationFailedError", func(t *testing.T) {
		err := NewRevocationFailed("test.op", "revocation failed")
		if err.Code != errors.CodeInternal {
			t.Errorf("expected CodeInternal, got %v", err.Code)
		}
	})
}

func TestTypedErrors_ErrorMessage(t *testing.T) {
	err := NewTenantNotFound("admin.tenant.Get", "tenant xyz not found")
	msg := err.Error()
	if msg == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestTypedErrors_TypeAssertions(t *testing.T) {
	t.Run("OrderNotFoundError is error", func(t *testing.T) {
		var err error = NewOrderNotFound("test", "not found")
		_, ok := err.(*OrderNotFoundError)
		if !ok {
			t.Error("expected type assertion to OrderNotFoundError to succeed")
		}
	})

	t.Run("TenantRootCAExistsError is error", func(t *testing.T) {
		var err error = NewTenantRootCAExists("test", "exists")
		_, ok := err.(*TenantRootCAExistsError)
		if !ok {
			t.Error("expected type assertion to TenantRootCAExistsError to succeed")
		}
	})

	t.Run("IntermediateCANotFoundError is error", func(t *testing.T) {
		var err error = NewIntermediateCANotFound("test", "not found")
		_, ok := err.(*IntermediateCANotFoundError)
		if !ok {
			t.Error("expected type assertion to IntermediateCANotFoundError to succeed")
		}
	})

	t.Run("IntermediateCAExistsError is error", func(t *testing.T) {
		var err error = NewIntermediateCAExists("test", "exists")
		_, ok := err.(*IntermediateCAExistsError)
		if !ok {
			t.Error("expected type assertion to IntermediateCAExistsError to succeed")
		}
	})

	t.Run("TenantRootCANotFoundError is error", func(t *testing.T) {
		var err error = NewTenantRootCANotFound("test", "not found")
		_, ok := err.(*TenantRootCANotFoundError)
		if !ok {
			t.Error("expected type assertion to TenantRootCANotFoundError to succeed")
		}
	})
}
