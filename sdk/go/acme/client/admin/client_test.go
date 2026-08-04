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
)

func TestNewClient(t *testing.T) {
	mt := &mockTransport{}
	c := NewClient(mt)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestClient_SubClients(t *testing.T) {
	mt := &mockTransport{}
	c := NewClient(mt)

	t.Run("Tenant returns same instance", func(t *testing.T) {
		tc1 := c.Tenant()
		tc2 := c.Tenant()
		if tc1 == nil {
			t.Fatal("expected non-nil tenant client")
		}
		if tc1 != tc2 {
			t.Error("expected same tenant client instance on repeated calls")
		}
	})

	t.Run("TenantCA returns same instance", func(t *testing.T) {
		tca1 := c.TenantCA()
		tca2 := c.TenantCA()
		if tca1 == nil {
			t.Fatal("expected non-nil tenant CA client")
		}
		if tca1 != tca2 {
			t.Error("expected same tenant CA client instance on repeated calls")
		}
	})

	t.Run("EAB returns same instance", func(t *testing.T) {
		ec1 := c.EAB()
		ec2 := c.EAB()
		if ec1 == nil {
			t.Fatal("expected non-nil EAB client")
		}
		if ec1 != ec2 {
			t.Error("expected same EAB client instance on repeated calls")
		}
	})

	t.Run("Role returns same instance", func(t *testing.T) {
		rc1 := c.Role()
		rc2 := c.Role()
		if rc1 == nil {
			t.Fatal("expected non-nil role client")
		}
		if rc1 != rc2 {
			t.Error("expected same role client instance on repeated calls")
		}
	})

	t.Run("User returns same instance", func(t *testing.T) {
		uc1 := c.User()
		uc2 := c.User()
		if uc1 == nil {
			t.Fatal("expected non-nil user client")
		}
		if uc1 != uc2 {
			t.Error("expected same user client instance on repeated calls")
		}
	})

	t.Run("Certificate returns same instance", func(t *testing.T) {
		cc1 := c.Certificate()
		cc2 := c.Certificate()
		if cc1 == nil {
			t.Fatal("expected non-nil certificate client")
		}
		if cc1 != cc2 {
			t.Error("expected same certificate client instance on repeated calls")
		}
	})

	t.Run("Account returns same instance", func(t *testing.T) {
		ac1 := c.Account()
		ac2 := c.Account()
		if ac1 == nil {
			t.Fatal("expected non-nil account client")
		}
		if ac1 != ac2 {
			t.Error("expected same account client instance on repeated calls")
		}
	})

	t.Run("Order returns same instance", func(t *testing.T) {
		oc1 := c.Order()
		oc2 := c.Order()
		if oc1 == nil {
			t.Fatal("expected non-nil order client")
		}
		if oc1 != oc2 {
			t.Error("expected same order client instance on repeated calls")
		}
	})

	t.Run("Status returns same instance", func(t *testing.T) {
		sc1 := c.Status()
		sc2 := c.Status()
		if sc1 == nil {
			t.Fatal("expected non-nil status client")
		}
		if sc1 != sc2 {
			t.Error("expected same status client instance on repeated calls")
		}
	})
}
