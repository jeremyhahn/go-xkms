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

package xkmstest

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testing/enclavetest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest/vaultservice"
)

// TestReexport_TestHelpers pins that the xkmstest helpers xkey's tests use are
// the root test-support helpers, not copies.
func TestReexport_TestHelpers(t *testing.T) {
	funcs := []struct {
		name      string
		got, want any
	}{
		{"SecretLiteral", SecretLiteral, secrettest.Literal},
		{"RunWithEnclaveBudget", RunWithEnclaveBudget, enclavetest.RunWithBudget},
		{"NewVaultSimulatedKey", NewVaultSimulatedKey, vaulttest.NewSimulatedKey},
		{"NewVaultService", NewVaultService, vaultservice.New},
		{"NewBarrierRegistry", NewBarrierRegistry, barriertest.NewRegistry},
	}
	for _, tc := range funcs {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, reflect.ValueOf(tc.want).Pointer(), reflect.ValueOf(tc.got).Pointer())
		})
	}

	require.IsType(t, (*VaultSimulatedKey)(nil), vaulttest.NewSimulatedKey("1234"))
	require.Equal(t, vaulttest.RelyingParty, VaultRelyingParty)
	require.Equal(t, vaultservice.Tenant, VaultTenant)
}
