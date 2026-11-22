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

package oidc_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"

	"github.com/jeremyhahn/go-xkms/sdk/go/oidc"
)

// The credential re-exports are aliases, so a server that takes a
// *credential.Service accepts the sdk/go name.
var (
	_ *credential.Service = (*oidc.CredentialService)(nil)
	_ credential.Barriers = oidc.CredentialBarriers(nil)
)

// TestReexport_CredentialService proves the server credential service
// constructors are pkg/oidc/credential's own functions.
func TestReexport_CredentialService(t *testing.T) {
	for name, pair := range map[string][2]any{
		"NewCredentialService":       {oidc.NewCredentialService, credential.New},
		"CredentialRegistryBarriers": {oidc.CredentialRegistryBarriers, credential.RegistryBarriers},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, reflect.ValueOf(pair[1]).Pointer(), reflect.ValueOf(pair[0]).Pointer())
		})
	}
}
