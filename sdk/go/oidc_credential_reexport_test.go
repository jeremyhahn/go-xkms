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
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// TestReexport_OIDCCredentialConstructors pins the OIDC credential service
// constructor and its barrier-registry option to pkg/oidc/credential, so xkey
// builds the service through sdk/go only (row xkey-sdk-only).
func TestReexport_OIDCCredentialConstructors(t *testing.T) {
	require.Equal(t, reflect.ValueOf(credential.New).Pointer(), reflect.ValueOf(NewOIDCCredentialService).Pointer())
	require.Equal(t, reflect.ValueOf(credential.RegistryBarriers).Pointer(), reflect.ValueOf(OIDCCredentialRegistryBarriers).Pointer())

	var barriers OIDCCredentialBarriers = credential.RegistryBarriers(nil)
	require.NotNil(t, barriers)
}

// TestReexport_PIVStorageError pins the PIV storage error type, so xkey
// matches it with errors.As through sdk/go.
func TestReexport_PIVStorageError(t *testing.T) {
	var sdkErr *PIVStorageError
	var pkgErr *pivcert.PIVStorageError = sdkErr
	require.Nil(t, pkgErr)
}
