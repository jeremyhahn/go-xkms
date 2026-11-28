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

package xkms

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

// TestReexport_TPMFixtureNames pins that the TPM names xkey's TPM fixtures
// use are the pkg/tpm2 and pkg/tpm2/store ones, not copies.
func TestReexport_TPMFixtureNames(t *testing.T) {
	require.Equal(t, reflect.ValueOf(tpm2.ProvisionFresh).Pointer(), reflect.ValueOf(ProvisionTPMFresh).Pointer())
	require.Equal(t, reflect.ValueOf(store.NewMemoryCertStore).Pointer(), reflect.ValueOf(NewTPMMemoryCertStore).Pointer())
	require.Equal(t, tpm2.NVOwnerIndexFirst, TPMNVOwnerIndexFirst)
	require.Equal(t, tpm2.NVOwnerIndexLast, TPMNVOwnerIndexLast)
}
