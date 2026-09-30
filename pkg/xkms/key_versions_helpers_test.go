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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// wireKeyVersionStore installs an in-memory key-version store on the
// initialized service singleton and returns it.
func wireKeyVersionStore(t *testing.T) *keyversion.Store {
	t.Helper()
	svc, err := Get()
	require.NoError(t, err)
	store, err := keyversion.NewStore(storage.New())
	require.NoError(t, err)
	svc.SetKeyVersionStore(store)
	return store
}
