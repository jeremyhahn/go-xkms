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

package qrdb

import (
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
)

func TestTypeAliasSDKClient(t *testing.T) {
	t.Run("alias resolves to sdk.Client", func(t *testing.T) {
		// Compile-time verification that the type alias resolves correctly.
		var _ = (*qrdbsdk.Client)(nil)
	})
}

func TestTypeAliasKVClient(t *testing.T) {
	t.Run("alias is assignable from MemoryKVClient", func(t *testing.T) {
		var kv KVClient = NewMemoryKVClient()
		assert.NotNil(t, kv)
	})

	t.Run("alias matches db.KVClient", func(t *testing.T) {
		var kv = db.KVClient(NewMemoryKVClient())
		assert.NotNil(t, kv)
	})
}

func TestTypeAliasAdminClient(t *testing.T) {
	t.Run("alias is assignable from testAdminClient", func(t *testing.T) {
		var admin AdminClient = newTestAdminClient()
		assert.NotNil(t, admin)
	})
}

func TestTypeAliasCompileChecks(t *testing.T) {
	t.Run("all aliases compile correctly", func(t *testing.T) {
		// These assignments verify compile-time type compatibility.
		// The blank identifiers ensure the compiler checks the types
		// without requiring runtime values.
		var _ = (db.KVClient)(nil)
		var _ = (db.AdminClient)(nil)
		var _ = (db.WatchClient)(nil)
		var _ = (db.LeaseClient)(nil)
		var _ = (db.BatchClient)(nil)
		var _ = (db.TransactionClient)(nil)
		var _ = (db.IndexClient)(nil)
	})
}
