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

package testutil

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

// NewMemoryDAOFactory returns a DAO factory over a fresh in-process go-qrdb
// KV store. The default database and every named one share that store, which
// supports the atomic conditional writes and secondary indexes real DAOs
// rely on, so tests exercise the production persistence path in memory.
func NewMemoryDAOFactory() *qrdbsdk.DAOFactory {
	return dao.NewStoreFactory(qrdbsdk.NewMemoryKVStore())
}
