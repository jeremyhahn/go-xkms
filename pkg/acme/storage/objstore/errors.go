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

package objstore

import (
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ErrIndexNotSupported is returned when an index query is attempted against
// the objstore backend, which does not support native indexes.
var ErrIndexNotSupported = errors.New("objstore: index queries not supported")

// errNilDAOFactory is the go-qrdb configuration error a factory constructor
// returns when it is given no DAO factory.
func errNilDAOFactory() error {
	return qrdbsdk.DAOInvalidConfigError{Field: "daoFactory", Reason: "DAO factory not configured"}
}

// errNilKVStore is the go-qrdb configuration error a factory constructor
// returns when it is given no KVStore.
func errNilKVStore() error {
	return qrdbsdk.DAOInvalidConfigError{Field: "kvStore", Reason: "kv store not configured"}
}
