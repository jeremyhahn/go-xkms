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

// This file re-exports the shared-datastore constructor (pkg/datastore) and
// its configuration types (pkg/config) so an SDK embedder can open the SAME
// single datastore an xkmsd-hosted deployment uses -- standalone (an
// embedded qrdb node) or remote (dialing an existing cluster). The datastore
// hands out the go-qrdb client and a DAO factory; DatastoreStorage bridges
// the factory to the StorageBackend AutoConfig.Datastore takes. See
// docs/datastore/architecture.md.
package xkms

import (
	"context"
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
)

// DatastoreConfig configures the single shared datastore OpenDatastore
// opens: Engine/Path for a standalone embedded qrdb node (default), or Mode
// "remote" plus Remote for dialing an already-running cluster. Yaml key
// "datastore" in xkmsd's own configuration; an embedder that does not parse
// yaml builds one directly.
type DatastoreConfig = config.DatastoreConfig

// DatastoreRemoteConfig configures DatastoreConfig's "remote" mode.
type DatastoreRemoteConfig = config.DatastoreRemoteConfig

// Datastore is the open shared datastore: the go-qrdb client and the DAO
// factory features persist through. Close releases what OpenDatastore built.
type Datastore = datastore.Datastore

// OpenDatastore opens the single shared datastore for cfg, exactly as an
// xkmsd-hosted deployment does: "standalone" (default) hosts an embedded
// qrdb node in this process; "remote" dials an already-running cluster.
func OpenDatastore(ctx context.Context, cfg DatastoreConfig, logger *slog.Logger) (*Datastore, error) {
	return datastore.Open(ctx, &config.Config{Datastore: cfg}, logger)
}

// DatastoreStorage returns a StorageBackend over the default database of
// daos -- typically an open Datastore's DAOFactory(). Pass it as
// AutoConfig.Datastore so every backend's key storage -- and, for TPM2, a
// factory built with NewTPMFactory -- is a prefixed view over the same
// store, never a private per-backend engine. Closing the backend does not
// close the datastore.
func DatastoreStorage(daos *qrdbsdk.DAOFactory) (StorageBackend, error) {
	return compose.FactoryBackend(daos)
}
