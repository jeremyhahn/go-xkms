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
// embedded qrdb node) or remote (dialing an existing cluster) -- and hand
// the resulting StorageBackend to AutoConfig.Datastore, instead of every
// backend resolving its own storage. See docs/datastore/architecture.md.
package xkms

import (
	"context"
	"log/slog"

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

// OpenDatastore builds the single shared StorageBackend for cfg, exactly as
// an xkmsd-hosted deployment's Server.initializeQRDBStorage does:
// "standalone" (default) hosts an embedded qrdb node in this process;
// "remote" dials an already-running cluster. Pass the result as
// AutoConfig.Datastore so every backend's key storage -- and, for TPM2, a
// factory built with NewTPMFactory -- is a prefixed view over the same
// store, never a private per-backend engine.
func OpenDatastore(ctx context.Context, cfg DatastoreConfig, logger *slog.Logger) (StorageBackend, error) {
	return datastore.Open(ctx, &config.Config{Datastore: cfg}, logger)
}
