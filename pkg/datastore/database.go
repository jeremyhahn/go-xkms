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

package datastore

import (
	"context"
	"errors"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// ensureDatabase confirms the named database exists, creating it with its
// resolved backend when it does not. A CreateDatabase race -- another
// composition root ensuring the same database concurrently -- resolves to
// success rather than an error: the database existing is the postcondition
// ensureDatabase promises, regardless of who created it.
func ensureDatabase(ctx context.Context, client *qrdbsdk.Client, cfg config.DatastoreConfig, name string) error {
	if _, err := client.Database().GetDatabase(ctx, name); err == nil {
		return nil
	}

	_, err := client.Database().CreateDatabase(ctx, qrdbtransport.CreateDatabaseRequest{
		Name:    name,
		Backend: resolveDatabaseBackend(cfg, name),
	})
	if err == nil {
		return nil
	}

	var exists *qrdbsdk.DBAlreadyExistsError
	if errors.As(err, &exists) {
		return nil
	}
	return &ErrEnsureDatabase{Name: name, Err: err}
}

// resolveDatabaseBackend returns the go-qrdb storage backend ("memory",
// "file", "pebble", or "raft") the named database is created with: the
// cfg.Databases override for name when one is configured with a non-empty
// Backend, and cfg.Engine (already defaulted to "pebble" by config.Validate)
// otherwise.
func resolveDatabaseBackend(cfg config.DatastoreConfig, name string) string {
	for _, db := range cfg.Databases {
		if db.Name == name && db.Backend != "" {
			return strings.ToLower(strings.TrimSpace(db.Backend))
		}
	}
	engine := strings.ToLower(strings.TrimSpace(cfg.Engine))
	if engine == "" {
		engine = "pebble"
	}
	return engine
}
