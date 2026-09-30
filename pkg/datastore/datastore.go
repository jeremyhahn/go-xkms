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

// Package datastore opens the single shared datastore.Backend for callers
// that compose go-xkms without a *server.Server -- the SDK/library
// composition path: pkg/xkms's AutoInitialize and register_* backend
// factories (via a caller-supplied storage.Backend handle), sdk/go, and
// xkey. It mirrors exactly what pkg/server's Server.initializeQRDBStorage
// does for an xkmsd-hosted deployment, reusing the SAME Server-independent
// building blocks (pkg/embeddednode for "standalone", DialRemote in this
// package for "remote") so there is exactly one implementation of each --
// see docs/datastore/architecture.md.
package datastore

import (
	"context"
	"log/slog"
	"strings"

	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// Open builds the single shared datastore.Backend for cfg.Datastore:
//
//   - "standalone" (default) hosts an embedded qrdb node in this process,
//     rooted at cfg.Datastore.Path and using cfg.Datastore.Engine, via
//     embeddednode.OpenEmbeddedNode -- the same Server-independent
//     construction xkmsd init uses. Datastore.Path is required for every
//     Engine, "memory" included: go-qrdb roots the node's on-disk state
//     (its vector-storage subsystem in particular) under it regardless of
//     the primary KV engine, so there is no engine choice that lets a
//     standalone node run with no directory at all -- config.Validate
//     enforces this for an xkmsd-hosted deployment; this is the same check
//     for an embedded/programmatic caller that never ran Validate.
//   - "remote" dials an already-running qrdb cluster at
//     cfg.Datastore.Remote.Address, via DialRemote.
//
// The returned storage.Backend is the caller's to Close when done; every
// subsystem's storage is then a key-prefixed view over it
// (storage.NewPrefixBackend), never a private per-subsystem engine.
func Open(ctx context.Context, cfg *config.Config, logger *slog.Logger) (storage.Backend, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Datastore.Mode))
	if mode == "" {
		mode = "standalone"
	}

	switch mode {
	case "standalone":
		if cfg.Datastore.Path == "" {
			return nil, &embeddednode.ErrDatastorePathRequired{Reason: "the standalone datastore"}
		}

		node, _, err := embeddednode.OpenEmbeddedNode(ctx, embeddednode.EmbeddedNodeOptions{
			Config: cfg,
			Logger: logger,
		})
		if err != nil {
			return nil, &ErrOpenDatastore{Mode: mode, Err: err}
		}
		return &standaloneBackend{
			Backend: qrdbstorage.NewBackend(node.Client().KV()),
			node:    node,
		}, nil

	case "remote":
		backend, err := DialRemote(ctx, cfg.Datastore.Remote)
		if err != nil {
			return nil, &ErrOpenDatastore{Mode: mode, Err: err}
		}
		return backend, nil

	default:
		return nil, &ErrUnsupportedDatastoreMode{Mode: cfg.Datastore.Mode}
	}
}

// standaloneBackend wraps the embedded qrdb node's storage.Backend together
// with the node itself so Close tears down both in one step. The embedded
// *qrdbstorage.Backend provides all storage operations.
type standaloneBackend struct {
	*qrdbstorage.Backend
	node *qrdbnode.Node
}

// Close closes the embedded qrdb node this backend's KV client belongs to.
func (b *standaloneBackend) Close() error {
	return b.node.Close()
}
