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

package embeddednode

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// CloudNodeSealSubdir is the fixed subdirectory, under the configured
// datastore path, where each cloud node seal keeps its KMS key metadata (one
// directory per strategy). The metadata must outlive the process: AWS KMS
// records there the identifier of the key it created on first boot.
const CloudNodeSealSubdir = "node-seal"

// cloudNodeSealBackend builds the KMS backend a cloud node seal seals
// through, keeping the backend's key metadata in metadata. It runs before
// the node, and so before the credential service, exists: a backend
// authenticates with its provider's ambient credentials, or with a secret
// released from the pre-barrier store (OpenPreseal).
type cloudNodeSealBackend func(ctx context.Context, cfg *config.Config, metadata storage.Backend, logger *slog.Logger) (types.KeyProvider, error)

// cloudNodeSeal is one cloud strategy's node seal: the key store its seal
// key lives in and the backend it seals through.
type cloudNodeSeal struct {
	store   types.StoreType
	backend cloudNodeSealBackend
}

// cloudNodeSeals holds every cloud node seal compiled into this binary. Each
// provider registers itself from a file built under its own tag (awskms,
// gcpkms, azurekv, vault), the tag that compiles its backend in.
var cloudNodeSeals = map[seal.StrategyID]cloudNodeSeal{}

// registerCloudNodeSeal adds the node seal for strategy id.
func registerCloudNodeSeal(id seal.StrategyID, store types.StoreType, backend cloudNodeSealBackend) {
	cloudNodeSeals[id] = cloudNodeSeal{store: store, backend: backend}
}

// resolveCloudNodeSeal builds the node seal for a cloud strategy: the
// provider's backend over persistent key metadata, and the seal key
// provisioned on it. The result's Close releases the backend and the
// metadata.
func resolveCloudNodeSeal(ctx context.Context, cfg *config.Config, strategy string, logger *slog.Logger) (ResolvedNodeSeal, error) {
	id := seal.StrategyID(strategy)
	if !seal.IsCloudSealStrategy(id) {
		return ResolvedNodeSeal{}, &NodeSealError{Reason: "unknown barrier strategy " + strconv.Quote(strategy)}
	}
	cloud, ok := cloudNodeSeals[id]
	if !ok {
		return ResolvedNodeSeal{}, &NodeSealError{
			Reason: "barrier strategy " + strconv.Quote(strategy) +
				" is not compiled into this binary (build tag " + strategy + ")",
		}
	}
	if cfg.Datastore.Path == "" {
		return ResolvedNodeSeal{}, &ErrDatastorePathRequired{Reason: "the cloud seal key metadata"}
	}
	metadata, err := storage.NewFile(filepath.Join(cfg.Datastore.Path, CloudNodeSealSubdir, strategy))
	if err != nil {
		return ResolvedNodeSeal{}, &NodeSealError{Reason: "opening the " + strategy + " seal key metadata", Err: err}
	}
	provider, err := cloud.backend(ctx, cfg, metadata, logger)
	if err != nil {
		return ResolvedNodeSeal{}, &NodeSealError{
			Reason: "building the " + strategy + " seal backend",
			Err:    errors.Join(err, metadata.Close()),
		}
	}
	return cloudNodeSealFromProvider(ctx, id, cloud.store, provider, metadata)
}

// cloudNodeSealFromProvider provisions the seal key on provider (creating it
// on first boot, reusing it on every boot after) and wraps provider as the
// node's sealing strategy. The result's Close releases provider and
// metadata; on error both are already released.
func cloudNodeSealFromProvider(ctx context.Context, id seal.StrategyID, store types.StoreType, provider types.KeyProvider, metadata storage.Backend) (ResolvedNodeSeal, error) {
	closeAll := func() error {
		return errors.Join(provider.Close(), metadata.Close())
	}
	strategy, err := seal.BuildCloudKMSStrategy(ctx, id, store, provider)
	if err != nil {
		return ResolvedNodeSeal{}, &NodeSealError{
			Reason: "provisioning the " + string(id) + " seal key",
			Err:    errors.Join(err, closeAll()),
		}
	}
	return ResolvedNodeSeal{Enabled: true, Strategy: strategy, Close: closeAll}, nil
}
