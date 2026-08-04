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

package clusterca

import (
	"context"

	softwarebackend "github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// barrierStrategy stores the cluster CA signing key in the qrdb-routed
// replicated datastore, encrypted at rest by each node's own barrier. It
// bootstraps the key node-local (before the datastore exists, so the first node
// can issue its own transport certificate), then promotes it into the
// replicated store once available. Every node then loads the key from the
// replicated store — each decrypting with its own barrier — so any node can
// issue.
//
// The node-local and replicated keystores share the operator's cluster CA
// passphrase (KeyProtection), so the promoted (passphrase-wrapped) key blob is
// decryptable on every node while the barrier additionally protects it at rest.
type barrierStrategy struct {
	// bootstrapKeyStorage is retained between BootstrapBackend and
	// RuntimeBackend so the first node can copy the node-local key blobs into
	// the replicated store during promotion.
	bootstrapKeyStorage storage.Backend
}

// Name reports the strategy identifier.
func (s *barrierStrategy) Name() KeyStrategyName { return KeyStrategyBarrier }

// BootstrapBackends builds the node-local software backends (under
// {NodeLocalDataDir}) the first node creates the cluster CA key in before the
// datastore exists. It retains the key storage handle so RuntimeBackend can
// promote the key into the replicated store.
func (s *barrierStrategy) BootstrapBackends(ctx context.Context, deps *StrategyDeps) (func(string) (xkms.Backend, error), error) {
	set, err := newNodeLocalBackendSet(ctx, &NodeLocalBackendsParams{
		DataDir:     deps.NodeLocalDataDir,
		CAConfig:    deps.CAConfig,
		Protection:  deps.Protection,
		HardwareTPM: deps.TPMSealer,
		Logger:      deps.logger(),
	})
	if err != nil {
		return nil, err
	}
	s.bootstrapKeyStorage = set.keyStorage
	return set.resolve, nil
}

// RuntimeBackend builds the software keystore over the replicated (qrdb-routed,
// barrier-encrypted) storage and, when a node-local bootstrap key exists (the
// first node), promotes it by copying the key blobs into the replicated store.
// Other nodes simply load the already-replicated key.
func (s *barrierStrategy) RuntimeBackend(ctx context.Context, deps *StrategyDeps) (xkms.Backend, error) {
	if deps.ReplicatedKeyStorage == nil || deps.ReplicatedCertStorage == nil {
		return nil, ErrStrategyMisconfigured
	}

	// Ensure the CA identities carry the same keystore password used at
	// bootstrap so the replicated (passphrase-wrapped) blobs decrypt here.
	protection := deps.Protection
	if protection.DataDir == "" {
		protection.DataDir = deps.NodeLocalDataDir
	}
	if protection.Logger == nil {
		protection.Logger = deps.logger()
	}
	if protection.Sealer == nil {
		protection.Sealer = deps.TPMSealer
	}
	if err := injectKeystorePassword(ctx, &protection, deps.CAConfig); err != nil {
		return nil, err
	}

	// Promotion: on the first node the CA key was created node-local; copy the
	// key blobs into the replicated store so every node can load it. Idempotent
	// (PutIfAbsent-style overwrite is safe; the blobs are identical).
	if s.bootstrapKeyStorage != nil {
		if err := promoteKeyStorage(ctx, s.bootstrapKeyStorage, deps.ReplicatedKeyStorage); err != nil {
			return nil, err
		}
		deps.logger().Info("promoted cluster CA key into the replicated barrier-encrypted store")
	}

	return newSoftwareBackend(deps.ReplicatedKeyStorage, deps.ReplicatedCertStorage)
}

// promoteKeyStorage copies every key-value entry from src into dst. The entries
// are the CA keystore's (passphrase-wrapped) key blobs; copying them into the
// replicated store makes the key available on every node (which additionally
// barrier-encrypts its local copy at rest).
func promoteKeyStorage(ctx context.Context, src, dst storage.Backend) error {
	return src.Scan(ctx, "", func(key string, value []byte) error {
		return dst.Put(ctx, key, value)
	})
}

// newSoftwareBackend composes a software key provider over keyStorage with an
// xkms.Backend cert store over certStorage.
func newSoftwareBackend(keyStorage, certStorage storage.Backend) (xkms.Backend, error) {
	provider, err := softwarebackend.NewBackend(&softwarebackend.Config{KeyStorage: keyStorage})
	if err != nil {
		return nil, err
	}
	return xkms.New(&xkms.BackendConfig{
		Backend:     provider,
		CertStorage: certStorage,
	})
}
