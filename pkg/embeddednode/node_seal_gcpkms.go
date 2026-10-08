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

//go:build gcpkms

package embeddednode

import (
	"context"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	registerCloudNodeSeal(seal.StrategyGCPKMS, types.StoreGCPKMS, buildGCPKMSNodeSealBackend)
}

// buildGCPKMSNodeSealBackend builds the GCP Cloud KMS backend the gcpkms
// node seal seals through.
func buildGCPKMSNodeSealBackend(ctx context.Context, cfg *config.Config, metadata storage.Backend, _ *slog.Logger) (types.KeyProvider, error) {
	backendCfg, err := gcpKMSNodeSealConfig(cfg, metadata)
	if err != nil {
		return nil, err
	}
	return gcpkms.NewBackend(ctx, backendCfg)
}

// gcpKMSNodeSealConfig maps backends.gcpkms onto the node seal's backend
// configuration. The node seal authenticates with the configured
// credentials_file, a path readable before the node exists, or with
// Application Default Credentials when none is set.
func gcpKMSNodeSealConfig(cfg *config.Config, metadata storage.Backend) (*gcpkms.Config, error) {
	gcpCfg := cfg.Backends.GCPKMS
	if gcpCfg == nil {
		return nil, &NodeSealError{
			Reason: "strategy gcpkms configured for the node seal but backends.gcpkms is not set",
		}
	}
	return &gcpkms.Config{
		ProjectID:       gcpCfg.ProjectID,
		LocationID:      gcpCfg.Location,
		KeyRingID:       gcpCfg.KeyRing,
		CredentialsFile: gcpCfg.Credentials,
		KeyStorage:      metadata,
		CertStorage:     metadata,
	}, nil
}
