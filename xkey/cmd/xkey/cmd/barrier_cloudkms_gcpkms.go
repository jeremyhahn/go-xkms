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

package cmd

import (
	"context"
	"io"
	"path/filepath"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func init() {
	registerCloudKMSStrategyBuilder(xkms.StrategyGCPKMS, buildGCPKMSBarrierStrategy)
}

// buildGCPKMSBarrierStrategy builds the gcp_kms barrier sealing strategy from
// the operator's persisted xkey configuration (Barrier.CloudKMS.GCPKMS).
// GCP KMS has no SecretValue-typed credential of its own: CredentialsFile
// names a service account JSON key file on disk, and when it is unset the
// GCP client library resolves Application Default Credentials (ADC), the
// ambient default. The seal key itself needs no configured identifier: see
// buildAWSKMSBarrierStrategy's doc.
func buildGCPKMSBarrierStrategy(ctx context.Context, dataDir string) (xkms.SealingStrategy, io.Closer, error) {
	gcpCfg := GetConfig().Barrier.CloudKMS.GCPKMS
	if err := gcpCfg.Validate(); err != nil {
		return nil, nil, err
	}

	storageDir := filepath.Join(dataDir, "barrier", "cloudkms", "gcpkms")
	metaStorage, err := xkms.NewFileStorageBackend(storageDir)
	if err != nil {
		return nil, nil, &BarrierError{Operation: "create_storage", Err: err}
	}

	backend, err := xkms.NewGCPKMSBackend(ctx, &xkms.GCPKMSBackendConfig{
		ProjectID:       gcpCfg.ProjectID,
		LocationID:      gcpCfg.LocationID,
		KeyRingID:       gcpCfg.KeyRingID,
		CredentialsFile: gcpCfg.CredentialsFile,
		KeyStorage:      metaStorage,
		CertStorage:     metaStorage,
	})
	if err != nil {
		_ = metaStorage.Close()
		return nil, nil, &BarrierError{Operation: "create_backend", Err: err}
	}

	strategy, err := xkms.BuildCloudKMSStrategy(ctx, xkms.StrategyGCPKMS, xkms.StoreGCPKMS, backend)
	if err != nil {
		_ = backend.Close()
		return nil, nil, &BarrierError{Operation: "build_strategy", Err: err}
	}

	return strategy, backend, nil
}
