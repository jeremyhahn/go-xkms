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

//go:build awskms

package cmd

import (
	"context"
	"io"
	"path/filepath"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func init() {
	registerCloudKMSStrategyBuilder(xkms.StrategyAWSKMS, buildAWSKMSBarrierStrategy)
}

// buildAWSKMSBarrierStrategy builds the aws_kms barrier sealing strategy from
// the operator's persisted xkey configuration (Barrier.CloudKMS.AWSKMS),
// resolving any explicit *xkms.SecretValue credential reference and falling
// back to the AWS SDK's ambient credential chain when none is configured.
// The seal key itself needs no configured identifier: sdk/go.BuildCloudKMSStrategy
// resolves (or creates on first use) the symmetric wrapping key under the
// fixed CN xkmsd uses too, so a barrier initialized by either unseals under
// the other (go-xkms#757).
func buildAWSKMSBarrierStrategy(ctx context.Context, dataDir string) (xkms.SealingStrategy, io.Closer, error) {
	awsCfg := GetConfig().Barrier.CloudKMS.AWSKMS
	if awsCfg != nil {
		awsCfg.SecretAccessKey = normalizeAmbientSecret(awsCfg.SecretAccessKey)
		awsCfg.SessionToken = normalizeAmbientSecret(awsCfg.SessionToken)
	}
	if err := awsCfg.Validate(); err != nil {
		return nil, nil, err
	}

	if err := resolveBarrierCloudSecrets(ctx, awsCfg); err != nil {
		return nil, nil, &BarrierError{Operation: "resolve_credentials", Err: err}
	}

	secretAccessKey, err := xkms.SecretValueBytes(awsCfg.SecretAccessKey)
	if err != nil {
		return nil, nil, &BarrierError{Operation: "resolve_credentials", Err: err}
	}
	sessionToken, err := xkms.SecretValueBytes(awsCfg.SessionToken)
	if err != nil {
		return nil, nil, &BarrierError{Operation: "resolve_credentials", Err: err}
	}

	storageDir := filepath.Join(dataDir, "barrier", "cloudkms", "awskms")
	metaStorage, err := xkms.NewFileStorageBackend(storageDir)
	if err != nil {
		return nil, nil, &BarrierError{Operation: "create_storage", Err: err}
	}

	backend, err := xkms.NewAWSKMSBackend(&xkms.AWSKMSBackendConfig{
		Region:          awsCfg.Region,
		AccessKeyID:     awsCfg.AccessKeyID,
		SecretAccessKey: string(secretAccessKey),
		SessionToken:    string(sessionToken),
		Endpoint:        awsCfg.Endpoint,
		KeyStorage:      metaStorage,
		CertStorage:     metaStorage,
	})
	if err != nil {
		_ = metaStorage.Close()
		return nil, nil, &BarrierError{Operation: "create_backend", Err: err}
	}

	strategy, err := xkms.BuildCloudKMSStrategy(ctx, xkms.StrategyAWSKMS, xkms.StoreAWSKMS, backend)
	if err != nil {
		_ = backend.Close()
		return nil, nil, &BarrierError{Operation: "build_strategy", Err: err}
	}

	return strategy, backend, nil
}
