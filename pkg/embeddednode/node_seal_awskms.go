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

package embeddednode

import (
	"context"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	registerCloudNodeSeal(seal.StrategyAWSKMS, types.StoreAWSKMS, buildAWSKMSNodeSealBackend)
}

// buildAWSKMSNodeSealBackend builds the AWS KMS backend the awskms node seal
// seals through.
func buildAWSKMSNodeSealBackend(_ context.Context, cfg *config.Config, metadata storage.Backend, logger *slog.Logger) (types.KeyProvider, error) {
	backendCfg, err := awsKMSNodeSealConfig(cfg, metadata, logger)
	if err != nil {
		return nil, err
	}
	return awskms.NewBackend(backendCfg)
}

// awsKMSNodeSealConfig maps backends.awskms onto the node seal's backend
// configuration. The node seal authenticates through the AWS SDK's default
// credential chain (environment, shared config, instance or task role):
// a configured secret_key is a credential-service reference, and the
// credential service only exists once the node is unsealed.
func awsKMSNodeSealConfig(cfg *config.Config, metadata storage.Backend, logger *slog.Logger) (*awskms.Config, error) {
	awsCfg := cfg.Backends.AWSKMS
	if awsCfg == nil {
		return nil, &NodeSealError{
			Reason: "strategy awskms configured for the node seal but backends.awskms is not set",
		}
	}
	if awsCfg.AccessKey != "" || awsCfg.SecretKey != nil {
		logger.Warn("node barrier: the awskms node seal authenticates with the AWS default credential chain; the configured static credentials are not used for it")
	}
	return &awskms.Config{
		Region:      awsCfg.Region,
		Endpoint:    awsCfg.Endpoint,
		KeyID:       awsCfg.KeyID,
		KeyStorage:  metadata,
		CertStorage: metadata,
	}, nil
}
