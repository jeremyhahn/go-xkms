// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build awskms

package server

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend/awskms"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func createAWSKMSBackend(config BackendConfig) (types.Backend, error) {
	region, _ := config.Config["region"].(string)
	if region == "" {
		return nil, fmt.Errorf("region is required for AWS KMS backend")
	}

	accessKeyID, _ := config.Config["access_key_id"].(string)
	secretAccessKey, _ := config.Config["secret_access_key"].(string)
	sessionToken, _ := config.Config["session_token"].(string)
	endpoint, _ := config.Config["endpoint"].(string)

	// Create storage
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/awskms/keys"
	}
	certDir, ok := config.Config["cert_dir"].(string)
	if !ok || certDir == "" {
		certDir = "/tmp/keystore/awskms/certs"
	}

	var keyStorage storage.Backend
	var err error
	if keyDir == "memory" {
		keyStorage = storage.New()
	} else {
		keyStorage, err = file.New(keyDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create key storage: %w", err)
		}
	}

	var certStorage storage.Backend
	if certDir == "memory" {
		certStorage = storage.New()
	} else {
		certStorage, err = file.New(certDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create cert storage: %w", err)
		}
	}

	awsConfig := &awskms.Config{
		Region:          region,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Endpoint:        endpoint,
		KeyStorage:      keyStorage,
		CertStorage:     certStorage,
	}

	return awskms.NewBackend(awsConfig)
}
