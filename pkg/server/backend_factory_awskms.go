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

//go:build awskms

package server

import (
	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func createAWSKMSBackend(config BackendConfig) (types.KeyProvider, error) {
	region, _ := config.Config["region"].(string)
	if region == "" {
		return nil, &ErrConfigRequired{Field: "region", Backend: "AWS KMS"}
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
			return nil, &ErrStorageCreate{Resource: "key storage", Err: err}
		}
	}

	var certStorage storage.Backend
	if certDir == "memory" {
		certStorage = storage.New()
	} else {
		certStorage, err = file.New(certDir)
		if err != nil {
			return nil, &ErrStorageCreate{Resource: "cert storage", Err: err}
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
