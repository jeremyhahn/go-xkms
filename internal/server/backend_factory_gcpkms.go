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

//go:build gcpkms

package server

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func createGCPKMSBackend(config BackendConfig) (types.Backend, error) {
	projectID, _ := config.Config["project_id"].(string)
	if projectID == "" {
		return nil, fmt.Errorf("project_id is required for GCP KMS backend")
	}

	locationID, _ := config.Config["location_id"].(string)
	if locationID == "" {
		return nil, fmt.Errorf("location_id is required for GCP KMS backend")
	}

	keyRingID, _ := config.Config["key_ring_id"].(string)
	if keyRingID == "" {
		return nil, fmt.Errorf("key_ring_id is required for GCP KMS backend")
	}

	credentialsFile, _ := config.Config["credentials_file"].(string)
	credentialsJSON, _ := config.Config["credentials_json"].(string)

	// Create storage
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/gcpkms/keys"
	}
	certDir, ok := config.Config["cert_dir"].(string)
	if !ok || certDir == "" {
		certDir = "/tmp/keystore/gcpkms/certs"
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

	gcpConfig := &gcpkms.Config{
		ProjectID:       projectID,
		LocationID:      locationID,
		KeyRingID:       keyRingID,
		CredentialsFile: credentialsFile,
		CredentialsJSON: []byte(credentialsJSON),
		KeyStorage:      keyStorage,
		CertStorage:     certStorage,
	}

	// GCP KMS backend requires a context
	ctx := context.Background()
	return gcpkms.NewBackend(ctx, gcpConfig)
}
