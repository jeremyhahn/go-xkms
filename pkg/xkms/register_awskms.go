//go:build awskms

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

// Package xkms provides AWS KMS backend registration and factory.
//
// The AWS KMS backend integrates with Amazon Web Services Key Management Service
// for cloud-based key storage and cryptographic operations.
//
// This file is only compiled when the 'awskms' build tag is specified.
package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	RegisterBackend(BackendAWSKMS)
	RegisterBackendFactory(BackendAWSKMS, newAWSKMSKeyProvider)
}

// newAWSKMSKeyProvider creates an AWS KMS backend KeyProvider from configuration.
//
// Supported configuration keys:
//   - "region" (string): AWS region (required)
//   - "access_key_id" (string): AWS access key ID (optional, uses IAM if empty)
//   - "secret_access_key" (string): AWS secret access key (optional)
//   - "session_token" (string): AWS session token (optional)
//   - "endpoint" (string): Custom KMS endpoint (optional, for LocalStack)
//   - "key_id" (string): Default KMS key ID or ARN (optional)
func newAWSKMSKeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	awsConfig := &awskms.Config{
		KeyStorage: storage.New(),
	}

	if region, ok := config["region"].(string); ok {
		awsConfig.Region = region
	}
	if accessKey, ok := config["access_key_id"].(string); ok {
		awsConfig.AccessKeyID = accessKey
	}
	if secretKey, ok := config["secret_access_key"].(string); ok {
		awsConfig.SecretAccessKey = secretKey
	}
	if token, ok := config["session_token"].(string); ok {
		awsConfig.SessionToken = token
	}
	if endpoint, ok := config["endpoint"].(string); ok {
		awsConfig.Endpoint = endpoint
	}
	if keyID, ok := config["key_id"].(string); ok {
		awsConfig.KeyID = keyID
	}

	return awskms.NewBackend(awsConfig)
}
