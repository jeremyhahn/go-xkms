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

package awskms

import (
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Config contains configuration for AWS KMS backend operations.
// It specifies the AWS region, credentials, and optional endpoint override.
type Config struct {
	// Region is the AWS region where KMS keys will be managed.
	// Examples: "us-east-1", "us-west-2", "eu-west-1"
	Region string `yaml:"region" json:"region" mapstructure:"region"`

	// AccessKeyID is the AWS access key ID.
	// Optional - if not provided, will use IAM role or environment credentials.
	AccessKeyID string `yaml:"access_key_id,omitempty" json:"access_key_id,omitempty" mapstructure:"access_key_id"`

	// SecretAccessKey is the AWS secret access key.
	// Optional - if not provided, will use IAM role or environment credentials.
	SecretAccessKey string `yaml:"secret_access_key,omitempty" json:"secret_access_key,omitempty" mapstructure:"secret_access_key"`

	// SessionToken is the AWS session token for temporary credentials.
	// Optional - used for temporary security credentials.
	SessionToken string `yaml:"session_token,omitempty" json:"session_token,omitempty" mapstructure:"session_token"`

	// Endpoint is a custom KMS endpoint URL.
	// Optional - useful for testing with LocalStack or custom KMS endpoints.
	// Example: "http://localhost:4566" for LocalStack
	Endpoint string `yaml:"endpoint,omitempty" json:"endpoint,omitempty" mapstructure:"endpoint"`

	// KeyID is the default KMS key ID or ARN to use.
	// Optional - can be specified per-operation instead.
	// Examples:
	//   - "1234abcd-12ab-34cd-56ef-1234567890ab" (key ID)
	//   - "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab" (key ARN)
	//   - "alias/my-key" (key alias)
	KeyID string `yaml:"key_id,omitempty" json:"key_id,omitempty" mapstructure:"key_id"`

	// Debug enables debug logging for AWS SDK operations.
	Debug bool `yaml:"debug,omitempty" json:"debug,omitempty" mapstructure:"debug"`

	// KeyStorage is the underlying storage for key metadata.
	// This can be file-based, memory-based, or any implementation
	// of the storage.Backend interface.
	// Note: Actual key material stays in AWS KMS, this is for metadata only.
	KeyStorage storage.Backend `yaml:"-" json:"-" mapstructure:"-"`

	// CertStorage is the underlying storage for certificate material.
	// This can be file-based, memory-based, or any implementation
	// of the storage.Backend interface.
	CertStorage storage.Backend `yaml:"-" json:"-" mapstructure:"-"`

	// Tracker is the AEAD safety tracker for nonce/bytes tracking.
	// If nil, a default memory-based tracker will be created.
	// For production systems, provide a persistent tracker.
	Tracker types.AEADSafetyTracker `yaml:"-" json:"-" mapstructure:"-"`
}

// Validate checks if the configuration is valid and returns an error if not.
// It verifies that required fields are set and that values meet minimum requirements.
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	// Region is required
	if c.Region == "" {
		return fmt.Errorf("%w: region is required", ErrInvalidConfig)
	}

	// Validate region format (basic check)
	if !isValidRegion(c.Region) {
		return fmt.Errorf("%w: %s", ErrInvalidRegion, c.Region)
	}

	// If static credentials are provided, both access key and secret must be present
	if (c.AccessKeyID != "" && c.SecretAccessKey == "") ||
		(c.AccessKeyID == "" && c.SecretAccessKey != "") {
		return fmt.Errorf("%w: both access_key_id and secret_access_key must be provided together", ErrInvalidConfig)
	}

	// Storage providers are required
	if c.KeyStorage == nil {
		return fmt.Errorf("%w: key storage is required", ErrInvalidConfig)
	}
	if c.CertStorage == nil {
		return fmt.Errorf("%w: cert storage is required", ErrInvalidConfig)
	}

	return nil
}

// String returns a string representation of the config with sensitive data masked.
// Credentials are masked with asterisks to prevent accidental exposure in logs.
func (c *Config) String() string {
	accessKeyMask := "<not set>"
	if c.AccessKeyID != "" {
		if len(c.AccessKeyID) > 4 {
			accessKeyMask = "****" + c.AccessKeyID[len(c.AccessKeyID)-4:]
		} else {
			accessKeyMask = "****"
		}
	}

	secretKeyMask := "<not set>"
	if c.SecretAccessKey != "" {
		secretKeyMask = "****"
	}

	sessionTokenMask := "<not set>"
	if c.SessionToken != "" {
		sessionTokenMask = "****"
	}

	keyIDDisplay := "<not set>"
	if c.KeyID != "" {
		keyIDDisplay = c.KeyID
	}

	endpointDisplay := "<default>"
	if c.Endpoint != "" {
		endpointDisplay = c.Endpoint
	}

	return fmt.Sprintf("AWS KMS Config{Region: %s, AccessKeyID: %s, SecretAccessKey: %s, SessionToken: %s, Endpoint: %s, KeyID: %s, Debug: %t}",
		c.Region, accessKeyMask, secretKeyMask, sessionTokenMask, endpointDisplay, keyIDDisplay, c.Debug)
}

// isValidRegion performs basic validation of AWS region format.
// Valid regions follow the pattern: us-east-1, eu-west-2, ap-southeast-1, etc.
func isValidRegion(region string) bool {
	if region == "" {
		return false
	}

	// Allow "local" for LocalStack testing
	if region == "local" || region == "us-east-1-local" {
		return true
	}

	// Basic validation: must contain at least one hyphen and be alphanumeric
	parts := strings.Split(region, "-")
	if len(parts) < 2 {
		return false
	}

	// Each part should be alphanumeric
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
				return false
			}
		}
	}

	return true
}
