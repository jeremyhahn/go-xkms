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

//go:build gcpkms

package gcpkms

import (
	"fmt"
	"os"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Config contains configuration for GCP KMS backend operations.
// It specifies the GCP project, location, key ring, and authentication credentials.
type Config struct {
	// ProjectID is the GCP project ID where the KMS resources are located.
	// Required.
	ProjectID string `yaml:"project_id" json:"project_id" mapstructure:"project_id"`

	// LocationID is the GCP location (region) for KMS resources.
	// Examples: "us-east1", "us-central1", "global"
	// Required.
	LocationID string `yaml:"location_id" json:"location_id" mapstructure:"location_id"`

	// KeyRingID is the key ring identifier within the project and location.
	// Key rings are logical groupings of cryptographic keys.
	// Required.
	KeyRingID string `yaml:"key_ring_id" json:"key_ring_id" mapstructure:"key_ring_id"`

	// CredentialsFile is the path to a service account JSON key file.
	// Optional. If not provided, uses Application Default Credentials (ADC).
	CredentialsFile string `yaml:"credentials_file,omitempty" json:"credentials_file,omitempty" mapstructure:"credentials_file"`

	// CredentialsJSON contains the service account JSON key content.
	// Optional. Takes precedence over CredentialsFile if both are provided.
	CredentialsJSON []byte `yaml:"credentials_json,omitempty" json:"credentials_json,omitempty" mapstructure:"credentials_json"`

	// Endpoint is a custom KMS API endpoint.
	// Optional. Useful for testing with a KMS emulator such as floci-gcp.
	// Example: "localhost:4588" for local emulator
	Endpoint string `yaml:"endpoint,omitempty" json:"endpoint,omitempty" mapstructure:"endpoint"`

	// Insecure disables TLS and authentication on the KMS connection.
	// Optional. Only valid together with a custom Endpoint; used for
	// plaintext gRPC connections to a local emulator. Never enable this
	// against the real GCP Cloud KMS service.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty" mapstructure:"insecure"`

	// Debug enables debug logging for KMS operations.
	Debug bool `yaml:"debug" json:"debug" mapstructure:"debug"`

	// KeyStorage is the underlying storage for key metadata.
	// This can be file-based, memory-based, or any implementation
	// of the storage.Backend interface.
	// Note: Actual key material stays in GCP KMS, this is for metadata only.
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
// It verifies that required fields are set and credentials are accessible.
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	// Project ID is required
	if c.ProjectID == "" {
		return &errs.Detail{Err: ErrInvalidProjectID, Detail: "project ID is required"}
	}

	// Location ID is required
	if c.LocationID == "" {
		return &errs.Detail{Err: ErrInvalidLocationID, Detail: "location ID is required"}
	}

	// Key ring ID is required
	if c.KeyRingID == "" {
		return &errs.Detail{Err: ErrInvalidKeyRingID, Detail: "key ring ID is required"}
	}

	// Insecure connections are only permitted against a custom endpoint
	if c.Insecure && c.Endpoint == "" {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "insecure requires a custom endpoint"}
	}

	// If credentials file is specified, verify it exists
	if c.CredentialsFile != "" && len(c.CredentialsJSON) == 0 {
		if _, err := os.Stat(c.CredentialsFile); os.IsNotExist(err) {
			return &errs.Detail{Err: ErrInvalidCredentials, Detail: fmt.Sprintf("credentials file not found: %s", c.CredentialsFile)}
		}
	}

	// Storage providers are required
	if c.KeyStorage == nil {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "key storage is required"}
	}
	if c.CertStorage == nil {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "cert storage is required"}
	}

	return nil
}

// KeyRingName returns the fully qualified key ring resource name.
// Format: projects/{project}/locations/{location}/keyRings/{keyRing}
func (c *Config) KeyRingName() string {
	return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s",
		c.ProjectID, c.LocationID, c.KeyRingID)
}

// String returns a string representation of the config with sensitive data masked.
func (c *Config) String() string {
	credsMask := "<not set>"
	if c.CredentialsFile != "" {
		credsMask = maskPath(c.CredentialsFile)
	} else if len(c.CredentialsJSON) > 0 {
		credsMask = fmt.Sprintf("<json: %d bytes>", len(c.CredentialsJSON))
	}

	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = "<default>"
	}

	return fmt.Sprintf("GCP KMS Config{Project: %s, Location: %s, KeyRing: %s, Credentials: %s, Endpoint: %s, Insecure: %t, Debug: %t}",
		c.ProjectID, c.LocationID, c.KeyRingID, credsMask, endpoint, c.Insecure, c.Debug)
}

// maskPath masks the middle portion of a file path for security.
// Example: /home/user/credentials.json becomes /home/.../credentials.json
func maskPath(path string) string {
	if path == "" {
		return ""
	}

	parts := strings.Split(path, string(os.PathSeparator))
	if len(parts) <= 2 {
		return path
	}

	// Keep first and last parts, mask the middle
	masked := make([]string, 0, len(parts))
	masked = append(masked, parts[0])
	if len(parts) > 3 {
		masked = append(masked, "...")
	}
	masked = append(masked, parts[len(parts)-1])

	return strings.Join(masked, string(os.PathSeparator))
}
