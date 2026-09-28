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

package config

import (
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// BarrierCloudKMSConfig holds the connection settings for the barrier's
// cloud-KMS-backed sealing strategies (aws_kms, gcp_kms, azure_kv, vault).
// The symmetric key each provider seals the barrier root key under is
// resolved and, on first use, created automatically by go-xkms under a
// fixed, well-known name (sdk/go's SealKeyCN) when the operator configures
// no key identifier of their own. aws_kms is the one strategy that also
// accepts an operator-supplied key identifier (BarrierAWSKMSConfig.KeyID) to
// seal under an existing CMK instead.
//
// Ambient credentials (the AWS SDK's default credential chain, GCP
// Application Default Credentials, Azure's DefaultAzureCredential, Vault's
// VAULT_TOKEN environment variable) are the default for every provider: the
// credential fields below are optional. Any explicit credential is a
// *xkms.SecretValue reference (go-qrdb's secret-reference contract, sdk/go's
// SecretConfigProcessor/SecretResolverRegistry) -- never a literal in the
// config file.
type BarrierCloudKMSConfig struct {
	AWSKMS  *BarrierAWSKMSConfig  `yaml:"aws_kms,omitempty" json:"aws_kms,omitempty" mapstructure:"aws_kms"`
	GCPKMS  *BarrierGCPKMSConfig  `yaml:"gcp_kms,omitempty" json:"gcp_kms,omitempty" mapstructure:"gcp_kms"`
	AzureKV *BarrierAzureKVConfig `yaml:"azure_kv,omitempty" json:"azure_kv,omitempty" mapstructure:"azure_kv"`
	Vault   *BarrierVaultConfig   `yaml:"vault,omitempty" json:"vault,omitempty" mapstructure:"vault"`
}

// BarrierAWSKMSConfig configures the aws_kms barrier strategy. Region is
// required. AccessKeyID/SecretAccessKey are optional and must be provided
// together; when both are unset, the AWS SDK's default credential chain
// (environment, shared config/profile, IAM role) resolves ambient
// credentials.
type BarrierAWSKMSConfig struct {
	Region          string            `yaml:"region" json:"region" mapstructure:"region"`
	AccessKeyID     string            `yaml:"access_key_id,omitempty" json:"access_key_id,omitempty" mapstructure:"access_key_id"`
	SecretAccessKey *xkms.SecretValue `yaml:"secret_access_key,omitempty" json:"secret_access_key,omitempty" mapstructure:"secret_access_key"`
	SessionToken    *xkms.SecretValue `yaml:"session_token,omitempty" json:"session_token,omitempty" mapstructure:"session_token"`
	Endpoint        string            `yaml:"endpoint,omitempty" json:"endpoint,omitempty" mapstructure:"endpoint"`

	// KeyID is the operator-supplied identifier of an existing AWS KMS
	// customer master key to seal the barrier root key under, instead of one
	// xkey provisions itself on first use. Accepts a key ID, a key ARN, an
	// alias name, or an alias ARN. Optional -- when empty, the barrier
	// creates and persists a new CMK under sdk/go's fixed SealKeyCN
	// (go-xkms#842). Format is validated where the backend is constructed
	// (sdk/go.AWSKMSBackendConfig.KeyID, via awskms.Config.Validate);
	// existence is checked against the live AWS KMS API at that same point
	// (DescribeKey).
	KeyID string `yaml:"key_id,omitempty" json:"key_id,omitempty" mapstructure:"key_id"`
}

// Validate checks that c holds a usable aws_kms barrier configuration.
func (c *BarrierAWSKMSConfig) Validate() error {
	if c == nil {
		return &DetailError{Err: ErrBarrierCloudKMSConfigInvalid, Detail: ": aws_kms: no configuration provided (run 'xkey barrier init --strategy aws_kms --aws-region <region>')"}
	}
	if c.Region == "" {
		return &DetailError{Err: ErrBarrierCloudKMSConfigInvalid, Detail: ": aws_kms: region is required"}
	}
	if (c.AccessKeyID != "") != (c.SecretAccessKey != nil) {
		return &DetailError{Err: ErrBarrierCloudKMSConfigInvalid, Detail: ": aws_kms: access_key_id and secret_access_key must be provided together"}
	}
	return nil
}

// BarrierGCPKMSConfig configures the gcp_kms barrier strategy. ProjectID,
// LocationID and KeyRingID are required (the key ring the seal key is
// created in). CredentialsFile is optional; when unset, Application Default
// Credentials (ADC) resolve ambient credentials.
type BarrierGCPKMSConfig struct {
	ProjectID       string `yaml:"project_id" json:"project_id" mapstructure:"project_id"`
	LocationID      string `yaml:"location_id" json:"location_id" mapstructure:"location_id"`
	KeyRingID       string `yaml:"key_ring_id" json:"key_ring_id" mapstructure:"key_ring_id"`
	CredentialsFile string `yaml:"credentials_file,omitempty" json:"credentials_file,omitempty" mapstructure:"credentials_file"`
}

// Validate checks that c holds a usable gcp_kms barrier configuration.
func (c *BarrierGCPKMSConfig) Validate() error {
	if c == nil {
		return &DetailError{Err: ErrBarrierCloudKMSConfigInvalid, Detail: ": gcp_kms: no configuration provided (run 'xkey barrier init --strategy gcp_kms --gcp-project-id <id> --gcp-location <location> --gcp-key-ring <ring>')"}
	}
	if c.ProjectID == "" {
		return &DetailError{Err: ErrBarrierCloudKMSConfigInvalid, Detail: ": gcp_kms: project_id is required"}
	}
	if c.LocationID == "" {
		return &DetailError{Err: ErrBarrierCloudKMSConfigInvalid, Detail: ": gcp_kms: location_id is required"}
	}
	if c.KeyRingID == "" {
		return &DetailError{Err: ErrBarrierCloudKMSConfigInvalid, Detail: ": gcp_kms: key_ring_id is required"}
	}
	return nil
}

// BarrierAzureKVConfig configures the azure_kv barrier strategy. VaultURL is
// required. TenantID/ClientID/ClientSecret are optional and must be provided
// together; when unset, DefaultAzureCredential resolves ambient credentials.
type BarrierAzureKVConfig struct {
	VaultURL     string            `yaml:"vault_url" json:"vault_url" mapstructure:"vault_url"`
	TenantID     string            `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty" mapstructure:"tenant_id"`
	ClientID     string            `yaml:"client_id,omitempty" json:"client_id,omitempty" mapstructure:"client_id"`
	ClientSecret *xkms.SecretValue `yaml:"client_secret,omitempty" json:"client_secret,omitempty" mapstructure:"client_secret"`

	// AllowLocalVaultURL permits VaultURL to name localhost or 127.0.0.1
	// instead of an Azure vault domain, for local development against an
	// emulator or mock. Off by default.
	AllowLocalVaultURL bool `yaml:"allow_local_vault_url,omitempty" json:"allow_local_vault_url,omitempty" mapstructure:"allow_local_vault_url"`
}

// Validate checks that c holds a usable azure_kv barrier configuration.
func (c *BarrierAzureKVConfig) Validate() error {
	if c == nil {
		return &DetailError{Err: ErrBarrierCloudKMSConfigInvalid, Detail: ": azure_kv: no configuration provided (run 'xkey barrier init --strategy azure_kv --azure-vault-url <url>')"}
	}
	if c.VaultURL == "" {
		return &DetailError{Err: ErrBarrierCloudKMSConfigInvalid, Detail: ": azure_kv: vault_url is required"}
	}
	hasClientID := c.ClientID != ""
	hasClientSecret := c.ClientSecret != nil
	hasTenantID := c.TenantID != ""
	if (hasClientID || hasClientSecret || hasTenantID) && (!hasClientID || !hasClientSecret || !hasTenantID) {
		return &DetailError{Err: ErrBarrierCloudKMSConfigInvalid, Detail: ": azure_kv: tenant_id, client_id, and client_secret must all be provided together"}
	}
	return nil
}

// BarrierVaultConfig configures the vault barrier strategy. Address is
// required. Token is optional; when unset, the Vault Go client's own
// VAULT_TOKEN environment variable resolves ambient credentials.
type BarrierVaultConfig struct {
	Address   string            `yaml:"address" json:"address" mapstructure:"address"`
	Token     *xkms.SecretValue `yaml:"token,omitempty" json:"token,omitempty" mapstructure:"token"`
	Namespace string            `yaml:"namespace,omitempty" json:"namespace,omitempty" mapstructure:"namespace"`
	MountPath string            `yaml:"mount_path,omitempty" json:"mount_path,omitempty" mapstructure:"mount_path"`
}

// Validate checks that c holds a usable vault barrier configuration.
func (c *BarrierVaultConfig) Validate() error {
	if c == nil {
		return &DetailError{Err: ErrBarrierCloudKMSConfigInvalid, Detail: ": vault: no configuration provided (run 'xkey barrier init --strategy vault --vault-address <address>')"}
	}
	if c.Address == "" {
		return &DetailError{Err: ErrBarrierCloudKMSConfigInvalid, Detail: ": vault: address is required"}
	}
	return nil
}
