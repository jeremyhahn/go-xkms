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

package cmd

import (
	"context"
	"fmt"
	"io"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Cloud KMS barrier strategy connection flags for `xkey barrier init`. Only
// the non-secret connection settings (where the key lives) are exposed as
// flags; an explicit credential is never accepted as a flag or any other
// literal -- it is a *xkms.SecretValue reference the operator sets in the
// config file (go-qrdb's secret-reference contract), or the field is left
// unset and the provider's own ambient credential chain (AWS SDK default
// chain, GCP Application Default Credentials, Azure DefaultAzureCredential,
// Vault's VAULT_TOKEN) is used -- the default for every provider.
var (
	barrierAWSRegion   string
	barrierAWSEndpoint string

	barrierGCPProjectID       string
	barrierGCPLocationID      string
	barrierGCPKeyRingID       string
	barrierGCPCredentialsFile string

	barrierAzureVaultURL           string
	barrierAzureAllowLocalVaultURL bool

	barrierVaultAddress   string
	barrierVaultMountPath string
)

func init() {
	barrierInitCmd.Flags().StringVar(&barrierAWSRegion, "aws-region", "",
		"AWS region for the aws_kms barrier strategy")
	barrierInitCmd.Flags().StringVar(&barrierAWSEndpoint, "aws-endpoint", "",
		"Custom AWS KMS endpoint (optional; for testing against an emulator)")

	barrierInitCmd.Flags().StringVar(&barrierGCPProjectID, "gcp-project-id", "",
		"GCP project ID for the gcp_kms barrier strategy")
	barrierInitCmd.Flags().StringVar(&barrierGCPLocationID, "gcp-location", "",
		"GCP KMS location (e.g. us-east1)")
	barrierInitCmd.Flags().StringVar(&barrierGCPKeyRingID, "gcp-key-ring", "",
		"GCP KMS key ring ID")
	barrierInitCmd.Flags().StringVar(&barrierGCPCredentialsFile, "gcp-credentials-file", "",
		"Path to a GCP service account JSON key file (optional; Application Default Credentials are used when unset)")

	barrierInitCmd.Flags().StringVar(&barrierAzureVaultURL, "azure-vault-url", "",
		"Azure Key Vault URL for the azure_kv barrier strategy")
	barrierInitCmd.Flags().BoolVar(&barrierAzureAllowLocalVaultURL, "azure-allow-local-vault-url", false,
		"Allow a localhost/127.0.0.1 vault URL (development only)")

	barrierInitCmd.Flags().StringVar(&barrierVaultAddress, "vault-address", "",
		"HashiCorp Vault server address for the vault barrier strategy")
	barrierInitCmd.Flags().StringVar(&barrierVaultMountPath, "vault-mount-path", "",
		"Vault Transit engine mount path (default: transit)")
}

// cloudKMSStrategyBuilder builds a cloud KMS barrier sealing strategy from
// the operator's persisted xkey configuration (GetConfig().Barrier.CloudKMS)
// and the given barrier data directory (for the provider's local key-metadata
// storage). The returned io.Closer releases the backend's resources and must
// be closed by the caller once the strategy is no longer needed.
type cloudKMSStrategyBuilder func(ctx context.Context, dataDir string) (xkms.SealingStrategy, io.Closer, error)

// cloudKMSStrategyBuilders holds one entry per cloud KMS strategy ID whose
// build tag is compiled in. Each provider's tag-gated file
// (barrier_cloudkms_awskms.go, etc.) registers itself in its own init(); a
// provider built without its tag has no entry, so buildCloudKMSBarrierStrategy
// reports a typed "not compiled in" error instead of reaching a nil builder.
var cloudKMSStrategyBuilders = map[xkms.StrategyID]cloudKMSStrategyBuilder{}

// registerCloudKMSStrategyBuilder registers fn as the builder for id. Called
// from the init() of each cloud KMS provider's build-tag-gated file.
func registerCloudKMSStrategyBuilder(id xkms.StrategyID, fn cloudKMSStrategyBuilder) {
	cloudKMSStrategyBuilders[id] = fn
}

// cloudKMSBuildTags names the build tag that compiles in each cloud KMS
// strategy, for the "not compiled in" error message.
var cloudKMSBuildTags = map[xkms.StrategyID]string{
	xkms.StrategyAWSKMS:  "awskms",
	xkms.StrategyGCPKMS:  "gcpkms",
	xkms.StrategyAzureKV: "azurekv",
	xkms.StrategyVault:   "vault",
}

// buildCloudKMSBarrierStrategy dispatches to the registered builder for id.
func buildCloudKMSBarrierStrategy(ctx context.Context, id xkms.StrategyID, dataDir string) (xkms.SealingStrategy, io.Closer, error) {
	fn, ok := cloudKMSStrategyBuilders[id]
	if !ok {
		tag := cloudKMSBuildTags[id]
		return nil, nil, &BarrierError{
			Operation: "assemble_strategy",
			Message:   fmt.Sprintf("%s strategy not available: this xkey binary was built without -tags %s", id, tag),
		}
	}
	return fn(ctx, dataDir)
}

// resolveBarrierCloudSecrets resolves every *xkms.SecretValue field reachable
// from cfg (a pointer to one of the BarrierAWSKMSConfig/BarrierAzureKVConfig/
// BarrierVaultConfig structs) in place, through sdk/go's re-export of
// go-qrdb's secret-reference SPI (the same contract xkmsd resolves its own
// backend credentials through in pkg/server/secret_wiring.go).
//
// xkey has no credential service of its own, so the registry it builds here
// carries no resolvers: a field left nil (ambient credentials, the default)
// is skipped by the walk and never reaches resolution; a field that names an
// explicit reference fails closed with xkms.ErrUnresolvedSecretURI rather
// than being read as a literal. This is not a partial implementation -- it is
// the same state xkmsd itself is in whenever no credential service is
// configured (see buildSecretRegistry) -- and it is the correct, secure
// default until a resolver for a reference scheme xkey can serve is added.
func resolveBarrierCloudSecrets(ctx context.Context, cfg any) error {
	reg := xkms.NewSecretResolverRegistry()
	proc := xkms.NewSecretConfigProcessor(reg)
	_, err := proc.Process(ctx, cfg)
	return err
}

// normalizeAmbientSecret nils out sv when it carries no reference (an empty
// Raw), so a *SecretValue field the config loader materialized as an empty,
// non-nil struct (see DefaultConfig's doc in xkey/pkg/config/config.go for
// why every Load() does this to a direct struct-pointer field) is treated
// exactly like a field that was genuinely never mentioned: ambient
// credentials. Without this, resolveBarrierCloudSecrets would see a
// protected target holding nothing resolvable and fail closed with an
// UnresolvableTargetError for every cloud KMS config that went through
// config.Load(), even when the operator configured nothing at all. A
// genuinely configured reference (non-empty Raw) is returned unchanged and
// still resolved (or fails) normally.
func normalizeAmbientSecret(sv *xkms.SecretValue) *xkms.SecretValue {
	if sv != nil && sv.Raw == "" {
		return nil
	}
	return sv
}
