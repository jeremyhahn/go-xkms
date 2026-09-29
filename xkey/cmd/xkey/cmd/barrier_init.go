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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// barrierInitCmd initializes the barrier for first-time setup.
var barrierInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the barrier (first-time setup)",
	Long: `Initialize the barrier by generating a new root key and sealing it.

This must be called exactly once before the barrier can be used. A root
key is generated using crypto/rand and sealed with the best available
strategy. The sealed root key blob is persisted to the data directory.

Strategies (in preference order):
  tpm2      - TPM 2.0 hardware-backed sealing
  pkcs11    - PKCS#11 HSM token sealing
  aws_kms   - AWS Key Management Service
  gcp_kms   - Google Cloud KMS
  azure_kv  - Azure Key Vault
  vault     - HashiCorp Vault Transit engine
  software  - Argon2id password-based (always available)

Use --strategy to force a specific strategy instead of auto-detecting. The
four cloud KMS strategies need their connection settings persisted to the
xkey config the first time (the --aws-*/--gcp-*/--azure-*/--vault-* flags
below); every later "xkey barrier unseal" or headless "xkey extension serve"
reads them back from there. An explicit credential is never a flag -- it is
a *SecretValue reference set by hand in the config file; every provider uses
its own ambient credential chain (the AWS SDK default chain, GCP Application
Default Credentials, Azure DefaultAzureCredential, Vault's VAULT_TOKEN) by
default.

Examples:
  # Auto-detect best strategy
  xkey barrier init

  # Force software-only strategy
  xkey barrier init --strategy software

  # AWS KMS, ambient credentials (the AWS SDK's default credential chain)
  xkey barrier init --strategy aws_kms --aws-region us-east-1

  # AWS KMS, sealing under an existing CMK instead of provisioning one
  xkey barrier init --strategy aws_kms --aws-region us-east-1 \
    --aws-key-id arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab

  # GCP Cloud KMS, ambient Application Default Credentials
  xkey barrier init --strategy gcp_kms --gcp-project-id my-project \
    --gcp-location us-east1 --gcp-key-ring xkey-barrier

  # Azure Key Vault, ambient DefaultAzureCredential
  xkey barrier init --strategy azure_kv --azure-vault-url https://my-vault.vault.azure.net/

  # HashiCorp Vault, ambient VAULT_TOKEN
  xkey barrier init --strategy vault --vault-address https://vault.example.com:8200

  # Use a custom data directory
  xkey barrier init --data-dir /secure/xkey`,
	RunE: runBarrierInit,
}

func init() {
	barrierInitCmd.Flags().StringVar(&barrierStrategy, "strategy", "",
		"sealing strategy: software, tpm2, pkcs11, aws_kms, gcp_kms, azure_kv, vault (default: auto-detect)")

	barrierCmd.AddCommand(barrierInitCmd)
}

func runBarrierInit(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()

	// Validate strategy flag if provided.
	if barrierStrategy != "" {
		if !isValidStrategy(barrierStrategy) {
			return &BarrierError{
				Operation: "validate_strategy",
				Message:   fmt.Sprintf("unknown strategy %q, valid values: %s", barrierStrategy, strings.Join(validStrategyNames, ", ")),
			}
		}
	}

	// A cloud KMS strategy's connection settings are persisted to the xkey
	// config before the barrier is built, so every later command that
	// rebuilds this strategy (unseal, headless serve) reads the same
	// settings back rather than requiring the flags again.
	if err := persistBarrierCloudKMSConfig(barrierStrategy); err != nil {
		return err
	}

	// Resolve data directory.
	dataDir, err := resolveBarrierDataDir()
	if err != nil {
		return err
	}

	// Check if barrier already initialized.
	if barrierRootKeyExists(dataDir) {
		return &BarrierError{
			Operation: "check_initialized",
			Message:   "barrier already initialized (root key exists)",
		}
	}

	// Read and confirm password.
	password, err := readAndConfirmBarrierPassword(out)
	if err != nil {
		return err
	}

	// Create and initialize the barrier.
	barrier, closer, err := createBarrier(dataDir)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := barrier.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
		if closer != nil {
			if cerr := closer.Close(); cerr != nil {
				err = errors.Join(err, cerr)
			}
		}
	}()

	// The CLI has already rejected an empty password above, and this []byte
	// conversion is a fresh copy this function owns and never reads again, so
	// NewCredentials (move + wipe) is used rather than CredentialsFor (copy).
	creds, credErr := xkms.NewCredentials([]byte(password))
	if credErr != nil {
		return &BarrierError{
			Operation: "build_credentials",
			Err:       credErr,
		}
	}
	defer creds.Secret.Destroy()

	if err := barrier.Initialize(context.Background(), creds); err != nil {
		return &BarrierError{
			Operation: "initialize",
			Err:       err,
		}
	}

	// Report success with strategy used.
	strategy := strategyDisplayName(barrier.ActiveStrategy())
	_, _ = fmt.Fprintf(out, "Barrier initialized successfully.\n")
	_, _ = fmt.Fprintf(out, "  Strategy:        %s\n", strategy)
	_, _ = fmt.Fprintf(out, "  Data directory:  %s\n", dataDir)
	_, _ = fmt.Fprintf(out, "\nUse 'xkey barrier unseal' to unseal the barrier.\n")

	return nil
}

// isValidStrategy checks whether the given strategy string is recognized.
func isValidStrategy(s string) bool {
	_, ok := strategyFlagToID[s]
	return ok
}

// persistBarrierCloudKMSConfig builds the BarrierAWSKMSConfig/
// BarrierGCPKMSConfig/BarrierAzureKVConfig/BarrierVaultConfig section for
// strategyFlag from the --aws-*/--gcp-*/--azure-*/--vault-* flags, validates
// it, and saves it into the xkey config so every later command that rebuilds
// this strategy (unseal, headless serve) reads the same settings back
// instead of requiring the flags again. A no-op for every non-cloud-KMS
// strategy (including "", auto-detect).
func persistBarrierCloudKMSConfig(strategyFlag string) error {
	switch strategyFlag {
	case "aws_kms", "gcp_kms", "azure_kv", "vault":
		// Handled below; every other value (including "", auto-detect) is a
		// no-op and returns before touching GetConfig().
	default:
		return nil
	}

	cfg := GetConfig()
	if cfg == nil {
		return ErrBarrierConfigNotLoaded
	}
	section := &cfg.Barrier.CloudKMS

	switch strategyFlag {
	case "aws_kms":
		awsCfg := &config.BarrierAWSKMSConfig{
			Region:   barrierAWSRegion,
			Endpoint: barrierAWSEndpoint,
			KeyID:    barrierAWSKeyID,
		}
		if err := awsCfg.Validate(); err != nil {
			return err
		}
		section.AWSKMS = awsCfg
	case "gcp_kms":
		gcpCfg := &config.BarrierGCPKMSConfig{
			ProjectID:       barrierGCPProjectID,
			LocationID:      barrierGCPLocationID,
			KeyRingID:       barrierGCPKeyRingID,
			CredentialsFile: barrierGCPCredentialsFile,
		}
		if err := gcpCfg.Validate(); err != nil {
			return err
		}
		section.GCPKMS = gcpCfg
	case "azure_kv":
		azureCfg := &config.BarrierAzureKVConfig{
			VaultURL:           barrierAzureVaultURL,
			AllowLocalVaultURL: barrierAzureAllowLocalVaultURL,
		}
		if err := azureCfg.Validate(); err != nil {
			return err
		}
		section.AzureKV = azureCfg
	case "vault":
		vaultCfg := &config.BarrierVaultConfig{
			Address:   barrierVaultAddress,
			MountPath: barrierVaultMountPath,
		}
		if err := vaultCfg.Validate(); err != nil {
			return err
		}
		section.Vault = vaultCfg
	default:
		return nil
	}

	if err := config.Save(cfg); err != nil {
		return &BarrierError{Operation: "save_config", Err: err}
	}
	return nil
}
