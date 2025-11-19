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

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/migration"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/spf13/cobra"
)

// migrateCmd represents the migrate command
var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate keys between backends",
	Long: `Migrate cryptographic keys from one backend to another.

Supports migrations between:
  - PKCS#8 (software) to AES
  - PKCS#8 to PKCS#11 (hardware)
  - PKCS#11 to TPM2
  - Cloud KMS (AWS, GCP, Azure) to local backends
  - Any backends supporting import/export`,
}

// migratePlanCmd shows what would be migrated
var migratePlanCmd = &cobra.Command{
	Use:   "plan --from <source-backend> --to <dest-backend>",
	Short: "Show migration plan without executing",
	Long:  `Analyze which keys would be migrated between backends without actually performing the migration`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		sourceBackend, _ := cmd.Flags().GetString("from")
		destBackend, _ := cmd.Flags().GetString("to")

		if sourceBackend == "" || destBackend == "" {
			handleError(fmt.Errorf("both --from and --to flags are required"))
			return
		}

		printVerbose("Migration plan from %s to %s", sourceBackend, destBackend)

		// Save current backend and switch to source
		originalBackend := cfg.Backend
		cfg.Backend = sourceBackend

		sourceBe, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create source backend: %w", err))
			return
		}
		defer func() { _ = sourceBe.Close() }()

		// Switch to destination backend
		cfg.Backend = destBackend

		destBe, err := cfg.CreateBackend()
		if err != nil {
			// Restore original backend
			cfg.Backend = originalBackend
			handleError(fmt.Errorf("failed to create destination backend: %w", err))
			return
		}
		defer func() { _ = destBe.Close() }()

		// Create migrator
		migrator, err := migration.NewMigrator(sourceBe, destBe)
		if err != nil {
			// Restore original backend
			cfg.Backend = originalBackend
			handleError(fmt.Errorf("failed to create migrator: %w", err))
			return
		}
		defer func() { _ = migrator.Close() }()

		// Build filter from flags
		filter := buildMigrationFilter(cmd)

		// Get migration plan
		plan, err := migrator.MigrationPlan(filter)
		if err != nil {
			cfg.Backend = originalBackend
			handleError(fmt.Errorf("failed to create migration plan: %w", err))
			return
		}

		// Restore original backend
		cfg.Backend = originalBackend

		// Output plan
		if cfg.OutputFormat == "json" {
			outputMigrationPlanJSON(plan, printer)
		} else {
			outputMigrationPlanText(plan, printer)
		}
	},
}

// migrateExecuteCmd executes the actual migration
var migrateExecuteCmd = &cobra.Command{
	Use:   "execute --from <source-backend> --to <dest-backend>",
	Short: "Execute migration",
	Long:  `Migrate keys from source backend to destination backend`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		sourceBackend, _ := cmd.Flags().GetString("from")
		destBackend, _ := cmd.Flags().GetString("to")
		deleteSource, _ := cmd.Flags().GetBool("delete-source")
		skipVerify, _ := cmd.Flags().GetBool("skip-verify")
		parallel, _ := cmd.Flags().GetInt("parallel")
		stopOnError, _ := cmd.Flags().GetBool("stop-on-error")

		if sourceBackend == "" || destBackend == "" {
			handleError(fmt.Errorf("both --from and --to flags are required"))
			return
		}

		printVerbose("Executing migration from %s to %s", sourceBackend, destBackend)

		// Save current backend and switch to source
		originalBackend := cfg.Backend
		cfg.Backend = sourceBackend

		sourceBe, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create source backend: %w", err))
			return
		}
		defer func() { _ = sourceBe.Close() }()

		// Switch to destination backend
		cfg.Backend = destBackend

		destBe, err := cfg.CreateBackend()
		if err != nil {
			cfg.Backend = originalBackend
			handleError(fmt.Errorf("failed to create destination backend: %w", err))
			return
		}
		defer func() { _ = destBe.Close() }()

		// Create migrator
		migrator, err := migration.NewMigrator(sourceBe, destBe)
		if err != nil {
			cfg.Backend = originalBackend
			handleError(fmt.Errorf("failed to create migrator: %w", err))
			return
		}
		defer func() { _ = migrator.Close() }()

		// Build filter from flags
		filter := buildMigrationFilter(cmd)

		// Build migration options
		opts := &migration.MigrateOptions{
			DeleteSourceAfterVerification: deleteSource,
			SkipVerification:              skipVerify,
			StopOnError:                   stopOnError,
			Parallel:                      parallel,
		}

		if opts.Parallel <= 0 {
			opts.Parallel = 1
		}

		// Get migration plan first
		plan, err := migrator.MigrationPlan(filter)
		if err != nil {
			cfg.Backend = originalBackend
			handleError(fmt.Errorf("failed to create migration plan: %w", err))
			return
		}

		if len(plan.Keys) == 0 {
			cfg.Backend = originalBackend
			if err := printer.PrintSuccess("No keys found matching the filter"); err != nil {
				handleError(err)
			}
			return
		}

		// Show plan to user
		fmt.Printf("\nMigration Plan:\n")
		fmt.Printf("  Source: %s\n", sourceBackend)
		fmt.Printf("  Destination: %s\n", destBackend)
		fmt.Printf("  Keys to migrate: %d\n", len(plan.Keys))
		if len(plan.Warnings) > 0 {
			fmt.Printf("  Warnings:\n")
			for _, w := range plan.Warnings {
				fmt.Printf("    - %s\n", w)
			}
		}

		// Ask for confirmation unless --force is set
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			fmt.Print("\nProceed with migration? (yes/no): ")
			var response string
			_, _ = fmt.Scanln(&response)
			if response != "yes" {
				cfg.Backend = originalBackend
				if err := printer.PrintSuccess("Migration cancelled"); err != nil {
					handleError(err)
				}
				return
			}
		}

		// Execute migration
		result, err := migrator.MigrateAll(filter, opts)
		if err != nil {
			cfg.Backend = originalBackend
			handleError(fmt.Errorf("migration failed: %w", err))
			return
		}

		// Restore original backend
		cfg.Backend = originalBackend

		// Output results
		if cfg.OutputFormat == "json" {
			outputMigrationResultJSON(result, printer)
		} else {
			outputMigrationResultText(result, printer)
		}
	},
}

// migrateValidateCmd validates keys after migration
var migrateValidateCmd = &cobra.Command{
	Use:   "validate --key-id <key-id>",
	Short: "Validate migrated keys",
	Long:  `Verify that a key migrated to the destination backend works correctly`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyID, _ := cmd.Flags().GetString("key-id")
		sourceBackend, _ := cmd.Flags().GetString("from")
		destBackend, _ := cmd.Flags().GetString("to")

		if keyID == "" || sourceBackend == "" || destBackend == "" {
			handleError(fmt.Errorf("--key-id, --from, and --to flags are required"))
			return
		}

		printVerbose("Validating key %s migration from %s to %s", keyID, sourceBackend, destBackend)

		// Save current backend and switch to source
		originalBackend := cfg.Backend
		cfg.Backend = sourceBackend

		sourceBe, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create source backend: %w", err))
			return
		}
		defer func() { _ = sourceBe.Close() }()

		// Switch to destination backend
		cfg.Backend = destBackend

		destBe, err := cfg.CreateBackend()
		if err != nil {
			cfg.Backend = originalBackend
			handleError(fmt.Errorf("failed to create destination backend: %w", err))
			return
		}
		defer func() { _ = destBe.Close() }()

		// Create migrator
		migrator, err := migration.NewMigrator(sourceBe, destBe)
		if err != nil {
			cfg.Backend = originalBackend
			handleError(fmt.Errorf("failed to create migrator: %w", err))
			return
		}
		defer func() { _ = migrator.Close() }()

		// Build key attributes from ID
		attrs := &types.KeyAttributes{
			CN: keyID,
		}

		// Validate
		result, err := migrator.ValidateMigration(attrs)
		if err != nil {
			cfg.Backend = originalBackend
			handleError(fmt.Errorf("validation failed: %w", err))
			return
		}

		// Restore original backend
		cfg.Backend = originalBackend

		// Output result
		if cfg.OutputFormat == "json" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
		} else {
			if result.IsValid {
				if err := printer.PrintSuccess(result.Message); err != nil {
					handleError(err)
				}
			} else {
				if err := printer.PrintError(fmt.Errorf("%s", result.Message)); err != nil {
					handleError(err)
				}
			}

			if len(result.Errors) > 0 {
				fmt.Printf("\nErrors:\n")
				for _, e := range result.Errors {
					fmt.Printf("  - %s\n", e)
				}
			}

			if len(result.Warnings) > 0 {
				fmt.Printf("\nWarnings:\n")
				for _, w := range result.Warnings {
					fmt.Printf("  - %s\n", w)
				}
			}
		}
	},
}

// Helper functions

// buildMigrationFilter builds a KeyFilter from command flags
func buildMigrationFilter(cmd *cobra.Command) *migration.KeyFilter {
	filter := &migration.KeyFilter{}

	// Key types
	if keyTypes, _ := cmd.Flags().GetStringSlice("key-types"); len(keyTypes) > 0 {
		for _, kt := range keyTypes {
			switch strings.ToLower(kt) {
			case "signing":
				filter.KeyTypes = append(filter.KeyTypes, types.KeyTypeSigning)
			case "encryption":
				filter.KeyTypes = append(filter.KeyTypes, types.KeyTypeEncryption)
			case "ca":
				filter.KeyTypes = append(filter.KeyTypes, types.KeyTypeCA)
			case "tls":
				filter.KeyTypes = append(filter.KeyTypes, types.KeyTypeTLS)
			}
		}
	}

	// Store types
	if storeTypes, _ := cmd.Flags().GetStringSlice("store-types"); len(storeTypes) > 0 {
		for _, st := range storeTypes {
			filter.StoreTypes = append(filter.StoreTypes, types.ParseStoreType(st))
		}
	}

	// Partitions
	if partitions, _ := cmd.Flags().GetStringSlice("partitions"); len(partitions) > 0 {
		for _, p := range partitions {
			filter.Partitions = append(filter.Partitions, types.Partition(p))
		}
	}

	// CN pattern
	if pattern, _ := cmd.Flags().GetString("cn-pattern"); pattern != "" {
		filter.CNPattern = pattern
	}

	// Created before/after
	if before, _ := cmd.Flags().GetString("created-before"); before != "" {
		if t, err := time.Parse(time.RFC3339, before); err == nil {
			filter.CreatedBefore = &t
		}
	}

	if after, _ := cmd.Flags().GetString("created-after"); after != "" {
		if t, err := time.Parse(time.RFC3339, after); err == nil {
			filter.CreatedAfter = &t
		}
	}

	return filter
}

// outputMigrationPlanText outputs migration plan in text format
func outputMigrationPlanText(plan *migration.MigrationPlan, printer *Printer) {
	fmt.Printf("\nMigration Plan\n")
	fmt.Printf("==============\n")
	fmt.Printf("Source Backend:        %s\n", plan.SourceBackendType)
	fmt.Printf("Destination Backend:   %s\n", plan.DestBackendType)
	fmt.Printf("Keys to Migrate:       %d\n", len(plan.Keys))
	fmt.Printf("Estimated Duration:    %v\n", plan.EstimatedDuration)
	fmt.Printf("Analysis Timestamp:    %s\n", plan.Timestamp.Format(time.RFC3339))

	if len(plan.Keys) > 0 {
		fmt.Printf("\nKeys:\n")
		for i, key := range plan.Keys {
			fmt.Printf("  %d. %s (Type: %s, Algorithm: %v)\n", i+1, key.CN, key.KeyType, key.KeyAlgorithm)
		}
	}

	if len(plan.Warnings) > 0 {
		fmt.Printf("\nWarnings:\n")
		for _, w := range plan.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	if len(plan.Errors) > 0 {
		fmt.Printf("\nErrors:\n")
		for _, e := range plan.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}
}

// outputMigrationPlanJSON outputs migration plan in JSON format
func outputMigrationPlanJSON(plan *migration.MigrationPlan, printer *Printer) {
	// Create a serializable version of the plan
	output := map[string]interface{}{
		"source_backend":     plan.SourceBackendType,
		"dest_backend":       plan.DestBackendType,
		"keys_count":         len(plan.Keys),
		"estimated_duration": plan.EstimatedDuration.String(),
		"timestamp":          plan.Timestamp,
		"warnings":           plan.Warnings,
		"errors":             plan.Errors,
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))
}

// outputMigrationResultText outputs migration result in text format
func outputMigrationResultText(result *migration.MigrationResult, printer *Printer) {
	fmt.Printf("\nMigration Result\n")
	fmt.Printf("================\n")
	fmt.Printf("Successful:    %d\n", result.SuccessCount)
	fmt.Printf("Failed:        %d\n", result.FailureCount)
	fmt.Printf("Skipped:       %d\n", result.SkippedCount)
	fmt.Printf("Total Time:    %v\n", result.Duration)

	if len(result.SuccessfulKeys) > 0 {
		fmt.Printf("\nSuccessfully Migrated Keys:\n")
		for i, key := range result.SuccessfulKeys {
			fmt.Printf("  %d. %s\n", i+1, key.CN)
		}
	}

	if len(result.FailedKeys) > 0 {
		fmt.Printf("\nFailed Migrations:\n")
		i := 1
		for key, err := range result.FailedKeys {
			fmt.Printf("  %d. %s: %v\n", i, key.CN, err)
			i++
		}
	}
}

// outputMigrationResultJSON outputs migration result in JSON format
func outputMigrationResultJSON(result *migration.MigrationResult, printer *Printer) {
	// Create a serializable version
	failedKeys := make(map[string]string)
	for key, err := range result.FailedKeys {
		failedKeys[key.CN] = err.Error()
	}

	successfulCNs := make([]string, 0, len(result.SuccessfulKeys))
	for _, key := range result.SuccessfulKeys {
		successfulCNs = append(successfulCNs, key.CN)
	}

	output := map[string]interface{}{
		"successful_count": result.SuccessCount,
		"failure_count":    result.FailureCount,
		"skipped_count":    result.SkippedCount,
		"successful_keys":  successfulCNs,
		"failed_keys":      failedKeys,
		"start_time":       result.StartTime,
		"end_time":         result.EndTime,
		"duration":         result.Duration.String(),
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))
}

func init() {
	// Add migrate command and subcommands
	rootCmd.AddCommand(migrateCmd)
	migrateCmd.AddCommand(migratePlanCmd)
	migrateCmd.AddCommand(migrateExecuteCmd)
	migrateCmd.AddCommand(migrateValidateCmd)

	// Plan flags
	migratePlanCmd.Flags().String("from", "", "source backend")
	migratePlanCmd.Flags().String("to", "", "destination backend")
	migratePlanCmd.Flags().StringSlice("key-types", []string{}, "filter by key types (signing, encryption, ca, tls)")
	migratePlanCmd.Flags().StringSlice("store-types", []string{}, "filter by store types")
	migratePlanCmd.Flags().StringSlice("partitions", []string{}, "filter by partitions")
	migratePlanCmd.Flags().String("cn-pattern", "", "regex pattern to match common names")
	migratePlanCmd.Flags().String("created-before", "", "only keys created before (RFC3339 format)")
	migratePlanCmd.Flags().String("created-after", "", "only keys created after (RFC3339 format)")

	// Execute flags
	migrateExecuteCmd.Flags().String("from", "", "source backend")
	migrateExecuteCmd.Flags().String("to", "", "destination backend")
	migrateExecuteCmd.Flags().Bool("delete-source", false, "delete key from source after successful migration")
	migrateExecuteCmd.Flags().Bool("skip-verify", false, "skip verification of migrated keys")
	migrateExecuteCmd.Flags().Bool("stop-on-error", false, "stop migration if any key fails")
	migrateExecuteCmd.Flags().Int("parallel", 1, "number of parallel migrations")
	migrateExecuteCmd.Flags().Bool("force", false, "skip confirmation prompt")
	migrateExecuteCmd.Flags().StringSlice("key-types", []string{}, "filter by key types (signing, encryption, ca, tls)")
	migrateExecuteCmd.Flags().StringSlice("store-types", []string{}, "filter by store types")
	migrateExecuteCmd.Flags().StringSlice("partitions", []string{}, "filter by partitions")
	migrateExecuteCmd.Flags().String("cn-pattern", "", "regex pattern to match common names")
	migrateExecuteCmd.Flags().String("created-before", "", "only keys created before (RFC3339 format)")
	migrateExecuteCmd.Flags().String("created-after", "", "only keys created after (RFC3339 format)")

	// Validate flags
	migrateValidateCmd.Flags().String("from", "", "source backend")
	migrateValidateCmd.Flags().String("to", "", "destination backend")
	migrateValidateCmd.Flags().String("key-id", "", "key ID to validate")
}
