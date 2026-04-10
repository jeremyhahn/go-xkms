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

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/mocks"
	"github.com/jeremyhahn/go-xkms/pkg/migration"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/spf13/cobra"
)

// =============================================================================
// Basic command structure tests
// =============================================================================

func TestMigrateCmd_Exists(t *testing.T) {
	if migrateCmd == nil {
		t.Fatal("migrateCmd should not be nil")
	}
}

func TestMigrateCmd_Properties(t *testing.T) {
	if migrateCmd.Use != "migrate" {
		t.Errorf("migrateCmd.Use = %v, want migrate", migrateCmd.Use)
	}

	if migrateCmd.Short == "" {
		t.Error("migrateCmd.Short should not be empty")
	}
}

func TestMigrateCmd_HasSubcommands(t *testing.T) {
	subcommands := migrateCmd.Commands()

	expectedCmds := []string{
		"plan",
		"execute",
		"validate",
	}
	foundCmds := make(map[string]bool)

	for _, cmd := range subcommands {
		foundCmds[cmd.Name()] = true
	}

	for _, expected := range expectedCmds {
		if !foundCmds[expected] {
			t.Errorf("expected subcommand %q not found", expected)
		}
	}
}

func TestMigratePlanCmd_Exists(t *testing.T) {
	if migratePlanCmd == nil {
		t.Fatal("migratePlanCmd should not be nil")
	}
}

func TestMigratePlanCmd_Properties(t *testing.T) {
	if migratePlanCmd.Short == "" {
		t.Error("migratePlanCmd.Short should not be empty")
	}
}

func TestMigrateExecuteCmd_Exists(t *testing.T) {
	if migrateExecuteCmd == nil {
		t.Fatal("migrateExecuteCmd should not be nil")
	}
}

func TestMigrateExecuteCmd_Properties(t *testing.T) {
	if migrateExecuteCmd.Short == "" {
		t.Error("migrateExecuteCmd.Short should not be empty")
	}
}

func TestMigrateValidateCmd_Exists(t *testing.T) {
	if migrateValidateCmd == nil {
		t.Fatal("migrateValidateCmd should not be nil")
	}
}

func TestMigrateValidateCmd_Properties(t *testing.T) {
	if migrateValidateCmd.Short == "" {
		t.Error("migrateValidateCmd.Short should not be empty")
	}
}

func TestMigrateCmd_CommandStructure(t *testing.T) {
	if !migrateCmd.HasSubCommands() {
		t.Error("migrateCmd should have subcommands")
	}

	for _, sub := range migrateCmd.Commands() {
		if sub.Parent() != migrateCmd {
			t.Errorf("subcommand %s should have migrateCmd as parent", sub.Use)
		}
	}
}

func TestMigratePlanCmd_HasFlags(t *testing.T) {
	flags := migratePlanCmd.Flags()

	expectedFlags := []string{"from", "to", "key-types", "store-types", "partitions", "cn-pattern", "created-before", "created-after"}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on migratePlanCmd", flag)
		}
	}
}

func TestMigrateExecuteCmd_HasFlags(t *testing.T) {
	flags := migrateExecuteCmd.Flags()

	expectedFlags := []string{"from", "to", "delete-source", "skip-verify", "stop-on-error", "parallel", "force"}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on migrateExecuteCmd", flag)
		}
	}
}

func TestMigrateValidateCmd_HasFlags(t *testing.T) {
	flags := migrateValidateCmd.Flags()

	expectedFlags := []string{"from", "to", "key-id"}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on migrateValidateCmd", flag)
		}
	}
}

// =============================================================================
// buildMigrationFilter tests
// =============================================================================

func TestBuildMigrationFilter_Empty_Migrate(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")

	filter := buildMigrationFilter(cmd)

	if filter == nil {
		t.Fatal("buildMigrationFilter should return non-nil filter")
	}
	if len(filter.KeyTypes) != 0 {
		t.Errorf("expected 0 key types, got %d", len(filter.KeyTypes))
	}
	if len(filter.StoreTypes) != 0 {
		t.Errorf("expected 0 store types, got %d", len(filter.StoreTypes))
	}
	if len(filter.Partitions) != 0 {
		t.Errorf("expected 0 partitions, got %d", len(filter.Partitions))
	}
}

func TestBuildMigrationFilter_WithKeyTypes_Migrate(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")
	_ = cmd.Flags().Set("key-types", "signing,encryption,ca,tls")

	filter := buildMigrationFilter(cmd)

	if len(filter.KeyTypes) != 4 {
		t.Errorf("expected 4 key types, got %d", len(filter.KeyTypes))
	}

	expectedTypes := map[types.KeyType]bool{
		types.KeyTypeSigning:    true,
		types.KeyTypeEncryption: true,
		types.KeyTypeCA:         true,
		types.KeyTypeTLS:        true,
	}
	for _, kt := range filter.KeyTypes {
		if !expectedTypes[kt] {
			t.Errorf("unexpected key type: %v", kt)
		}
	}
}

func TestBuildMigrationFilter_WithStoreTypes_Migrate(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")
	_ = cmd.Flags().Set("store-types", "software,tpm2")

	filter := buildMigrationFilter(cmd)

	if len(filter.StoreTypes) != 2 {
		t.Errorf("expected 2 store types, got %d", len(filter.StoreTypes))
	}
}

func TestBuildMigrationFilter_WithPartitions_Migrate(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")
	_ = cmd.Flags().Set("partitions", "default,production")

	filter := buildMigrationFilter(cmd)

	if len(filter.Partitions) != 2 {
		t.Errorf("expected 2 partitions, got %d", len(filter.Partitions))
	}
	if filter.Partitions[0] != types.Partition("default") {
		t.Errorf("expected partition 'default', got %v", filter.Partitions[0])
	}
	if filter.Partitions[1] != types.Partition("production") {
		t.Errorf("expected partition 'production', got %v", filter.Partitions[1])
	}
}

func TestBuildMigrationFilter_WithCNPattern_Migrate(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")
	_ = cmd.Flags().Set("cn-pattern", "test-*")

	filter := buildMigrationFilter(cmd)

	if filter.CNPattern != "test-*" {
		t.Errorf("expected cn-pattern 'test-*', got %q", filter.CNPattern)
	}
}

func TestBuildMigrationFilter_WithDates_Migrate(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")

	now := time.Now()
	_ = cmd.Flags().Set("created-before", now.Format(time.RFC3339))
	_ = cmd.Flags().Set("created-after", now.Add(-24*time.Hour).Format(time.RFC3339))

	filter := buildMigrationFilter(cmd)

	if filter.CreatedBefore == nil {
		t.Error("expected created-before to be set")
	}
	if filter.CreatedAfter == nil {
		t.Error("expected created-after to be set")
	}
}

func TestBuildMigrationFilter_InvalidDates(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")

	_ = cmd.Flags().Set("created-before", "invalid-date")
	_ = cmd.Flags().Set("created-after", "also-invalid")

	filter := buildMigrationFilter(cmd)

	if filter.CreatedBefore != nil {
		t.Error("expected created-before to be nil for invalid date")
	}
	if filter.CreatedAfter != nil {
		t.Error("expected created-after to be nil for invalid date")
	}
}

// =============================================================================
// Output helper function tests
// =============================================================================

// captureStdoutForMigration captures stdout during function execution
func captureStdoutForMigration(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestOutputMigrationPlanText_Migrate(t *testing.T) {
	printer := NewPrinter("text", &bytes.Buffer{})

	plan := &migration.MigrationPlan{
		SourceBackendType: types.BackendTypeSoftware,
		DestBackendType:   types.BackendTypeTPM2,
		Keys: []*types.KeyAttributes{
			{CN: "key1", KeyType: types.KeyTypeSigning, KeyAlgorithm: x509.RSA},
			{CN: "key2", KeyType: types.KeyTypeEncryption, KeyAlgorithm: x509.ECDSA},
		},
		EstimatedDuration: 5 * time.Second,
		Timestamp:         time.Now(),
		Warnings:          []string{"warning1", "warning2"},
		Errors:            []string{"error1"},
	}

	output := captureStdoutForMigration(func() {
		outputMigrationPlanText(plan, printer)
	})

	if !strings.Contains(output, "Migration Plan") {
		t.Errorf("expected 'Migration Plan' header in output, got: %s", output)
	}
	if !strings.Contains(output, "Keys to Migrate:") {
		t.Errorf("expected 'Keys to Migrate:' in output, got: %s", output)
	}
	if !strings.Contains(output, "key1") {
		t.Errorf("expected 'key1' in output, got: %s", output)
	}
	if !strings.Contains(output, "key2") {
		t.Errorf("expected 'key2' in output, got: %s", output)
	}
	if !strings.Contains(output, "Warnings:") {
		t.Errorf("expected 'Warnings:' in output, got: %s", output)
	}
	if !strings.Contains(output, "Errors:") {
		t.Errorf("expected 'Errors:' in output, got: %s", output)
	}
}

func TestOutputMigrationPlanText_NoKeys(t *testing.T) {
	printer := NewPrinter("text", &bytes.Buffer{})

	plan := &migration.MigrationPlan{
		SourceBackendType: types.BackendTypeSoftware,
		DestBackendType:   types.BackendTypeTPM2,
		Keys:              []*types.KeyAttributes{},
		EstimatedDuration: 0,
		Timestamp:         time.Now(),
	}

	output := captureStdoutForMigration(func() {
		outputMigrationPlanText(plan, printer)
	})

	if !strings.Contains(output, "Keys to Migrate:       0") {
		t.Errorf("expected 'Keys to Migrate: 0' in output, got: %s", output)
	}
}

func TestOutputMigrationPlanJSON(t *testing.T) {
	printer := NewPrinter("json", &bytes.Buffer{})

	plan := &migration.MigrationPlan{
		SourceBackendType: types.BackendTypeSoftware,
		DestBackendType:   types.BackendTypeTPM2,
		Keys: []*types.KeyAttributes{
			{CN: "key1", KeyType: types.KeyTypeSigning, KeyAlgorithm: x509.RSA},
		},
		EstimatedDuration: 5 * time.Second,
		Timestamp:         time.Now(),
		Warnings:          []string{"warning1"},
		Errors:            []string{"error1"},
	}

	output := captureStdoutForMigration(func() {
		outputMigrationPlanJSON(plan, printer)
	})

	if !strings.Contains(output, `"source_backend":`) {
		t.Errorf("expected 'source_backend' in JSON output, got: %s", output)
	}
	if !strings.Contains(output, `"dest_backend":`) {
		t.Errorf("expected 'dest_backend' in JSON output, got: %s", output)
	}
	if !strings.Contains(output, `"keys_count":`) {
		t.Errorf("expected 'keys_count' in JSON output, got: %s", output)
	}
	if !strings.Contains(output, `"estimated_duration":`) {
		t.Errorf("expected 'estimated_duration' in JSON output, got: %s", output)
	}
}

func TestOutputMigrationResultText_Migrate(t *testing.T) {
	printer := NewPrinter("text", &bytes.Buffer{})

	key := &types.KeyAttributes{CN: "failed-key"}
	failedKeys := make(map[*types.KeyAttributes]error)
	failedKeys[key] = errors.New("key migration failed")

	result := &migration.MigrationResult{
		SuccessCount:   5,
		FailureCount:   1,
		SkippedCount:   2,
		Duration:       10 * time.Second,
		SuccessfulKeys: []*types.KeyAttributes{{CN: "key1"}, {CN: "key2"}},
		FailedKeys:     failedKeys,
	}

	output := captureStdoutForMigration(func() {
		outputMigrationResultText(result, printer)
	})

	if !strings.Contains(output, "Migration Result") {
		t.Errorf("expected 'Migration Result' header in output, got: %s", output)
	}
	if !strings.Contains(output, "Successful:    5") {
		t.Errorf("expected 'Successful: 5' in output, got: %s", output)
	}
	if !strings.Contains(output, "Failed:        1") {
		t.Errorf("expected 'Failed: 1' in output, got: %s", output)
	}
	if !strings.Contains(output, "Skipped:       2") {
		t.Errorf("expected 'Skipped: 2' in output, got: %s", output)
	}
	if !strings.Contains(output, "key1") {
		t.Errorf("expected 'key1' in successful keys output, got: %s", output)
	}
	if !strings.Contains(output, "failed-key") {
		t.Errorf("expected 'failed-key' in failed keys output, got: %s", output)
	}
}

func TestOutputMigrationResultText_NoFailures(t *testing.T) {
	printer := NewPrinter("text", &bytes.Buffer{})

	result := &migration.MigrationResult{
		SuccessCount:   5,
		FailureCount:   0,
		SkippedCount:   0,
		Duration:       10 * time.Second,
		SuccessfulKeys: []*types.KeyAttributes{{CN: "key1"}},
		FailedKeys:     make(map[*types.KeyAttributes]error),
	}

	output := captureStdoutForMigration(func() {
		outputMigrationResultText(result, printer)
	})

	if !strings.Contains(output, "Successfully Migrated Keys:") {
		t.Errorf("expected 'Successfully Migrated Keys:' in output, got: %s", output)
	}
	if strings.Contains(output, "Failed Migrations:") {
		t.Error("did not expect 'Failed Migrations:' when no failures")
	}
}

func TestOutputMigrationResultJSON_Migrate(t *testing.T) {
	printer := NewPrinter("json", &bytes.Buffer{})

	key := &types.KeyAttributes{CN: "failed-key"}
	failedKeys := make(map[*types.KeyAttributes]error)
	failedKeys[key] = errors.New("key migration failed")

	result := &migration.MigrationResult{
		SuccessCount:   5,
		FailureCount:   1,
		SkippedCount:   2,
		Duration:       10 * time.Second,
		SuccessfulKeys: []*types.KeyAttributes{{CN: "key1"}, {CN: "key2"}},
		FailedKeys:     failedKeys,
		StartTime:      time.Now().Add(-10 * time.Second),
		EndTime:        time.Now(),
	}

	output := captureStdoutForMigration(func() {
		outputMigrationResultJSON(result, printer)
	})

	if !strings.Contains(output, `"successful_count":`) {
		t.Errorf("expected 'successful_count' in JSON output, got: %s", output)
	}
	if !strings.Contains(output, `"failure_count":`) {
		t.Errorf("expected 'failure_count' in JSON output, got: %s", output)
	}
	if !strings.Contains(output, `"skipped_count":`) {
		t.Errorf("expected 'skipped_count' in JSON output, got: %s", output)
	}
	if !strings.Contains(output, `"successful_keys":`) {
		t.Errorf("expected 'successful_keys' in JSON output, got: %s", output)
	}
	if !strings.Contains(output, `"failed_keys":`) {
		t.Errorf("expected 'failed_keys' in JSON output, got: %s", output)
	}
	if !strings.Contains(output, `"duration":`) {
		t.Errorf("expected 'duration' in JSON output, got: %s", output)
	}
}

// =============================================================================
// migratePlanCmd Run function tests
// =============================================================================

func TestMigratePlanCmd_MissingFromFlag(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	cmd := &cobra.Command{}
	cmd.Flags().String("from", "", "source backend")
	cmd.Flags().String("to", "software", "destination backend")

	code := captureExit(t, func() {
		migratePlanCmd.Run(cmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for missing from flag, got %d", code)
	}
}

func TestMigratePlanCmd_MissingToFlag(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	cmd := &cobra.Command{}
	cmd.Flags().String("from", "software", "source backend")
	cmd.Flags().String("to", "", "destination backend")

	code := captureExit(t, func() {
		migratePlanCmd.Run(cmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for missing to flag, got %d", code)
	}
}

func TestMigratePlanCmd_SourceBackendCreationError(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"
	globalConfig.Backend = "software"
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		return nil, fmt.Errorf("backend creation failed")
	}

	_ = migratePlanCmd.Flags().Set("from", "software")
	_ = migratePlanCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migratePlanCmd.Run(migratePlanCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for source backend creation error, got %d", code)
	}

	_ = migratePlanCmd.Flags().Set("from", "")
	_ = migratePlanCmd.Flags().Set("to", "")
}

func TestMigratePlanCmd_DestBackendCreationError(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	callCount := 0
	sourceMock := mocks.NewExtendedMockBackend()

	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return nil, fmt.Errorf("dest backend creation failed")
	}

	_ = migratePlanCmd.Flags().Set("from", "software")
	_ = migratePlanCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migratePlanCmd.Run(migratePlanCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for dest backend creation error, got %d", code)
	}

	_ = migratePlanCmd.Flags().Set("from", "")
	_ = migratePlanCmd.Flags().Set("to", "")
}

func TestMigratePlanCmd_Success_TextOutput(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sourceMock.StoreKey("test-key", ecKey)

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migratePlanCmd.Flags().Set("from", "software")
	_ = migratePlanCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migratePlanCmd.Run(migratePlanCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit on success, got code %d", code)
	}

	_ = migratePlanCmd.Flags().Set("from", "")
	_ = migratePlanCmd.Flags().Set("to", "")
}

func TestMigratePlanCmd_Success_JSONOutput(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "json"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sourceMock.StoreKey("test-key", ecKey)

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migratePlanCmd.Flags().Set("from", "software")
	_ = migratePlanCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migratePlanCmd.Run(migratePlanCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit on success, got code %d", code)
	}

	_ = migratePlanCmd.Flags().Set("from", "")
	_ = migratePlanCmd.Flags().Set("to", "")
}

// =============================================================================
// migrateExecuteCmd Run function tests
// =============================================================================

func TestMigrateExecuteCmd_MissingFlags(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	_ = migrateExecuteCmd.Flags().Set("from", "")
	_ = migrateExecuteCmd.Flags().Set("to", "software")

	code := captureExit(t, func() {
		migrateExecuteCmd.Run(migrateExecuteCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for missing from flag, got %d", code)
	}

	_ = migrateExecuteCmd.Flags().Set("from", "")
	_ = migrateExecuteCmd.Flags().Set("to", "")
}

func TestMigrateExecuteCmd_SourceBackendError(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		return nil, fmt.Errorf("source backend creation failed")
	}

	_ = migrateExecuteCmd.Flags().Set("from", "software")
	_ = migrateExecuteCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migrateExecuteCmd.Run(migrateExecuteCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for source backend error, got %d", code)
	}

	_ = migrateExecuteCmd.Flags().Set("from", "")
	_ = migrateExecuteCmd.Flags().Set("to", "")
}

func TestMigrateExecuteCmd_DestBackendError(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return nil, fmt.Errorf("dest backend creation failed")
	}

	_ = migrateExecuteCmd.Flags().Set("from", "software")
	_ = migrateExecuteCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migrateExecuteCmd.Run(migrateExecuteCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for dest backend error, got %d", code)
	}

	_ = migrateExecuteCmd.Flags().Set("from", "")
	_ = migrateExecuteCmd.Flags().Set("to", "")
}

func TestMigrateExecuteCmd_NoKeysFound(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migrateExecuteCmd.Flags().Set("from", "software")
	_ = migrateExecuteCmd.Flags().Set("to", "tpm2")
	_ = migrateExecuteCmd.Flags().Set("force", "true")

	code := captureExit(t, func() {
		migrateExecuteCmd.Run(migrateExecuteCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit when no keys found, got code %d", code)
	}

	_ = migrateExecuteCmd.Flags().Set("from", "")
	_ = migrateExecuteCmd.Flags().Set("to", "")
	_ = migrateExecuteCmd.Flags().Set("force", "false")
}

func TestMigrateExecuteCmd_WithForce_Success(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sourceMock.StoreKey("migrate-key", ecKey)

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migrateExecuteCmd.Flags().Set("from", "software")
	_ = migrateExecuteCmd.Flags().Set("to", "tpm2")
	_ = migrateExecuteCmd.Flags().Set("force", "true")
	_ = migrateExecuteCmd.Flags().Set("skip-verify", "true")

	code := captureExit(t, func() {
		migrateExecuteCmd.Run(migrateExecuteCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit on success, got code %d", code)
	}

	_ = migrateExecuteCmd.Flags().Set("from", "")
	_ = migrateExecuteCmd.Flags().Set("to", "")
	_ = migrateExecuteCmd.Flags().Set("force", "false")
	_ = migrateExecuteCmd.Flags().Set("skip-verify", "false")
}

func TestMigrateExecuteCmd_WithParallel(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	for i := 0; i < 3; i++ {
		ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sourceMock.StoreKey(fmt.Sprintf("key-%d", i), ecKey)
	}

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migrateExecuteCmd.Flags().Set("from", "software")
	_ = migrateExecuteCmd.Flags().Set("to", "tpm2")
	_ = migrateExecuteCmd.Flags().Set("force", "true")
	_ = migrateExecuteCmd.Flags().Set("parallel", "2")
	_ = migrateExecuteCmd.Flags().Set("skip-verify", "true")

	code := captureExit(t, func() {
		migrateExecuteCmd.Run(migrateExecuteCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit on success, got code %d", code)
	}

	_ = migrateExecuteCmd.Flags().Set("from", "")
	_ = migrateExecuteCmd.Flags().Set("to", "")
	_ = migrateExecuteCmd.Flags().Set("force", "false")
	_ = migrateExecuteCmd.Flags().Set("parallel", "1")
	_ = migrateExecuteCmd.Flags().Set("skip-verify", "false")
}

func TestMigrateExecuteCmd_JSONOutput(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "json"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sourceMock.StoreKey("json-key", ecKey)

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migrateExecuteCmd.Flags().Set("from", "software")
	_ = migrateExecuteCmd.Flags().Set("to", "tpm2")
	_ = migrateExecuteCmd.Flags().Set("force", "true")
	_ = migrateExecuteCmd.Flags().Set("skip-verify", "true")

	code := captureExit(t, func() {
		migrateExecuteCmd.Run(migrateExecuteCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit on success, got code %d", code)
	}

	_ = migrateExecuteCmd.Flags().Set("from", "")
	_ = migrateExecuteCmd.Flags().Set("to", "")
	_ = migrateExecuteCmd.Flags().Set("force", "false")
	_ = migrateExecuteCmd.Flags().Set("skip-verify", "false")
}

// =============================================================================
// migrateValidateCmd Run function tests
// =============================================================================

func TestMigrateValidateCmd_MissingFlags(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	_ = migrateValidateCmd.Flags().Set("key-id", "")
	_ = migrateValidateCmd.Flags().Set("from", "software")
	_ = migrateValidateCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migrateValidateCmd.Run(migrateValidateCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for missing key-id, got %d", code)
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "test-key")
	_ = migrateValidateCmd.Flags().Set("from", "")
	_ = migrateValidateCmd.Flags().Set("to", "tpm2")

	code = captureExit(t, func() {
		migrateValidateCmd.Run(migrateValidateCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for missing from, got %d", code)
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "")
	_ = migrateValidateCmd.Flags().Set("from", "")
	_ = migrateValidateCmd.Flags().Set("to", "")
}

func TestMigrateValidateCmd_SourceBackendError(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		return nil, fmt.Errorf("backend creation failed")
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "test-key")
	_ = migrateValidateCmd.Flags().Set("from", "software")
	_ = migrateValidateCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migrateValidateCmd.Run(migrateValidateCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for source backend error, got %d", code)
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "")
	_ = migrateValidateCmd.Flags().Set("from", "")
	_ = migrateValidateCmd.Flags().Set("to", "")
}

func TestMigrateValidateCmd_DestBackendError(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return nil, fmt.Errorf("dest backend creation failed")
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "test-key")
	_ = migrateValidateCmd.Flags().Set("from", "software")
	_ = migrateValidateCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migrateValidateCmd.Run(migrateValidateCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for dest backend error, got %d", code)
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "")
	_ = migrateValidateCmd.Flags().Set("from", "")
	_ = migrateValidateCmd.Flags().Set("to", "")
}

func TestMigrateValidateCmd_ValidationSuccess(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sourceMock.StoreKey("validate-key", ecKey)
	destMock.StoreKey("validate-key", ecKey)

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "validate-key")
	_ = migrateValidateCmd.Flags().Set("from", "software")
	_ = migrateValidateCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migrateValidateCmd.Run(migrateValidateCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit on success, got code %d", code)
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "")
	_ = migrateValidateCmd.Flags().Set("from", "")
	_ = migrateValidateCmd.Flags().Set("to", "")
}

func TestMigrateValidateCmd_ValidationFailure(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sourceMock.StoreKey("missing-key", ecKey)

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "missing-key")
	_ = migrateValidateCmd.Flags().Set("from", "software")
	_ = migrateValidateCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migrateValidateCmd.Run(migrateValidateCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit on validation (it prints result), got code %d", code)
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "")
	_ = migrateValidateCmd.Flags().Set("from", "")
	_ = migrateValidateCmd.Flags().Set("to", "")
}

func TestMigrateValidateCmd_JSONOutput(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "json"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sourceMock.StoreKey("json-validate-key", ecKey)
	destMock.StoreKey("json-validate-key", ecKey)

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "json-validate-key")
	_ = migrateValidateCmd.Flags().Set("from", "software")
	_ = migrateValidateCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migrateValidateCmd.Run(migrateValidateCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit on success, got code %d", code)
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "")
	_ = migrateValidateCmd.Flags().Set("from", "")
	_ = migrateValidateCmd.Flags().Set("to", "")
}

// =============================================================================
// Edge case and error path tests
// =============================================================================

func TestMigratePlanCmd_ListKeysError(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	sourceMock.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, fmt.Errorf("list keys failed")
	}
	destMock := mocks.NewExtendedMockBackend()

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migratePlanCmd.Flags().Set("from", "software")
	_ = migratePlanCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migratePlanCmd.Run(migratePlanCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 for list keys error, got %d", code)
	}

	_ = migratePlanCmd.Flags().Set("from", "")
	_ = migratePlanCmd.Flags().Set("to", "")
}

func TestMigrateExecuteCmd_MigrationError(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sourceMock.StoreKey("fail-key", ecKey)
	sourceMock.ExportKeyFunc = func(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
		return nil, fmt.Errorf("export failed")
	}

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migrateExecuteCmd.Flags().Set("from", "software")
	_ = migrateExecuteCmd.Flags().Set("to", "tpm2")
	_ = migrateExecuteCmd.Flags().Set("force", "true")
	_ = migrateExecuteCmd.Flags().Set("skip-verify", "true")

	code := captureExit(t, func() {
		migrateExecuteCmd.Run(migrateExecuteCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit (migration reports failures), got code %d", code)
	}

	_ = migrateExecuteCmd.Flags().Set("from", "")
	_ = migrateExecuteCmd.Flags().Set("to", "")
	_ = migrateExecuteCmd.Flags().Set("force", "false")
	_ = migrateExecuteCmd.Flags().Set("skip-verify", "false")
}

func TestMigrateExecuteCmd_StopOnError(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	for i := 0; i < 3; i++ {
		ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sourceMock.StoreKey(fmt.Sprintf("key-%d", i), ecKey)
	}

	sourceMock.ExportKeyFunc = func(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
		return nil, fmt.Errorf("export failed")
	}

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migrateExecuteCmd.Flags().Set("from", "software")
	_ = migrateExecuteCmd.Flags().Set("to", "tpm2")
	_ = migrateExecuteCmd.Flags().Set("force", "true")
	_ = migrateExecuteCmd.Flags().Set("stop-on-error", "true")

	code := captureExit(t, func() {
		migrateExecuteCmd.Run(migrateExecuteCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit (migration reports failures), got code %d", code)
	}

	_ = migrateExecuteCmd.Flags().Set("from", "")
	_ = migrateExecuteCmd.Flags().Set("to", "")
	_ = migrateExecuteCmd.Flags().Set("force", "false")
	_ = migrateExecuteCmd.Flags().Set("stop-on-error", "false")
}

func TestMigrateExecuteCmd_WithFilters(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sourceMock.StoreKey("filtered-key", ecKey)

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migrateExecuteCmd.Flags().Set("from", "software")
	_ = migrateExecuteCmd.Flags().Set("to", "tpm2")
	_ = migrateExecuteCmd.Flags().Set("force", "true")
	_ = migrateExecuteCmd.Flags().Set("key-types", "signing")
	_ = migrateExecuteCmd.Flags().Set("cn-pattern", "filtered-.*")
	_ = migrateExecuteCmd.Flags().Set("skip-verify", "true")

	code := captureExit(t, func() {
		migrateExecuteCmd.Run(migrateExecuteCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit, got code %d", code)
	}

	_ = migrateExecuteCmd.Flags().Set("from", "")
	_ = migrateExecuteCmd.Flags().Set("to", "")
	_ = migrateExecuteCmd.Flags().Set("force", "false")
	_ = migrateExecuteCmd.Flags().Set("key-types", "")
	_ = migrateExecuteCmd.Flags().Set("cn-pattern", "")
	_ = migrateExecuteCmd.Flags().Set("skip-verify", "false")
}

func TestMigrateValidateCmd_WithWarnings(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	sourceMock := mocks.NewExtendedMockBackend()
	destMock := mocks.NewExtendedMockBackend()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sourceMock.StoreKey("warn-key", ecKey)
	destMock.StoreKey("warn-key", ecKey)

	callCount := 0
	globalConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
		callCount++
		if callCount == 1 {
			return sourceMock, nil
		}
		return destMock, nil
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "warn-key")
	_ = migrateValidateCmd.Flags().Set("from", "software")
	_ = migrateValidateCmd.Flags().Set("to", "tpm2")

	code := captureExit(t, func() {
		migrateValidateCmd.Run(migrateValidateCmd, []string{})
	})

	if code != -1 {
		t.Errorf("expected no exit, got code %d", code)
	}

	_ = migrateValidateCmd.Flags().Set("key-id", "")
	_ = migrateValidateCmd.Flags().Set("from", "")
	_ = migrateValidateCmd.Flags().Set("to", "")
}

// =============================================================================
// Concurrent access tests
// =============================================================================

func TestMigratePlanCmd_ConcurrentAccess(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	var wg sync.WaitGroup
	const numGoroutines = 5

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			sourceMock := mocks.NewExtendedMockBackend()
			destMock := mocks.NewExtendedMockBackend()

			ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			sourceMock.StoreKey("concurrent-key", ecKey)

			callCount := 0
			testConfig := NewConfig()
			testConfig.OutputFormat = "text"
			testConfig.BackendFactory = func(cfg *Config) (types.KeyProvider, error) {
				callCount++
				if callCount == 1 {
					return sourceMock, nil
				}
				return destMock, nil
			}

			sourceBe, _ := testConfig.CreateBackend()
			testConfig.Backend = "tpm2"
			destBe, _ := testConfig.CreateBackend()

			migrator, err := migration.NewMigrator(sourceBe, destBe)
			if err == nil {
				_, _ = migrator.MigrationPlan(nil)
				_ = migrator.Close()
			}
		}()
	}

	wg.Wait()
}

// =============================================================================
// Output format edge cases
// =============================================================================

func TestOutputMigrationPlanText_EmptyWarningsAndErrors(t *testing.T) {
	printer := NewPrinter("text", &bytes.Buffer{})

	plan := &migration.MigrationPlan{
		SourceBackendType: types.BackendTypeSoftware,
		DestBackendType:   types.BackendTypeTPM2,
		Keys:              []*types.KeyAttributes{},
		EstimatedDuration: 0,
		Timestamp:         time.Now(),
		Warnings:          []string{},
		Errors:            []string{},
	}

	output := captureStdoutForMigration(func() {
		outputMigrationPlanText(plan, printer)
	})

	if strings.Contains(output, "Warnings:\n  -") {
		t.Error("should not have Warnings section with items when empty")
	}
	if strings.Contains(output, "Errors:\n  -") {
		t.Error("should not have Errors section with items when empty")
	}
}

func TestMigrateCmd_PrinterOutput(t *testing.T) {
	result := &migration.MigrationResult{
		SuccessCount:   1,
		FailureCount:   0,
		SkippedCount:   0,
		Duration:       100 * time.Millisecond,
		SuccessfulKeys: []*types.KeyAttributes{{CN: "output-test-key"}},
		FailedKeys:     make(map[*types.KeyAttributes]error),
	}

	printer := NewPrinter("text", &bytes.Buffer{})
	output := captureStdoutForMigration(func() {
		outputMigrationResultText(result, printer)
	})

	if len(output) == 0 {
		t.Error("expected output to be written to stdout")
	}
	if !strings.Contains(output, "output-test-key") {
		t.Errorf("expected output to contain key name, got: %s", output)
	}
}

// =============================================================================
// getConfig helper test
// =============================================================================

func TestGetConfig_ReturnsGlobalConfig_Migrate(t *testing.T) {
	cfg := getConfig()
	if cfg == nil {
		t.Error("getConfig() should not return nil")
	}
	if cfg != globalConfig {
		t.Error("getConfig() should return globalConfig")
	}
}

// =============================================================================
// Test for printVerbose function coverage
// =============================================================================

func TestPrintVerbose_WhenVerboseEnabled_Migrate(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.Verbose = true
	printVerbose("test message: %s", "value")
}

func TestPrintVerbose_WhenVerboseDisabled_Migrate(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.Verbose = false
	printVerbose("test message: %s", "value")
}

// =============================================================================
// Test for migrate command with all filter options
// =============================================================================

func TestBuildMigrationFilter_AllOptions(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("key-types", nil, "")
	cmd.Flags().StringSlice("store-types", nil, "")
	cmd.Flags().StringSlice("partitions", nil, "")
	cmd.Flags().String("cn-pattern", "", "")
	cmd.Flags().String("created-before", "", "")
	cmd.Flags().String("created-after", "", "")

	now := time.Now()
	_ = cmd.Flags().Set("key-types", "signing,encryption,ca,tls")
	_ = cmd.Flags().Set("store-types", "software,tpm2,pkcs11")
	_ = cmd.Flags().Set("partitions", "default,production,staging")
	_ = cmd.Flags().Set("cn-pattern", "test-.*-key")
	_ = cmd.Flags().Set("created-before", now.Format(time.RFC3339))
	_ = cmd.Flags().Set("created-after", now.Add(-48*time.Hour).Format(time.RFC3339))

	filter := buildMigrationFilter(cmd)

	if len(filter.KeyTypes) != 4 {
		t.Errorf("expected 4 key types, got %d", len(filter.KeyTypes))
	}
	if len(filter.StoreTypes) != 3 {
		t.Errorf("expected 3 store types, got %d", len(filter.StoreTypes))
	}
	if len(filter.Partitions) != 3 {
		t.Errorf("expected 3 partitions, got %d", len(filter.Partitions))
	}
	if filter.CNPattern != "test-.*-key" {
		t.Errorf("expected cn-pattern 'test-.*-key', got %q", filter.CNPattern)
	}
	if filter.CreatedBefore == nil {
		t.Error("expected created-before to be set")
	}
	if filter.CreatedAfter == nil {
		t.Error("expected created-after to be set")
	}
}

// =============================================================================
// Test printer parameter is ignored but present (for API consistency)
// =============================================================================

func TestOutputFunctions_PrinterParameter(t *testing.T) {
	printer := NewPrinter("text", &bytes.Buffer{})

	plan := &migration.MigrationPlan{
		SourceBackendType: types.BackendTypeSoftware,
		DestBackendType:   types.BackendTypeTPM2,
		Keys:              []*types.KeyAttributes{},
		Timestamp:         time.Now(),
	}

	result := &migration.MigrationResult{
		SuccessCount:   0,
		FailureCount:   0,
		SkippedCount:   0,
		Duration:       0,
		SuccessfulKeys: []*types.KeyAttributes{},
		FailedKeys:     make(map[*types.KeyAttributes]error),
	}

	// These should not panic
	_ = captureStdoutForMigration(func() {
		outputMigrationPlanText(plan, printer)
	})
	_ = captureStdoutForMigration(func() {
		outputMigrationPlanJSON(plan, printer)
	})
	_ = captureStdoutForMigration(func() {
		outputMigrationResultText(result, printer)
	})
	_ = captureStdoutForMigration(func() {
		outputMigrationResultJSON(result, printer)
	})

	discardPrinter := NewPrinter("text", io.Discard)
	_ = captureStdoutForMigration(func() {
		outputMigrationPlanText(plan, discardPrinter)
	})
	_ = captureStdoutForMigration(func() {
		outputMigrationResultText(result, discardPrinter)
	})
}
