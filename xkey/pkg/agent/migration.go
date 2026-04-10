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

package agent

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Migration errors.
var (
	// ErrMigrationNilStore is returned when a nil DAOStore is provided to migration.
	ErrMigrationNilStore = errors.New("agent: migration requires a non-nil DAOStore")

	// ErrMigrationNilLogger is returned when a nil logger is provided to migration.
	ErrMigrationNilLogger = errors.New("agent: migration requires a non-nil logger")

	// ErrMigrationSourceDir is returned when the source directory is empty or invalid.
	ErrMigrationSourceDir = errors.New("agent: migration source directory is required")

	// ErrMigrationReadDir is returned when the source directory cannot be read.
	ErrMigrationReadDir = errors.New("agent: failed to read migration source directory")
)

// MigrationResult reports the outcome of a migration from file-based
// storage to DAO-backed storage.
type MigrationResult struct {
	// Total is the number of JSON files found in the source directory.
	Total int

	// Migrated is the number of agents successfully migrated.
	Migrated int

	// Skipped is the number of files skipped due to parse or save errors.
	Skipped int

	// Errors contains per-file errors for files that failed migration.
	Errors map[string]error
}

// MigrateFileStoreToDAO reads all agent JSON files from sourceDir,
// parses each as an AgentInfo, and saves it to the DAOStore. Files
// that cannot be parsed or saved are skipped and reported in the
// result. This operation is idempotent: re-running it will overwrite
// existing DAO entries with the file-based data.
func MigrateFileStoreToDAO(sourceDir string, store *DAOStore, logger *slog.Logger) (*MigrationResult, error) {
	if sourceDir == "" {
		return nil, ErrMigrationSourceDir
	}
	if store == nil {
		return nil, ErrMigrationNilStore
	}
	if logger == nil {
		return nil, ErrMigrationNilLogger
	}

	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Info("migration source directory does not exist, nothing to migrate",
				"dir", sourceDir)
			return &MigrationResult{Errors: make(map[string]error)}, nil
		}
		return nil, ErrMigrationReadDir
	}

	result := &MigrationResult{
		Errors: make(map[string]error),
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		result.Total++
		filePath := filepath.Join(sourceDir, entry.Name())

		data, readErr := os.ReadFile(filePath)
		if readErr != nil {
			result.Skipped++
			result.Errors[entry.Name()] = readErr
			logger.Warn("migration: skipping unreadable file",
				"path", filePath, "error", readErr)
			continue
		}

		var agent AgentInfo
		if parseErr := json.Unmarshal(data, &agent); parseErr != nil {
			result.Skipped++
			result.Errors[entry.Name()] = parseErr
			logger.Warn("migration: skipping malformed file",
				"path", filePath, "error", parseErr)
			continue
		}

		if agent.ID == "" {
			result.Skipped++
			result.Errors[entry.Name()] = ErrAgentNotFound
			logger.Warn("migration: skipping file with empty agent ID",
				"path", filePath)
			continue
		}

		if saveErr := store.SaveAgent(&agent); saveErr != nil {
			result.Skipped++
			result.Errors[entry.Name()] = saveErr
			logger.Warn("migration: failed to save agent",
				"path", filePath, "agent_id", agent.ID, "error", saveErr)
			continue
		}

		result.Migrated++
		logger.Debug("migration: migrated agent",
			"agent_id", agent.ID, "file", entry.Name())
	}

	logger.Info("migration complete",
		"total", result.Total,
		"migrated", result.Migrated,
		"skipped", result.Skipped)

	return result, nil
}
