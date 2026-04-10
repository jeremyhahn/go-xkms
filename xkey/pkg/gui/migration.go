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

package gui

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Legacy PIN artifact file names.
const (
	// legacyPINStateFile is the Argon2id-hashed PIN state file written by
	// the deprecated FilePINManager (CLI extension-serve path).
	legacyPINStateFile = "pin-state.json"

	// legacyTPMPINStateFile is the PIN state file written by the deprecated
	// FilePINManager inside the TPM data subdirectory (GUI path).
	legacyTPMPINStateFile = "pin_state.json"

	// legacyUserPINLabel is the sealed-blob label formerly used to store a
	// raw PIN for auto-unlock via the SealService.
	legacyUserPINLabel = "user_pin"
)

// migratePINArtifacts removes legacy PIN storage files that are no longer
// needed after the migration to backend-native PIN verification.
//
// Legacy artifacts cleaned up:
//   - <dataDir>/pin-state.json        (FilePINManager, CLI path)
//   - <dataDir>/tpm/pin_state.json    (FilePINManager, GUI/TPM path)
//   - Sealed blobs with label "user_pin" (auto-unlock PIN blob)
//
// This method is idempotent: it is safe to call on every startup and is a
// no-op when the files do not exist.
func (a *App) migratePINArtifacts() {
	if a.dataDir == "" {
		a.log.Debug("PIN migration skipped: data directory not initialized")
		return
	}

	removed := 0

	// 1. Remove <dataDir>/pin-state.json (CLI extension path).
	removed += a.removeLegacyFile(filepath.Join(a.dataDir, legacyPINStateFile))

	// 2. Remove <dataDir>/tpm/pin_state.json (GUI/TPM path).
	removed += a.removeLegacyFile(filepath.Join(a.dataDir, "tpm", legacyTPMPINStateFile))

	// 3. Remove sealed blobs with label "user_pin" via the SealService.
	removed += a.removeLegacyUserPINBlobs()

	if removed > 0 {
		a.log.Info("PIN migration complete", "artifacts_removed", removed)
	} else {
		a.log.Debug("PIN migration complete: no legacy artifacts found")
	}
}

// removeLegacyFile removes a single file at path. Returns 1 if the file was
// removed, 0 otherwise. Logs at info level on removal and debug level when
// the file does not exist.
func (a *App) removeLegacyFile(path string) int {
	err := os.Remove(path)
	if err == nil {
		a.log.Info("removed legacy PIN artifact", "path", path)
		return 1
	}
	if errors.Is(err, fs.ErrNotExist) {
		a.log.Debug("legacy PIN artifact not found", "path", path)
		return 0
	}
	a.log.Warn("failed to remove legacy PIN artifact", "path", path, "error", err)
	return 0
}

// removeLegacyUserPINBlobs lists all sealed blobs and deletes any with the
// legacy "user_pin" label. Returns the number of blobs removed.
func (a *App) removeLegacyUserPINBlobs() int {
	if a.sealService == nil {
		a.log.Debug("PIN migration: seal service not available, skipping user_pin blob cleanup")
		return 0
	}

	blobs, err := a.sealService.ListBlobs()
	if err != nil {
		a.log.Warn("PIN migration: failed to list sealed blobs", "error", err)
		return 0
	}

	removed := 0
	for _, blob := range blobs {
		if blob.Label != legacyUserPINLabel {
			continue
		}
		if delErr := a.sealService.DeleteBlob(blob.ID); delErr != nil {
			a.log.Warn("PIN migration: failed to delete user_pin blob",
				"id", blob.ID, "error", delErr)
			continue
		}
		a.log.Info("removed legacy user_pin sealed blob", "id", blob.ID)
		removed++
	}

	return removed
}
