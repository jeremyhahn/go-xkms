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
	"errors"
	"path/filepath"

	"github.com/spf13/cobra"

	xkeysync "github.com/jeremyhahn/go-xkms/xkey/pkg/sync"
)

// Not ble-gated: neither the sync service opener nor its error touches
// Bluetooth. They used to live in device_sync.go, a ble-tagged file, because
// their only caller was "xkey device sync" (which does dial a paired phone
// over BLE). go-xkms#1306 adds a second caller, `xkey device relay`'s
// bridge-building (device_listen_handler.go, no ble tag required), so the
// pieces those two callers actually share move out from behind the tag that
// only ever applied to one of them.

// ErrDeviceSyncFailed indicates a phone sync operation failed.
var ErrDeviceSyncFailed = errors.New("device: sync operation failed")

// syncStateFile is the name of the sync state file kept in the data directory.
const syncStateFile = "sync-state.json"

// openSyncService opens every local store and wires it into a sync service.
// The caller owns the returned sources and must close them.
func openSyncService(cmd *cobra.Command) (*xkeysync.Service, *backupSources, error) {
	dataDir, err := backupDataDir()
	if err != nil {
		return nil, nil, err
	}

	// Sync merges in both directions, so a local store that has never been
	// written to is a normal starting point, not a missing source: strict
	// existence checking is for the read-only backup commands.
	sources, err := resolveBackupSources(cmd, backupStorePaths{}, false)
	if err != nil {
		return nil, nil, err
	}

	svc, err := xkeysync.NewService(&xkeysync.Config{
		DeviceName:    getHostname(),
		StateFilePath: filepath.Join(dataDir, syncStateFile),
	}, sources.syncOptions()...)
	if err != nil {
		sources.Close()
		return nil, nil, &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}

	return svc, sources, nil
}
