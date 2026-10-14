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

package services

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sealedRecords returns a well-formed sealed blob record and one with no
// backend ID, which cannot be unsealed and so must never be listed.
func sealedRecords(t *testing.T) map[string][]byte {
	t.Helper()
	records := map[string][]byte{}
	for id, backendID := range map[string]string{"good": "software", "orphan": ""} {
		data, err := json.Marshal(sealedBlobStorage{
			ID:        id,
			Label:     id + " secret",
			BackendID: backendID,
			CreatedAt: time.Now(),
		})
		require.NoError(t, err)
		records[id] = data
	}
	return records
}

func TestSealService_ListBlobsSkipsRecordsWithoutBackendID(t *testing.T) {
	t.Run("storage directory", func(t *testing.T) {
		dir := t.TempDir()
		for id, data := range sealedRecords(t) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, id+".json"), data, 0o600))
		}
		svc := NewSealService(dir)

		entries, err := svc.ListBlobs()
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "good", entries[0].ID)
	})

	t.Run("storage backend", func(t *testing.T) {
		backend := xkms.NewStorageMemory()
		for id, data := range sealedRecords(t) {
			require.NoError(t, backend.Put(context.Background(), "sealed/"+id, data))
		}
		svc := NewSealService(t.TempDir())
		svc.SetBackend(backend, "sealed/")

		entries, err := svc.ListBlobs()
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "good", entries[0].ID)
	})
}

// TestSealService_PolicyDenialReportsAuditFailure checks that a denied
// operation whose audit record cannot be written reports both failures.
func TestSealService_PolicyDenialReportsAuditFailure(t *testing.T) {
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "kept.json")
	require.NoError(t, os.WriteFile(blobPath, sealedRecords(t)["good"], 0o600))

	svc := NewSealService(dir)
	svc.SetPolicy(&config.PolicySection{UserCanManageSealedData: false})
	auditErr := errors.New("audit log unavailable")
	svc.SetAuditLogger(&failingBarrierAuditLogger{err: auditErr})

	err := svc.DeleteBlob("kept")
	var denied *PolicyDeniedError
	assert.ErrorAs(t, err, &denied)
	assert.ErrorIs(t, err, auditErr)
	assert.FileExists(t, blobPath, "a denied delete must leave the blob in place")
}
