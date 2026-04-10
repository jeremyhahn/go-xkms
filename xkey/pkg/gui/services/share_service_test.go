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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

func TestNewShareService(t *testing.T) {
	svc := NewShareService()
	require.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

func TestShareService_ListShares_Empty(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(sharestore.NewMemoryShareStore())

	infos, err := svc.ListShares()
	require.NoError(t, err)
	assert.NotNil(t, infos)
	assert.Empty(t, infos)
}

func TestShareService_ListShares_NilStore(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())

	infos, err := svc.ListShares()
	assert.Nil(t, infos)
	require.ErrorIs(t, err, ErrShareStoreNil)
}

func TestShareService_ImportShare_Success(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	store := sharestore.NewMemoryShareStore()
	svc.SetShareStore(store)

	entry := sharestore.ShareEntry{
		ServerURL:  "https://xkms.example.com",
		GroupID:    "group-1",
		GroupName:  "Test Group",
		ShareIndex: 1,
		ShareData:  []byte("secret-share-data"),
		Purpose:    "barrier",
		ReceivedAt: time.Now().UTC(),
		TenantID:   "tenant-a",
	}
	data, err := json.Marshal(entry)
	require.NoError(t, err)

	tmpFile, err := os.CreateTemp(t.TempDir(), "share-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(data)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	info, err := svc.ImportShare(tmpFile.Name())
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "https://xkms.example.com", info.ServerURL)
	assert.Equal(t, "group-1", info.GroupID)
	assert.Equal(t, "Test Group", info.GroupName)
	assert.Equal(t, 1, info.ShareIndex)
	assert.Equal(t, "barrier", info.Purpose)
	assert.Equal(t, "tenant-a", info.TenantID)

	// Verify it was persisted.
	loaded, err := store.Load(context.Background(), "https://xkms.example.com", "group-1", 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret-share-data"), loaded.ShareData)
}

func TestShareService_ImportShare_EmptyPath(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(sharestore.NewMemoryShareStore())

	info, err := svc.ImportShare("")
	assert.Nil(t, info)
	require.ErrorIs(t, err, ErrEmptyFilePath)
}

func TestShareService_ImportShare_NilStore(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())

	info, err := svc.ImportShare("/tmp/nonexistent.json")
	assert.Nil(t, info)
	require.ErrorIs(t, err, ErrShareStoreNil)
}

func TestShareService_ImportShare_InvalidJSON(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(sharestore.NewMemoryShareStore())

	tmpFile, err := os.CreateTemp(t.TempDir(), "bad-share-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("{invalid json content")
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	info, err := svc.ImportShare(tmpFile.Name())
	assert.Nil(t, info)
	require.ErrorIs(t, err, ErrShareImportFailed)
}

func TestShareService_ImportShare_InvalidEntry(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(sharestore.NewMemoryShareStore())

	// Missing ServerURL causes validation failure.
	entry := sharestore.ShareEntry{
		GroupID:    "group-1",
		ShareData:  []byte("data"),
		ReceivedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(entry)
	require.NoError(t, err)

	tmpFile, err := os.CreateTemp(t.TempDir(), "invalid-entry-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(data)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	info, err := svc.ImportShare(tmpFile.Name())
	assert.Nil(t, info)
	require.Error(t, err)
	require.ErrorIs(t, err, sharestore.ErrInvalidServerURL)
}

func TestShareService_DeleteShare_Success(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	store := sharestore.NewMemoryShareStore()
	svc.SetShareStore(store)

	// Import a share first.
	entry := sharestore.ShareEntry{
		ServerURL:  "https://xkms.example.com",
		GroupID:    "group-del",
		ShareIndex: 1,
		ShareData:  []byte("delete-me"),
		ReceivedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(entry)
	require.NoError(t, err)

	tmpFile, err := os.CreateTemp(t.TempDir(), "del-share-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(data)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	_, err = svc.ImportShare(tmpFile.Name())
	require.NoError(t, err)

	// Verify it exists.
	infos, err := svc.ListShares()
	require.NoError(t, err)
	require.Len(t, infos, 1)

	// Delete it.
	err = svc.DeleteShare("https://xkms.example.com", "group-del", 1)
	require.NoError(t, err)

	// Verify list is empty.
	infos, err = svc.ListShares()
	require.NoError(t, err)
	assert.Empty(t, infos)
}

func TestShareService_DeleteShare_EmptyServerURL(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(sharestore.NewMemoryShareStore())

	err := svc.DeleteShare("", "group-1", 1)
	require.ErrorIs(t, err, ErrEmptyServerURL)
}

func TestShareService_DeleteShare_EmptyGroupID(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(sharestore.NewMemoryShareStore())

	err := svc.DeleteShare("https://xkms.example.com", "", 1)
	require.ErrorIs(t, err, ErrEmptyGroupID)
}

func TestShareService_DeleteShare_NilStore(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())

	err := svc.DeleteShare("https://xkms.example.com", "group-1", 1)
	require.ErrorIs(t, err, ErrShareStoreNil)
}

func TestShareService_EventEmission(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(sharestore.NewMemoryShareStore())

	var mu sync.Mutex
	var captured []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		mu.Lock()
		defer mu.Unlock()
		captured = append(captured, e)
	})

	entry := sharestore.ShareEntry{
		ServerURL:  "https://xkms.example.com",
		GroupID:    "group-ev",
		ShareIndex: 1,
		ShareData:  []byte("event-data"),
		ReceivedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(entry)
	require.NoError(t, err)

	tmpFile, err := os.CreateTemp(t.TempDir(), "event-share-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(data)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	_, err = svc.ImportShare(tmpFile.Name())
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, captured, 1)
	assert.Equal(t, events.EventShareImported, captured[0].Type)
	assert.NotZero(t, captured[0].Time)

	payload, ok := captured[0].Payload.(ShareInfo)
	require.True(t, ok)
	assert.Equal(t, "https://xkms.example.com", payload.ServerURL)
	assert.Equal(t, "group-ev", payload.GroupID)
}

func TestShareService_EntryToShareInfo(t *testing.T) {
	now := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	entry := &sharestore.ShareEntry{
		ServerURL:  "https://xkms.example.com",
		GroupID:    "group-42",
		GroupName:  "Admins",
		ShareIndex: 3,
		ShareData:  []byte("raw-bytes"),
		Purpose:    "backup",
		ReceivedAt: now,
		TenantID:   "tenant-z",
	}

	info := entryToShareInfo(entry)

	assert.Equal(t, "https://xkms.example.com", info.ServerURL)
	assert.Equal(t, "group-42", info.GroupID)
	assert.Equal(t, "Admins", info.GroupName)
	assert.Equal(t, 3, info.ShareIndex)
	assert.Equal(t, "backup", info.Purpose)
	assert.Equal(t, "tenant-z", info.TenantID)
	assert.Equal(t, "2025-06-15T10:30:00Z", info.ReceivedAt)
}
