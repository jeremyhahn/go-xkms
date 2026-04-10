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
	"log/slog"
	"os"
	"sync"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// Share service errors.
var (
	ErrShareServiceNotReady = errors.New("share service not initialized")
	ErrShareStoreNil        = errors.New("share store is nil")
	ErrShareNotFound        = errors.New("share not found")
	ErrShareImportFailed    = errors.New("share import failed")
	ErrShareSubmitFailed    = errors.New("share submit failed")
	ErrShareReceiveFailed   = errors.New("share receive failed")
	ErrEmptyFilePath        = errors.New("file path is empty")
	ErrEmptyServerURL       = errors.New("server URL is empty")
	ErrEmptyGroupID         = errors.New("group ID is empty")
)

// ShareInfo is the frontend-visible share metadata (no raw share data exposed).
type ShareInfo struct {
	ServerURL  string `json:"server_url"`
	GroupID    string `json:"group_id"`
	GroupName  string `json:"group_name,omitempty"`
	ShareIndex int    `json:"share_index"`
	Purpose    string `json:"purpose,omitempty"`
	ReceivedAt string `json:"received_at"`
	TenantID   string `json:"tenant_id,omitempty"`
}

// ShareService manages Shamir secret shares for barrier unsealing ceremonies.
// It provides local share storage and server communication for receiving,
// importing, and submitting shares.
type ShareService struct {
	ctx     context.Context
	log     *slog.Logger
	mu      sync.RWMutex
	store   sharestore.ShareStore
	emitter func(events.Event)
}

// NewShareService creates a new ShareService.
func NewShareService() *ShareService {
	return &ShareService{
		log: slog.Default().With("component", "share_service"),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *ShareService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetEventEmitter sets the event callback for frontend notifications.
func (s *ShareService) SetEventEmitter(fn func(events.Event)) {
	s.emitter = fn
}

// SetShareStore sets the backing share store.
func (s *ShareService) SetShareStore(store sharestore.ShareStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = store
}

// ListShares returns metadata for all locally stored shares.
func (s *ShareService) ListShares() ([]ShareInfo, error) {
	s.mu.RLock()
	store := s.store
	s.mu.RUnlock()

	if store == nil {
		return nil, ErrShareStoreNil
	}

	entries, err := store.List(s.ctx)
	if err != nil {
		s.log.Error("failed to list shares", "error", err)
		return nil, err
	}

	infos := make([]ShareInfo, 0, len(entries))
	for _, e := range entries {
		infos = append(infos, entryToShareInfo(e))
	}
	return infos, nil
}

// ImportShare imports a share from a JSON file.
func (s *ShareService) ImportShare(filePath string) (*ShareInfo, error) {
	if filePath == "" {
		return nil, ErrEmptyFilePath
	}

	s.mu.RLock()
	store := s.store
	s.mu.RUnlock()

	if store == nil {
		return nil, ErrShareStoreNil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		s.log.Error("failed to read share file", "path", filePath, "error", err)
		return nil, ErrShareImportFailed
	}

	var entry sharestore.ShareEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		s.log.Error("failed to parse share file", "path", filePath, "error", err)
		return nil, ErrShareImportFailed
	}

	if err := entry.Validate(); err != nil {
		s.log.Error("share validation failed", "error", err)
		return nil, err
	}

	if err := store.Save(s.ctx, &entry); err != nil {
		s.log.Error("failed to save imported share", "error", err)
		return nil, err
	}

	info := entryToShareInfo(&entry)
	s.emit(events.EventShareImported, info)
	s.log.Info("share imported", "server", entry.ServerURL, "group", entry.GroupID)
	return &info, nil
}

// DeleteShare removes a locally stored share by server URL, group ID, and share index.
func (s *ShareService) DeleteShare(serverURL, groupID string, shareIndex int) error {
	if serverURL == "" {
		return ErrEmptyServerURL
	}
	if groupID == "" {
		return ErrEmptyGroupID
	}

	s.mu.RLock()
	store := s.store
	s.mu.RUnlock()

	if store == nil {
		return ErrShareStoreNil
	}

	if err := store.Delete(s.ctx, serverURL, groupID, shareIndex); err != nil {
		s.log.Error("failed to delete share", "server", serverURL, "group", groupID, "index", shareIndex, "error", err)
		return err
	}

	s.emit(events.EventShareDeleted, map[string]any{
		"server_url":  serverURL,
		"group_id":    groupID,
		"share_index": shareIndex,
	})
	s.log.Info("share deleted", "server", serverURL, "group", groupID, "index", shareIndex)
	return nil
}

// ReceiveShares polls a server for available shares and stores them locally.
func (s *ShareService) ReceiveShares(serverURL, spkiPin string) ([]ShareInfo, error) {
	if serverURL == "" {
		return nil, ErrEmptyServerURL
	}

	s.mu.RLock()
	store := s.store
	s.mu.RUnlock()

	if store == nil {
		return nil, ErrShareStoreNil
	}

	opts := []xkms.Option{
		xkms.WithProtocol(xkms.ProtocolREST),
		xkms.WithAddress(serverURL),
	}
	if spkiPin != "" {
		opts = append(opts, xkms.WithSPKIPin(spkiPin))
	}

	client, err := xkms.NewWithOptions(opts...)
	if err != nil {
		s.log.Error("failed to create SDK client", "server", serverURL, "error", err)
		return nil, ErrShareReceiveFailed
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		s.log.Error("failed to connect to server", "server", serverURL, "error", err)
		return nil, ErrShareReceiveFailed
	}
	defer client.Close()

	resp, err := client.ListShares(ctx)
	if err != nil {
		s.log.Error("failed to list shares from server", "server", serverURL, "error", err)
		return nil, ErrShareReceiveFailed
	}

	received := make([]ShareInfo, 0, len(resp.Shares))
	for _, si := range resp.Shares {
		entry := &sharestore.ShareEntry{
			ServerURL:  si.ServerURL,
			GroupID:    si.GroupID,
			GroupName:  si.GroupName,
			ShareIndex: si.ShareIndex,
			Purpose:    si.Purpose,
			ReceivedAt: si.ReceivedAt,
			TenantID:   si.TenantID,
		}
		if err := store.Save(ctx, entry); err != nil {
			if errors.Is(err, sharestore.ErrShareExists) {
				continue // already stored
			}
			s.log.Warn("failed to save received share", "group", si.GroupID, "error", err)
			continue
		}
		info := entryToShareInfo(entry)
		received = append(received, info)
		s.emit(events.EventShareReceived, info)
	}

	s.log.Info("shares received", "server", serverURL, "count", len(received))
	return received, nil
}

// SubmitShare submits a locally stored share to the server for barrier unsealing.
func (s *ShareService) SubmitShare(serverURL, groupID string, shareIndex int, spkiPin string) error {
	if serverURL == "" {
		return ErrEmptyServerURL
	}
	if groupID == "" {
		return ErrEmptyGroupID
	}

	s.mu.RLock()
	store := s.store
	s.mu.RUnlock()

	if store == nil {
		return ErrShareStoreNil
	}

	entry, err := store.Load(s.ctx, serverURL, groupID, shareIndex)
	if err != nil {
		s.log.Error("failed to load share", "server", serverURL, "group", groupID, "index", shareIndex, "error", err)
		return ErrShareNotFound
	}

	opts := []xkms.Option{
		xkms.WithProtocol(xkms.ProtocolREST),
		xkms.WithAddress(serverURL),
	}
	if spkiPin != "" {
		opts = append(opts, xkms.WithSPKIPin(spkiPin))
	}

	client, err := xkms.NewWithOptions(opts...)
	if err != nil {
		s.log.Error("failed to create SDK client", "server", serverURL, "error", err)
		return ErrShareSubmitFailed
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		s.log.Error("failed to connect to server", "server", serverURL, "error", err)
		return ErrShareSubmitFailed
	}
	defer client.Close()

	_, err = client.SubmitShare(ctx, &transport.SubmitShareRequest{
		GroupID:   groupID,
		ShareData: entry.ShareData,
	})
	if err != nil {
		s.log.Error("failed to submit share", "server", serverURL, "group", groupID, "error", err)
		return ErrShareSubmitFailed
	}

	s.emit(events.EventShareSubmitted, map[string]any{
		"server_url":  serverURL,
		"group_id":    groupID,
		"share_index": shareIndex,
	})
	s.log.Info("share submitted", "server", serverURL, "group", groupID, "index", shareIndex)
	return nil
}

// GetShareStatus returns the share collection status for a group on a server.
func (s *ShareService) GetShareStatus(serverURL, groupID, spkiPin string) (*transport.ShareCollectionStatus, error) {
	if serverURL == "" {
		return nil, ErrEmptyServerURL
	}
	if groupID == "" {
		return nil, ErrEmptyGroupID
	}

	opts := []xkms.Option{
		xkms.WithProtocol(xkms.ProtocolREST),
		xkms.WithAddress(serverURL),
	}
	if spkiPin != "" {
		opts = append(opts, xkms.WithSPKIPin(spkiPin))
	}

	client, err := xkms.NewWithOptions(opts...)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return nil, err
	}
	defer client.Close()

	return client.GetShareCollectionStatus(ctx, groupID)
}

// emit sends an event to the frontend if an emitter is registered.
func (s *ShareService) emit(eventType events.EventType, payload any) {
	if s.emitter != nil {
		s.emitter(events.Event{
			Type:    eventType,
			Payload: payload,
			Time:    time.Now(),
		})
	}
}

// entryToShareInfo converts a ShareEntry to frontend-safe ShareInfo.
func entryToShareInfo(e *sharestore.ShareEntry) ShareInfo {
	return ShareInfo{
		ServerURL:  e.ServerURL,
		GroupID:    e.GroupID,
		GroupName:  e.GroupName,
		ShareIndex: e.ShareIndex,
		Purpose:    e.Purpose,
		ReceivedAt: e.ReceivedAt.Format(time.RFC3339),
		TenantID:   e.TenantID,
	}
}
