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

package xkms

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// BackupServicer provides whole-node backup and restore operations. Backup
// state is owned entirely by the embedded go-qrdb node; xkms presents this
// API on top of the node's BackupClient and performs no local persistence,
// snapshot capture, checksum computation or encryption of its own
// (owner ruling 2026-09-30, go-xkms#728). On a standalone (non-raft) node the
// underlying qrdb service answers every call with its own typed
// unsupported-operation error, since shard snapshots require Raft-replicated
// state; xkms neither works around nor duplicates that restriction.
type BackupServicer interface {
	CreateBackup(ctx context.Context, req *transport.BackupRequest) (*transport.BackupInfo, error)
	ListBackups(ctx context.Context) ([]transport.BackupInfo, error)
	GetBackup(ctx context.Context, id string) (*transport.BackupInfo, error)
	DeleteBackup(ctx context.Context, id string) error
	RestoreBackup(ctx context.Context, req *transport.RestoreRequest) (*transport.RestoreResult, error)
	VerifyBackup(ctx context.Context, id string) (*transport.VerifyResult, error)
}

// CreateBackup initiates a new backup with the specified options. The
// transport request/response types are aliases of the qrdb transport types,
// so the call is a direct pass-through to the node's backup client.
func (s *XKMSService) CreateBackup(ctx context.Context, req *transport.BackupRequest) (*transport.BackupInfo, error) {
	backup := s.backup.load()
	if backup == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return backup.CreateBackup(ctx, req)
}

// ListBackups returns metadata for all available backups.
func (s *XKMSService) ListBackups(ctx context.Context) ([]transport.BackupInfo, error) {
	backup := s.backup.load()
	if backup == nil {
		return nil, ErrNotConfigured
	}
	return backup.ListBackups(ctx)
}

// GetBackup returns metadata for a specific backup by ID.
func (s *XKMSService) GetBackup(ctx context.Context, id string) (*transport.BackupInfo, error) {
	backup := s.backup.load()
	if backup == nil {
		return nil, ErrNotConfigured
	}
	return backup.GetBackup(ctx, id)
}

// DeleteBackup removes a backup by ID.
func (s *XKMSService) DeleteBackup(ctx context.Context, id string) error {
	backup := s.backup.load()
	if backup == nil {
		return ErrNotConfigured
	}
	return backup.DeleteBackup(ctx, id)
}

// RestoreBackup restores data from a backup, overwriting live shard state.
func (s *XKMSService) RestoreBackup(ctx context.Context, req *transport.RestoreRequest) (*transport.RestoreResult, error) {
	backup := s.backup.load()
	if backup == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return backup.RestoreBackup(ctx, req)
}

// VerifyBackup verifies the integrity of a backup by computing and comparing
// checksums.
func (s *XKMSService) VerifyBackup(ctx context.Context, id string) (*transport.VerifyResult, error) {
	backup := s.backup.load()
	if backup == nil {
		return nil, ErrNotConfigured
	}
	return backup.VerifyBackup(ctx, id)
}
