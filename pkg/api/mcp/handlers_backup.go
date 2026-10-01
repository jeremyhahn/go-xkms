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

package mcp

import (
	"context"
	"errors"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// backupIDParams selects a backup by ID.
type backupIDParams struct {
	ID string `json:"id"`
}

// backupID decodes and validates a backupIDParams from req.
func backupID(req *JSONRPCRequest) (string, error) {
	var params backupIDParams
	if err := decodeParams(req, &params); err != nil {
		return "", err
	}
	if params.ID == "" {
		return "", &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "id is required"}}
	}
	return params.ID, nil
}

// handleCreateBackup handles the xkms.createBackup method: initiates a new
// whole-node backup over the embedded go-qrdb node's shard-snapshot
// capability (go-xkms#728). Delegates entirely to the xkms service layer.
func (s *Server) handleCreateBackup(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.BackupRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Destination == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "destination is required"}}
	}

	resp, err := s.xkmsService.CreateBackup(ctx, &params)
	if err != nil {
		return nil, mapBackupError(err, "create backup")
	}
	return resp, nil
}

// handleListBackups handles the xkms.listBackups method: returns metadata
// for every available backup. Takes no params.
func (s *Server) handleListBackups(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	backups, err := s.xkmsService.ListBackups(ctx)
	if err != nil {
		return nil, mapBackupError(err, "list backups")
	}
	return transport.ListBackupsResponse{Backups: backups}, nil
}

// handleGetBackup handles the xkms.getBackup method: retrieves a single
// backup's metadata by ID.
func (s *Server) handleGetBackup(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	id, err := backupID(req)
	if err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.GetBackup(ctx, id)
	if err != nil {
		return nil, mapBackupError(err, "get backup")
	}
	return resp, nil
}

// handleDeleteBackup handles the xkms.deleteBackup method: removes a backup
// by ID.
func (s *Server) handleDeleteBackup(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	id, err := backupID(req)
	if err != nil {
		return nil, err
	}
	if err := s.xkmsService.DeleteBackup(ctx, id); err != nil {
		return nil, mapBackupError(err, "delete backup")
	}
	return map[string]interface{}{"success": true}, nil
}

// handleRestoreBackup handles the xkms.restoreBackup method: restores data
// from a backup, overwriting live shard state. Gated by backup:restore,
// distinct from backup:create/backup:read, because it is the most
// destructive backup operation.
func (s *Server) handleRestoreBackup(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.RestoreRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.BackupID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "backup_id is required"}}
	}

	resp, err := s.xkmsService.RestoreBackup(ctx, &params)
	if err != nil {
		return nil, mapBackupError(err, "restore backup")
	}
	return resp, nil
}

// handleVerifyBackup handles the xkms.verifyBackup method: verifies the
// integrity of a backup by computing and comparing checksums.
func (s *Server) handleVerifyBackup(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	id, err := backupID(req)
	if err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.VerifyBackup(ctx, id)
	if err != nil {
		return nil, mapBackupError(err, "verify backup")
	}
	return resp, nil
}

// mapBackupError converts an error returned by the xkms service layer's
// backup operations into a *KeyOpError, mirroring
// pkg/api/grpc/service_backup.go's mapBackupError.
func mapBackupError(err error, operation string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, xkms.ErrNotConfigured) {
		return &KeyOpError{Code: ErrCodeServiceUnavailable, Err: &errs.Wrapped{Msg: operation, Err: err}}
	}
	if errors.Is(err, xkms.ErrNilRequest) {
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Wrapped{Msg: operation, Err: err}}
	}

	var notFound *qrdbtransport.BackupNotFoundError
	if errors.As(err, &notFound) {
		return &KeyOpError{Code: sdkssh.JSONRPCCodeNotFound, Err: &errs.Wrapped{Msg: operation, Err: err}}
	}

	var emptyDest *qrdbtransport.BackupEmptyDestinationError
	var emptyID *qrdbtransport.BackupEmptyIDError
	if errors.As(err, &emptyDest) || errors.As(err, &emptyID) {
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Wrapped{Msg: operation, Err: err}}
	}

	var checksumMismatch *qrdbtransport.BackupChecksumMismatchError
	if errors.As(err, &checksumMismatch) {
		return &KeyOpError{Code: ErrCodeInternalError, Err: &errs.Wrapped{Msg: operation, Err: err}}
	}

	return &KeyOpError{Code: ErrCodeInternalError, Err: &errs.Wrapped{Msg: operation, Err: err}}
}
