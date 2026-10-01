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

package rest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Backup handler typed errors.
var (
	ErrBackupNotConfigured = errors.New("rest: backup service not configured")
	ErrMissingBackupID     = errors.New("rest: missing backup id")
	ErrMissingDestination  = errors.New("rest: missing backup destination")
)

// createBackupRequest is the REST request body for creating a backup.
type createBackupRequest struct {
	Destination   string                    `json:"destination"`
	Compression   transport.CompressionType `json:"compression,omitempty"`
	Encryption    transport.EncryptionType  `json:"encryption,omitempty"`
	EncryptionKey []byte                    `json:"encryption_key,omitempty"`
	Metadata      map[string]string         `json:"metadata,omitempty"`
	ShardIDs      []uint64                  `json:"shard_ids,omitempty"`
}

// restoreBackupRequest is the REST request body for restoring from a backup.
type restoreBackupRequest struct {
	BackupID      string   `json:"backup_id"`
	TargetShards  []uint64 `json:"target_shards,omitempty"`
	ValidateFirst bool     `json:"validate_first,omitempty"`
	DecryptionKey []byte   `json:"decryption_key,omitempty"`
}

// listBackupsResponse wraps the backups list for the SDK contract.
type listBackupsResponse struct {
	Backups []transport.BackupInfo `json:"backups"`
}

// CreateBackupHandler handles POST /api/v1/backups requests. It initiates a
// new whole-node backup over the embedded go-qrdb node's shard-snapshot
// capability; see docs/backup for the standalone-vs-raft availability
// distinction.
func (h *HandlerContext) CreateBackupHandler(w http.ResponseWriter, r *http.Request) {
	var req createBackupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	if req.Destination == "" {
		writeError(w, ErrMissingDestination, http.StatusBadRequest)
		return
	}

	resp, err := h.xkmsService.CreateBackup(r.Context(), &transport.BackupRequest{
		Destination:   req.Destination,
		Compression:   req.Compression,
		Encryption:    req.Encryption,
		EncryptionKey: req.EncryptionKey,
		Metadata:      req.Metadata,
		ShardIDs:      req.ShardIDs,
	})
	if err != nil {
		handleBackupError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusCreated)
}

// ListBackupsHandler handles GET /api/v1/backups requests.
func (h *HandlerContext) ListBackupsHandler(w http.ResponseWriter, r *http.Request) {
	backups, err := h.xkmsService.ListBackups(r.Context())
	if err != nil {
		handleBackupError(w, err)
		return
	}
	writeJSON(w, listBackupsResponse{Backups: backups}, http.StatusOK)
}

// GetBackupHandler handles GET /api/v1/backups/{id} requests.
func (h *HandlerContext) GetBackupHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, ErrMissingBackupID, http.StatusBadRequest)
		return
	}
	resp, err := h.xkmsService.GetBackup(r.Context(), id)
	if err != nil {
		handleBackupError(w, err)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}

// DeleteBackupHandler handles DELETE /api/v1/backups/{id} requests.
func (h *HandlerContext) DeleteBackupHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, ErrMissingBackupID, http.StatusBadRequest)
		return
	}
	if err := h.xkmsService.DeleteBackup(r.Context(), id); err != nil {
		handleBackupError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RestoreBackupHandler handles POST /api/v1/backups/restore requests. This is
// the most destructive backup operation: it overwrites live shard state,
// which is why it is gated by backup:restore rather than backup:create.
func (h *HandlerContext) RestoreBackupHandler(w http.ResponseWriter, r *http.Request) {
	var req restoreBackupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	if req.BackupID == "" {
		writeError(w, ErrMissingBackupID, http.StatusBadRequest)
		return
	}

	resp, err := h.xkmsService.RestoreBackup(r.Context(), &transport.RestoreRequest{
		BackupID:      req.BackupID,
		TargetShards:  req.TargetShards,
		ValidateFirst: req.ValidateFirst,
		DecryptionKey: req.DecryptionKey,
	})
	if err != nil {
		handleBackupError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// VerifyBackupHandler handles POST /api/v1/backups/{id}/verify requests.
func (h *HandlerContext) VerifyBackupHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, ErrMissingBackupID, http.StatusBadRequest)
		return
	}
	resp, err := h.xkmsService.VerifyBackup(r.Context(), id)
	if err != nil {
		handleBackupError(w, err)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}

// handleBackupError maps backup domain errors (surfaced by the go-qrdb
// node's backup client) to HTTP status codes and writes the error response.
func handleBackupError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, xkms.ErrNotConfigured):
		writeError(w, ErrBackupNotConfigured, http.StatusServiceUnavailable)
	case errors.Is(err, xkms.ErrNilRequest):
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
	case isBackupNotFound(err):
		writeError(w, err, http.StatusNotFound)
	case isBackupEmptyField(err):
		writeError(w, err, http.StatusBadRequest)
	case isBackupChecksumMismatch(err):
		writeError(w, err, http.StatusConflict)
	default:
		// An unexpected error from the backup subsystem must never be
		// silently collapsed into a bare 500 -- log the underlying cause for
		// diagnosis.
		slog.Default().Error("backup operation failed", "error", err)
		writeError(w, err, http.StatusInternalServerError)
	}
}

func isBackupNotFound(err error) bool {
	var e *qrdbtransport.BackupNotFoundError
	return errors.As(err, &e)
}

func isBackupEmptyField(err error) bool {
	var dest *qrdbtransport.BackupEmptyDestinationError
	var id *qrdbtransport.BackupEmptyIDError
	return errors.As(err, &dest) || errors.As(err, &id)
}

func isBackupChecksumMismatch(err error) bool {
	var e *qrdbtransport.BackupChecksumMismatchError
	return errors.As(err, &e)
}
