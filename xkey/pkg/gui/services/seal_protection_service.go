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
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// SealProtectionStatus is the frontend-facing representation of the
// global sealed data lock state.
type SealProtectionStatus struct {
	IsLocked  bool `json:"is_locked"`
	BlobCount int  `json:"blob_count"`
}

// SealProtectionService provides sealed data status.
// Lock/unlock functionality has been removed; the global AppLockService
// now handles all UI-level access gating.
type SealProtectionService struct {
	ctx      context.Context
	log      *slog.Logger
	sealSvc  *SealService
	auditLog atomic.Pointer[audit.Logger]
}

// NewSealProtectionService creates a new SealProtectionService.
func NewSealProtectionService(sealSvc *SealService) *SealProtectionService {
	return &SealProtectionService{
		log:     slog.Default().With("component", "seal_protection"),
		sealSvc: sealSvc,
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *SealProtectionService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetAuditLogger sets the audit logger for security event logging.
func (s *SealProtectionService) SetAuditLogger(l audit.Logger) {
	s.auditLog.Store(&l)
}

// logSealProtectionEvent logs a seal protection audit event.
func (s *SealProtectionService) logSealProtectionEvent(op audit.OperationType, success bool, err error, details map[string]any) {
	if p := s.auditLog.Load(); p != nil {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		(*p).Log(audit.Entry{
			Timestamp: time.Now(),
			Operation: op,
			Success:   success,
			Error:     errStr,
			Details:   details,
		})
	}
}

// GetStatus returns the current seal protection status.
// IsLocked is always false; the AppLockService handles access gating.
func (s *SealProtectionService) GetStatus() (*SealProtectionStatus, error) {
	blobCount := 0
	if s.sealSvc != nil {
		blobs, err := s.sealSvc.ListBlobs()
		if err == nil {
			blobCount = len(blobs)
		}
	}
	return &SealProtectionStatus{
		IsLocked:  false,
		BlobCount: blobCount,
	}, nil
}
