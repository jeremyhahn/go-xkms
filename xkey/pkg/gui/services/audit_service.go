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
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// Audit service errors.
var (
	ErrAuditInvalidFormat = errors.New("audit_service: invalid export format")
	ErrAuditNoEntries     = errors.New("audit_service: no entries found")
)

// AuditFilter describes query parameters for filtering audit entries.
type AuditFilter struct {
	Operation string    `json:"operation,omitempty"`
	Backend   string    `json:"backend,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	DeviceID  string    `json:"device_id,omitempty"`
	Success   *bool     `json:"success,omitempty"`
	Since     time.Time `json:"since,omitempty"`
	Until     time.Time `json:"until,omitempty"`
	Limit     int       `json:"limit,omitempty"`
	Offset    int       `json:"offset,omitempty"`
}

// AuditEntry represents a single audit log entry for the frontend.
type AuditEntry struct {
	Timestamp  time.Time      `json:"timestamp"`
	Operation  string         `json:"operation"`
	Backend    string         `json:"backend"`
	KeyID      string         `json:"key_id"`
	DeviceID   string         `json:"device_id"`
	DeviceName string         `json:"device_name"`
	Success    bool           `json:"success"`
	Error      string         `json:"error,omitempty"`
	DurationMs int64          `json:"duration_ms"`
	Details    map[string]any `json:"details,omitempty"`
}

// validExportFormats defines the set of recognized export formats.
var validExportFormats = map[string]struct{}{
	"json": {},
	"csv":  {},
}

// AuditService exposes audit log operations to the frontend.
type AuditService struct {
	ctx   context.Context
	store audit.Store

	// policy is the enterprise policy section whose UserCanViewAuditLog
	// field gates GetEntries and ExportEntries. nil in personal mode.
	// See SetPolicy.
	policy atomic.Pointer[config.PolicySection]
}

// NewAuditService creates a new AuditService.
func NewAuditService(store audit.Store) *AuditService {
	return &AuditService{
		store: store,
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *AuditService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetPolicy installs the enterprise policy section that gates GetEntries
// and ExportEntries. The GUI calls this with config.DefaultPolicy() before
// SO login and the verified section afterward; see startupEnterprisePolicy
// and applyVerifiedEnterprisePolicy in pkg/gui/enterprise_policy.go.
func (s *AuditService) SetPolicy(pol *config.PolicySection) {
	s.policy.Store(pol)
}

// requireViewAuditLog returns a *PolicyDeniedError, and logs it to the
// audit store itself (audit.Store embeds Logger), if enterprise policy's
// UserCanViewAuditLog is false.
func (s *AuditService) requireViewAuditLog(operation string) error {
	pol := s.policy.Load()
	if pol == nil || pol.UserCanViewAuditLog {
		return nil
	}
	err := &PolicyDeniedError{Field: "user_can_view_audit_log"}
	if s.store != nil {
		s.store.Log(audit.Entry{
			Timestamp: time.Now(),
			Operation: audit.OpPolicyDenied,
			Success:   false,
			Error:     err.Error(),
			Details:   map[string]any{"operation": operation},
		})
	}
	return err
}

// GetEntries returns audit log entries matching the filter.
func (s *AuditService) GetEntries(filter *AuditFilter) ([]AuditEntry, error) {
	if err := s.requireViewAuditLog("get_entries"); err != nil {
		return nil, err
	}
	if s.store == nil {
		return []AuditEntry{}, nil
	}

	var qf audit.QueryFilter
	if filter != nil {
		qf = audit.QueryFilter{
			Backend:  filter.Backend,
			KeyID:    filter.KeyID,
			DeviceID: filter.DeviceID,
			Success:  filter.Success,
			Since:    filter.Since,
			Until:    filter.Until,
			Limit:    filter.Limit,
			Offset:   filter.Offset,
		}
		if filter.Operation != "" {
			qf.Operation = audit.OperationType(filter.Operation)
		}
	}

	entries := s.store.Query(qf)
	result := make([]AuditEntry, len(entries))
	for i, e := range entries {
		result[i] = AuditEntry{
			Timestamp:  e.Timestamp,
			Operation:  string(e.Operation),
			Backend:    e.Backend,
			KeyID:      e.KeyID,
			DeviceID:   e.DeviceID,
			DeviceName: e.DeviceName,
			Success:    e.Success,
			Error:      e.Error,
			DurationMs: e.DurationMs,
			Details:    e.Details,
		}
	}
	return result, nil
}

// ExportEntries exports audit entries in the specified format.
// Supported formats: "json", "csv"; any other format is rejected with
// ErrAuditInvalidFormat. The entries are read from the audit store using the
// same filter semantics as GetEntries, and an empty result is reported as
// ErrAuditNoEntries rather than an empty document.
func (s *AuditService) ExportEntries(format string, filter *AuditFilter) ([]byte, error) {
	if _, ok := validExportFormats[format]; !ok {
		return nil, ErrAuditInvalidFormat
	}

	entries, err := s.GetEntries(filter)
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, ErrAuditNoEntries
	}

	switch format {
	case "json":
		return json.MarshalIndent(entries, "", "  ")
	case "csv":
		return s.exportCSV(entries)
	default:
		return nil, ErrAuditInvalidFormat
	}
}

// exportCSV renders audit entries as CSV bytes.
func (s *AuditService) exportCSV(entries []AuditEntry) ([]byte, error) {
	header := "timestamp,operation,backend,key_id,device_id,device_name,success,error,duration_ms\n"
	buf := []byte(header)
	for _, e := range entries {
		line := e.Timestamp.Format(time.RFC3339) + "," +
			e.Operation + "," +
			e.Backend + "," +
			e.KeyID + "," +
			e.DeviceID + "," +
			e.DeviceName + "," +
			boolToStr(e.Success) + "," +
			e.Error + "," +
			int64ToStr(e.DurationMs) + "\n"
		buf = append(buf, line...)
	}
	return buf, nil
}

func boolToStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func int64ToStr(n int64) string {
	return json.Number(intToStr(n)).String()
}

func intToStr(n int64) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 20)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	if neg {
		buf = append(buf, '-')
	}
	// Reverse.
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
