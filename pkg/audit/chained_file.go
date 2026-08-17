// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package audit

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ChainedFileLogger writes audit events to qrdb's tamper-evident chained
// file log. It is the fallback sink for deployments WITHOUT a qrdb client
// (non-qrdb storage backends), so audit never silently disappears: the
// record shape is identical to the qrdb-hosted chain (toTransportEvent —
// the same mapping QRDBLogger uses), only the storage location differs.
type ChainedFileLogger struct {
	sink qrdbsdk.NodeAuditLogger
}

// NewChainedFileLogger opens (or continues) the chained audit log at path.
func NewChainedFileLogger(path string) (*ChainedFileLogger, error) {
	sink, err := qrdbsdk.NewAuditFileLogger(path)
	if err != nil {
		return nil, &ChainedFileError{Path: path, Err: err}
	}
	return &ChainedFileLogger{sink: sink}, nil
}

// Log converts the xkms Event to the canonical audit record and emits it
// onto the chain. Emission is best-effort by the sink's contract and never
// blocks the audited operation.
func (l *ChainedFileLogger) Log(ctx context.Context, event *Event) error {
	if event == nil {
		return ErrNilEvent
	}
	tev := toTransportEvent(ctx, event)
	l.sink.Emit(ctx, qrdbsdk.NodeAuditEvent{
		Timestamp:  tev.Timestamp,
		Actor:      tev.Actor,
		TenantID:   tev.TenantID,
		Role:       tev.Role,
		Resource:   tev.Resource,
		Action:     tev.Action,
		Outcome:    tev.Outcome,
		Attributes: tev.Attributes,
		ClientIP:   tev.ClientIP,
	})
	return nil
}

// Close closes the underlying chained file.
func (l *ChainedFileLogger) Close() error {
	return l.sink.Close()
}

// Compile-time interface compliance check.
var _ Logger = (*ChainedFileLogger)(nil)

// ChainedFileError reports a chained-file audit sink failure.
type ChainedFileError struct {
	// Path is the audit log path.
	Path string
	// Err is the underlying error.
	Err error
}

// Error describes the failure.
func (e *ChainedFileError) Error() string {
	return "audit: chained file logger at " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ChainedFileError) Unwrap() error { return e.Err }
