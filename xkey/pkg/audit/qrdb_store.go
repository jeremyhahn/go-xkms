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

package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// qrdbActor is the actor xkey's own audit events carry: the desktop records
// the operations of its local user, not of a remote identity.
const qrdbActor = "xkey"

// Attribute keys that carry the xkey Entry fields the go-qrdb record has no
// column for.
const (
	attrBackend    = "backend"
	attrKeyID      = "key_id"
	attrDeviceID   = "device_id"
	attrDeviceName = "device_name"
	attrError      = "error"
	attrDurationMs = "duration_ms"
	attrDetails    = "details"
)

// qrdbQueryPageSize is the page size QRDBStore asks the sink for (the go-qrdb
// maximum).
const qrdbQueryPageSize = 1000

// ErrNilQRDBSink is returned by NewQRDBStore without a go-qrdb sink.
var ErrNilQRDBSink = errors.New("audit: go-qrdb audit sink is nil")

// QRDBStore is the xkey audit Store over go-qrdb's audit store: every entry
// is written to a go-qrdb node audit sink through go-xkms sdk/go, and Query
// reads it back from that sink. xkey keeps no audit storage of its own.
type QRDBStore struct {
	mu   sync.RWMutex
	sink xkms.QRDBNodeAuditLogger
}

var _ Store = (*QRDBStore)(nil)

// NewQRDBStore returns a Store that writes to and queries sink.
func NewQRDBStore(sink xkms.QRDBNodeAuditLogger) (*QRDBStore, error) {
	if sink == nil {
		return nil, ErrNilQRDBSink
	}
	return &QRDBStore{sink: sink}, nil
}

// MoveTo replays every event of the current sink into next, closes the
// current sink and writes to next from then on. The desktop starts on a
// go-qrdb ring buffer and moves to the go-qrdb file sink in its data
// directory once that directory is open. On a replay error the store keeps
// its current sink.
func (s *QRDBStore) MoveTo(next xkms.QRDBNodeAuditLogger) error {
	if next == nil {
		return ErrNilQRDBSink
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := context.Background()
	qf := xkms.QRDBNodeAuditFilter{Limit: qrdbQueryPageSize}
	for {
		page, err := s.sink.Query(ctx, qf)
		if err != nil {
			return fmt.Errorf("audit: read go-qrdb sink: %w", err)
		}
		if page == nil {
			break
		}
		for i := range page.Events {
			if err := next.Emit(ctx, page.Events[i]); err != nil {
				return fmt.Errorf("audit: replay into go-qrdb sink: %w", err)
			}
		}
		if page.Next == "" {
			break
		}
		qf.Cursor = page.Next
	}
	old := s.sink
	s.sink = next
	return old.Close()
}

// SealedAtRest reports whether the store writes to a BarrierSink, so its
// records are persisted under the barrier key.
func (s *QRDBStore) SealedAtRest() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.sink.(*BarrierSink)
	return ok
}

// VerifyChain verifies the hash chain of the persisted records, or returns
// ErrChainUnsupported while the sink keeps none.
func (s *QRDBStore) VerifyChain(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.sink.(interface{ VerifyChain(context.Context) error })
	if !ok {
		return ErrChainUnsupported
	}
	return v.VerifyChain(ctx)
}

// Close closes the go-qrdb sink.
func (s *QRDBStore) Close() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sink.Close()
}

// Log writes entry to the go-qrdb sink under the go-xkms write-failure
// policy: a security event the sink did not record is returned as
// *ErrAuditWriteFailed so the caller fails the operation it audits; an
// informational one is logged and dropped.
func (s *QRDBStore) Log(entry Entry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	s.mu.RLock()
	writeErr := s.sink.Emit(context.Background(), entryToQRDBEvent(entry))
	s.mu.RUnlock()
	return handleWriteFailure(slog.Default(), entry.Operation, writeErr)
}

// LogKeyOperation logs a key lifecycle operation.
func (s *QRDBStore) LogKeyOperation(op OperationType, backend, keyID string, success bool, err error, durationMs int64) error {
	return s.Log(Entry{Operation: op, Backend: backend, KeyID: keyID, Success: success, Error: errString(err), DurationMs: durationMs})
}

// LogCryptoOperation logs a cryptographic operation.
func (s *QRDBStore) LogCryptoOperation(op OperationType, backend, keyID, deviceID, deviceName string, success bool, err error, durationMs int64) error {
	return s.Log(Entry{Operation: op, Backend: backend, KeyID: keyID, DeviceID: deviceID, DeviceName: deviceName, Success: success, Error: errString(err), DurationMs: durationMs})
}

// LogConnectionEvent logs a connection event.
func (s *QRDBStore) LogConnectionEvent(op OperationType, deviceID, deviceName string, details map[string]any) error {
	return s.Log(Entry{Operation: op, DeviceID: deviceID, DeviceName: deviceName, Success: true, Details: details})
}

// LogServiceEvent logs a service lifecycle event.
func (s *QRDBStore) LogServiceEvent(op OperationType, details map[string]any) error {
	return s.Log(Entry{Operation: op, Success: true, Details: details})
}

// LogPINOperation logs a PIN operation.
func (s *QRDBStore) LogPINOperation(op OperationType, backend string, success bool, err error, details map[string]any) error {
	return s.Log(Entry{Operation: op, Backend: backend, Success: success, Error: errString(err), Details: details})
}

// LogTPMOperation logs a TPM operation.
func (s *QRDBStore) LogTPMOperation(op OperationType, success bool, err error, details map[string]any) error {
	return s.Log(Entry{Operation: op, Backend: "tpm2", Success: success, Error: errString(err), Details: details})
}

// LogPasswordStoreOperation logs a password store operation.
func (s *QRDBStore) LogPasswordStoreOperation(op OperationType, source string, success bool, err error, details map[string]any) error {
	return s.Log(Entry{Operation: op, Success: success, Error: errString(err), Details: withSource(details, source)})
}

// LogUserPresenceEvent logs a user presence event.
func (s *QRDBStore) LogUserPresenceEvent(op OperationType, source string, success bool, details map[string]any) error {
	return s.Log(Entry{Operation: op, Success: success, Details: withSource(details, source)})
}

// Query returns the entries matching filter, oldest first, read from the
// go-qrdb sink. A sink query error ends the read with what was matched.
func (s *QRDBStore) Query(filter QueryFilter) []Entry {
	qf := xkms.QRDBNodeAuditFilter{
		From:   filter.Since,
		Action: string(filter.Operation),
		Limit:  qrdbQueryPageSize,
	}
	if !filter.Until.IsZero() {
		// QueryFilter.Until is inclusive; the go-qrdb To bound is exclusive.
		qf.To = filter.Until.Add(time.Nanosecond)
	}
	var matched []Entry
	skipped := 0
	s.mu.RLock()
	defer s.mu.RUnlock()
	for {
		page, err := s.sink.Query(context.Background(), qf)
		if err != nil || page == nil {
			return matched
		}
		for i := range page.Events {
			e := qrdbEventToEntry(page.Events[i])
			if !filter.matches(e) {
				continue
			}
			if skipped < filter.Offset {
				skipped++
				continue
			}
			matched = append(matched, e)
			if filter.Limit > 0 && len(matched) >= filter.Limit {
				return matched
			}
		}
		if page.Next == "" {
			return matched
		}
		qf.Cursor = page.Next
	}
}

// Count returns the number of entries in the go-qrdb sink.
func (s *QRDBStore) Count() int { return len(s.Query(QueryFilter{})) }

// matches reports whether e passes the filter fields the go-qrdb query does
// not apply itself.
func (f QueryFilter) matches(e Entry) bool {
	switch {
	case f.Operation != "" && e.Operation != f.Operation,
		f.Backend != "" && e.Backend != f.Backend,
		f.KeyID != "" && e.KeyID != f.KeyID,
		f.DeviceID != "" && e.DeviceID != f.DeviceID,
		f.Success != nil && e.Success != *f.Success,
		!f.Since.IsZero() && e.Timestamp.Before(f.Since),
		!f.Until.IsZero() && e.Timestamp.After(f.Until):
		return false
	}
	return true
}

func entryToQRDBEvent(e Entry) xkms.QRDBNodeAuditEvent {
	attrs := map[string]any{}
	put := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	put(attrBackend, e.Backend)
	put(attrKeyID, e.KeyID)
	put(attrDeviceID, e.DeviceID)
	put(attrDeviceName, e.DeviceName)
	put(attrError, e.Error)
	if e.DurationMs != 0 {
		attrs[attrDurationMs] = e.DurationMs
	}
	if len(e.Details) > 0 {
		attrs[attrDetails] = e.Details
	}
	outcome := "success"
	if !e.Success {
		outcome = "failure"
		if e.Error != "" {
			outcome = "failure:" + e.Error
		}
	}
	resource := "xkey"
	switch {
	case e.KeyID != "":
		resource = "key:" + e.KeyID
	case e.DeviceID != "":
		resource = "device:" + e.DeviceID
	case e.Backend != "":
		resource = "backend:" + e.Backend
	}
	return xkms.QRDBNodeAuditEvent{
		Timestamp:  e.Timestamp.UTC(),
		Actor:      qrdbActor,
		Resource:   resource,
		Action:     string(e.Operation),
		Outcome:    outcome,
		Attributes: attrs,
	}
}

func qrdbEventToEntry(ev xkms.QRDBNodeAuditEvent) Entry {
	str := func(k string) string {
		v, _ := ev.Attributes[k].(string)
		return v
	}
	e := Entry{
		Timestamp:  ev.Timestamp,
		Operation:  OperationType(ev.Action),
		Backend:    str(attrBackend),
		KeyID:      str(attrKeyID),
		DeviceID:   str(attrDeviceID),
		DeviceName: str(attrDeviceName),
		Error:      str(attrError),
		Success:    ev.Outcome == "success" || strings.HasPrefix(ev.Outcome, "success:"),
	}
	// A file-backed sink decodes numbers as float64.
	switch d := ev.Attributes[attrDurationMs].(type) {
	case int64:
		e.DurationMs = d
	case float64:
		e.DurationMs = int64(d)
	}
	if d, ok := ev.Attributes[attrDetails].(map[string]any); ok {
		e.Details = d
	}
	return e
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func withSource(details map[string]any, source string) map[string]any {
	if details == nil {
		details = make(map[string]any)
	}
	details["source"] = source
	return details
}
