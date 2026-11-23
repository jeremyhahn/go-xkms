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
	"path/filepath"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestNewQRDBStore_NilSinkRefused(t *testing.T) {
	if _, err := NewQRDBStore(nil); !errors.Is(err, ErrNilQRDBSink) {
		t.Fatalf("NewQRDBStore(nil) error = %v, want ErrNilQRDBSink", err)
	}
}

// TestQRDBStore_WritesToGoQRDBSink proves an xkey entry lands in the go-qrdb
// sink as a canonical record and reads back through Query, on the ring and
// on the hash-chained file sink.
func TestQRDBStore_WritesToGoQRDBSink(t *testing.T) {
	file, err := xkms.NewQRDBAuditFileLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("NewQRDBAuditFileLogger: %v", err)
	}
	for name, sink := range map[string]xkms.QRDBNodeAuditLogger{
		"ring": xkms.NewQRDBAuditRingBuffer(64),
		"file": file,
	} {
		t.Run(name, func(t *testing.T) {
			store, err := NewQRDBStore(sink)
			if err != nil {
				t.Fatalf("NewQRDBStore: %v", err)
			}
			defer func() { _ = store.Close() }()

			if err := store.LogCryptoOperation(OpSignRequest, "tpm2", "k1", "d1", "Phone", false, errors.New("denied"), 7); err != nil {
				t.Fatalf("LogCryptoOperation: %v", err)
			}
			if err := store.LogPasswordStoreOperation(OpPasswordAccessed, "gui", true, nil, nil); err != nil {
				t.Fatalf("LogPasswordStoreOperation: %v", err)
			}

			page, err := sink.Query(context.Background(), xkms.QRDBNodeAuditFilter{Action: string(OpSignRequest)})
			if err != nil || page == nil || len(page.Events) != 1 {
				t.Fatalf("sink.Query = %+v, %v; want the one sign event", page, err)
			}
			ev := page.Events[0]
			if ev.Actor != qrdbActor || ev.Resource != "key:k1" || ev.Outcome != "failure:denied" {
				t.Fatalf("sink record = %+v", ev)
			}

			if got := store.Count(); got != 2 {
				t.Fatalf("Count = %d, want 2", got)
			}
			failed := false
			got := store.Query(QueryFilter{Success: &failed})
			if len(got) != 1 {
				t.Fatalf("Query(failed) = %+v, want one entry", got)
			}
			e := got[0]
			if e.Operation != OpSignRequest || e.Backend != "tpm2" || e.KeyID != "k1" || e.DeviceID != "d1" ||
				e.DeviceName != "Phone" || e.Error != "denied" || e.DurationMs != 7 || e.Success {
				t.Fatalf("round-tripped entry = %+v", e)
			}
			pw := store.Query(QueryFilter{Operation: OpPasswordAccessed})
			if len(pw) != 1 || !pw[0].Success || pw[0].Details["source"] != "gui" {
				t.Fatalf("Query(password) = %+v", pw)
			}
			if n := len(store.Query(QueryFilter{Until: time.Now().Add(-time.Hour)})); n != 0 {
				t.Fatalf("Query(until an hour ago) = %d entries, want 0", n)
			}
			if n := len(store.Query(QueryFilter{Offset: 1, Limit: 5})); n != 1 {
				t.Fatalf("Query(offset 1) = %d entries, want 1", n)
			}
		})
	}
}

// TestQRDBStore_MoveToReplaysIntoNewSink proves the start-up ring's events
// move into the persistent go-qrdb file sink and new writes land there.
func TestQRDBStore_MoveToReplaysIntoNewSink(t *testing.T) {
	store, err := NewQRDBStore(xkms.NewQRDBAuditRingBuffer(16))
	if err != nil {
		t.Fatalf("NewQRDBStore: %v", err)
	}
	if err := store.LogServiceEvent(OpServiceStarted, nil); err != nil {
		t.Fatalf("LogServiceEvent: %v", err)
	}
	if err := store.MoveTo(nil); !errors.Is(err, ErrNilQRDBSink) {
		t.Fatalf("MoveTo(nil) error = %v, want ErrNilQRDBSink", err)
	}
	file, err := xkms.NewQRDBAuditFileLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("NewQRDBAuditFileLogger: %v", err)
	}
	if err := store.MoveTo(file); err != nil {
		t.Fatalf("MoveTo: %v", err)
	}
	defer func() { _ = store.Close() }()
	if err := store.LogKeyOperation(OpKeyCreated, "software", "k2", true, nil, 1); err != nil {
		t.Fatalf("LogKeyOperation: %v", err)
	}
	page, err := file.Query(context.Background(), xkms.QRDBNodeAuditFilter{})
	if err != nil || page == nil || len(page.Events) != 2 {
		t.Fatalf("file sink = %+v, %v; want the replayed and the new event", page, err)
	}
	if page.Events[0].Action != string(OpServiceStarted) || page.Events[1].Resource != "key:k2" {
		t.Fatalf("file sink events = %+v", page.Events)
	}
}

// tiedStore holds distinct events at t0..t(distinct-1) seconds and then tied
// events all at one later timestamp, emitted straight into the sink.
func tiedStore(t *testing.T, distinct, tied int) (*QRDBStore, xkms.QRDBNodeAuditLogger) {
	t.Helper()
	sink := xkms.NewQRDBAuditRingBuffer(distinct + tied)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx := context.Background()
	for i := 0; i < distinct; i++ {
		ev := xkms.QRDBNodeAuditEvent{Timestamp: base.Add(time.Duration(i) * time.Second), Actor: qrdbActor, Action: string(OpKeyCreated), Resource: fmt.Sprintf("key:d%d", i), Outcome: "success", Attributes: map[string]any{attrKeyID: fmt.Sprintf("d%d", i)}}
		if err := sink.Emit(ctx, ev); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	tie := base.Add(time.Hour)
	for i := 0; i < tied; i++ {
		ev := xkms.QRDBNodeAuditEvent{Timestamp: tie, Actor: qrdbActor, Action: string(OpKeyCreated), Resource: fmt.Sprintf("key:t%d", i), Outcome: "success", Attributes: map[string]any{attrKeyID: fmt.Sprintf("t%d", i)}}
		if err := sink.Emit(ctx, ev); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	store, err := NewQRDBStore(sink)
	if err != nil {
		t.Fatalf("NewQRDBStore: %v", err)
	}
	return store, sink
}

func uniqueKeys(t *testing.T, entries []Entry) map[string]bool {
	t.Helper()
	seen := map[string]bool{}
	for _, e := range entries {
		if seen[e.KeyID] {
			t.Fatalf("duplicate entry %q", e.KeyID)
		}
		seen[e.KeyID] = true
	}
	return seen
}

// Equal timestamps across a go-qrdb page boundary: go-qrdb v0.51.0-alpha's
// timestamp cursor resumes after the first tied event, so a cursor walk
// repeats; the timestamp-window walk returns each event once and ends.
func TestQRDBStore_QueryPagesAcrossEqualTimestamps(t *testing.T) {
	store, _ := tiedStore(t, qrdbQueryPageSize-2, 4)
	got := store.Query(QueryFilter{})
	if len(got) != qrdbQueryPageSize+2 {
		t.Fatalf("Query returned %d entries, want %d", len(got), qrdbQueryPageSize+2)
	}
	if seen := uniqueKeys(t, got); !seen["t0"] || !seen["t3"] || !seen["d0"] {
		t.Fatalf("Query missed entries")
	}
	if n := store.Count(); n != qrdbQueryPageSize+2 {
		t.Fatalf("Count = %d, want %d", n, qrdbQueryPageSize+2)
	}
	if got := store.Query(QueryFilter{Offset: qrdbQueryPageSize - 1, Limit: 2}); len(got) != 2 {
		t.Fatalf("Query offset/limit returned %d entries, want 2", len(got))
	}
}

func TestQRDBStore_MoveToPagesAcrossEqualTimestamps(t *testing.T) {
	store, _ := tiedStore(t, qrdbQueryPageSize-2, 4)
	next := xkms.NewQRDBAuditRingBuffer(2 * qrdbQueryPageSize)
	if err := store.MoveTo(next); err != nil {
		t.Fatalf("MoveTo: %v", err)
	}
	got := store.Query(QueryFilter{})
	if len(got) != qrdbQueryPageSize+2 {
		t.Fatalf("after MoveTo %d entries, want %d", len(got), qrdbQueryPageSize+2)
	}
	uniqueKeys(t, got)
}

// More tied events than one page holds cannot be read in full: the walk ends
// with ErrAuditTimestampOverflow instead of looping, and MoveTo keeps the old
// sink.
func TestQRDBStore_TimestampOverflowEndsTheWalk(t *testing.T) {
	store, sink := tiedStore(t, 0, qrdbQueryPageSize+2)
	next := xkms.NewQRDBAuditRingBuffer(4 * qrdbQueryPageSize)
	if err := store.MoveTo(next); !errors.Is(err, ErrAuditTimestampOverflow) {
		t.Fatalf("MoveTo error = %v, want ErrAuditTimestampOverflow", err)
	}
	if store.sink != sink {
		t.Fatalf("MoveTo swapped the sink after a failed replay")
	}
	if n := store.Count(); n > qrdbQueryPageSize+2 {
		t.Fatalf("Count = %d: the walk repeated events", n)
	}
}

// Clock-stamped writes get unique timestamps, so a burst never forms a tie.
func TestQRDBStore_ClockStampedWritesAreUnique(t *testing.T) {
	store, err := NewQRDBStore(xkms.NewQRDBAuditRingBuffer(3 * qrdbQueryPageSize))
	if err != nil {
		t.Fatalf("NewQRDBStore: %v", err)
	}
	n := qrdbQueryPageSize + 5
	for i := 0; i < n; i++ {
		if err := store.LogKeyOperation(OpKeyCreated, "software", fmt.Sprintf("k%d", i), true, nil, 0); err != nil {
			t.Fatalf("LogKeyOperation: %v", err)
		}
	}
	got := store.Query(QueryFilter{})
	if len(got) != n {
		t.Fatalf("Query returned %d entries, want %d", len(got), n)
	}
	for i := 1; i < len(got); i++ {
		if !got[i].Timestamp.After(got[i-1].Timestamp) {
			t.Fatalf("timestamps %d and %d not strictly increasing", i-1, i)
		}
	}
}

// failingQRDBSink is a go-qrdb sink whose every write fails.
type failingQRDBSink struct {
	xkms.QRDBNodeAuditLogger
	err error
}

var errSinkDown = errors.New("sink down")

func (f failingQRDBSink) Emit(context.Context, xkms.QRDBNodeAuditEvent) error { return f.err }

// TestQRDBStore_WriteFailurePolicy proves the go-xkms write-failure policy
// holds on the go-qrdb sink: a security event that is not recorded fails,
// an informational one is logged and does not.
func TestQRDBStore_WriteFailurePolicy(t *testing.T) {
	store, err := NewQRDBStore(failingQRDBSink{err: errSinkDown})
	if err != nil {
		t.Fatalf("NewQRDBStore: %v", err)
	}
	var failed *ErrAuditWriteFailed
	if err := store.LogKeyOperation(OpKeyCreated, "software", "k1", true, nil, 1); !errors.As(err, &failed) || !errors.Is(err, errSinkDown) {
		t.Fatalf("security write error = %v, want *ErrAuditWriteFailed wrapping the sink error", err)
	}
	if err := store.LogConnectionEvent(OpConnectionEstablished, "d1", "Phone", nil); err != nil {
		t.Fatalf("informational write error = %v, want nil", err)
	}
}
