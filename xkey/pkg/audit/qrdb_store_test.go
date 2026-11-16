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
