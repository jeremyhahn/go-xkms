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

// Package audittest provides in-memory qrdbsdk.NodeAuditLogger sinks for
// tests of code that emits go-xkms audit events through audit.Emit.
package audittest

import (
	"context"
	"fmt"
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
)

// resourceIDAttribute is the attribute audit.Emit carries Event.ResourceID in.
const resourceIDAttribute = "resource_id"

// Recorder is a sink that keeps every event it is given.
type Recorder struct {
	mu     sync.Mutex
	events []qrdbsdk.NodeAuditEvent
}

// Emit records the event.
func (r *Recorder) Emit(_ context.Context, ev qrdbsdk.NodeAuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

// Query returns an empty page; Recorder is read through Records and Events.
func (r *Recorder) Query(context.Context, qrdbsdk.NodeAuditFilter) (*qrdbsdk.NodeAuditPage, error) {
	return &qrdbsdk.NodeAuditPage{}, nil
}

// Close is a no-op.
func (r *Recorder) Close() error { return nil }

// Records returns the canonical go-qrdb records received so far.
func (r *Recorder) Records() []qrdbsdk.NodeAuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]qrdbsdk.NodeAuditEvent(nil), r.events...)
}

// Events returns the records received so far, mapped back onto the product
// Event they were emitted from.
func (r *Recorder) Events() []*audit.Event {
	records := r.Records()
	events := make([]*audit.Event, len(records))
	for i, rec := range records {
		events[i] = toEvent(rec)
	}
	return events
}

// LastEvent returns the most recent event, or nil when none was received.
func (r *Recorder) LastEvent() *audit.Event {
	events := r.Events()
	if len(events) == 0 {
		return nil
	}
	return events[len(events)-1]
}

// toEvent inverts audit.Emit's mapping: the resource id and every other
// attribute come back as Details.
func toEvent(rec qrdbsdk.NodeAuditEvent) *audit.Event {
	event := &audit.Event{
		Timestamp: rec.Timestamp,
		Subject:   rec.Actor,
		Action:    rec.Action,
		Resource:  rec.Resource,
		Outcome:   rec.Outcome,
	}
	for k, v := range rec.Attributes {
		if k == resourceIDAttribute {
			event.ResourceID = fmt.Sprint(v)
			continue
		}
		if event.Details == nil {
			event.Details = make(map[string]string, len(rec.Attributes))
		}
		event.Details[k] = fmt.Sprint(v)
	}
	return event
}

// Failing is a sink whose Emit always fails with Err and whose Close returns
// CloseErr.
type Failing struct {
	Err      error
	CloseErr error
}

// Emit fails with Err.
func (f *Failing) Emit(context.Context, qrdbsdk.NodeAuditEvent) error { return f.Err }

// Query returns an empty page.
func (f *Failing) Query(context.Context, qrdbsdk.NodeAuditFilter) (*qrdbsdk.NodeAuditPage, error) {
	return &qrdbsdk.NodeAuditPage{}, nil
}

// Close returns CloseErr.
func (f *Failing) Close() error { return f.CloseErr }

var (
	_ qrdbsdk.NodeAuditLogger = (*Recorder)(nil)
	_ qrdbsdk.NodeAuditLogger = (*Failing)(nil)
)
