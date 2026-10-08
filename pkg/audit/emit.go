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
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// Outcome constants for Event.Outcome.
const (
	OutcomeAllow = "allow"
	OutcomeDeny  = "deny"
)

// Event is one go-xkms product operation (key, CA, PKCS#11, TPM, PIV,
// WebAuthn, seal, authorization) to be recorded on go-qrdb's audit chain.
type Event struct {
	Timestamp  time.Time         `json:"timestamp"`
	Subject    string            `json:"subject"`     // Who performed the action
	Action     string            `json:"action"`      // What action was performed
	Resource   string            `json:"resource"`    // Resource type (keys, certs, users, etc.)
	ResourceID string            `json:"resource_id"` // Specific resource identifier
	Outcome    string            `json:"outcome"`     // OutcomeAllow or OutcomeDeny
	Details    map[string]string `json:"details,omitempty"`
}

// Emit records event on sink, go-qrdb's audit logger. A nil sink means audit
// is not wired for the caller and is not a failure; a nil event is
// ErrNilEvent.
//
// A failed emission is returned as *qrdbsdk.AuditGateError naming the event's
// Action as the component: the event did not reach the sink's durability
// boundary, and the caller must fail the operation that produced it rather
// than let it complete unaudited.
func Emit(ctx context.Context, sink qrdbsdk.NodeAuditLogger, event *Event) error {
	if sink == nil {
		return nil
	}
	if event == nil {
		return ErrNilEvent
	}
	if err := sink.Emit(ctx, toNodeEvent(ctx, event)); err != nil {
		return &qrdbsdk.AuditGateError{Component: event.Action, Err: err}
	}
	return nil
}

// toNodeEvent maps an Event onto go-qrdb's canonical audit record: actor,
// action, resource and outcome map directly, ResourceID and every Details
// entry ride Attributes so no detail is lost in the chain, the remote address
// and role lift into their dedicated fields, and the tenant resolves from the
// authenticated identity on the context.
//
// The tenant is normalized through qrdbsdk.NormalizeTenantID: an absent
// identity, or one with an empty TenantID, folds onto qrdbsdk.SystemTenantID
// rather than "". "" is the audit chain's match-everything filter, so an
// unnormalized event emitted without an identity (a background job, an
// internal operation) would be invisible to a system-tenant auditor (#1134).
func toNodeEvent(ctx context.Context, event *Event) qrdbsdk.NodeAuditEvent {
	attributes := make(map[string]any, len(event.Details)+1)
	for k, v := range event.Details {
		attributes[k] = v
	}
	if event.ResourceID != "" {
		attributes["resource_id"] = event.ResourceID
	}

	var tenantID string
	if id := auth.GetIdentity(ctx); id != nil {
		tenantID = id.TenantID
	}

	return qrdbsdk.NodeAuditEvent{
		Timestamp:  event.Timestamp,
		Actor:      event.Subject,
		Action:     event.Action,
		Resource:   event.Resource,
		Outcome:    event.Outcome,
		Attributes: attributes,
		ClientIP:   event.Details["remote_addr"],
		Role:       event.Details["role"],
		TenantID:   qrdbsdk.NormalizeTenantID(tenantID),
	}
}
