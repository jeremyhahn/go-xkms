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

package audit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/audit/audittest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

func TestEmit_ProductEventReachesQRDBLoggerWithFieldsAndActor(t *testing.T) {
	sink := qrdbsdk.NewAuditRingBuffer(8)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: "acme"})
	now := time.Now().UTC()

	err := audit.Emit(ctx, sink, &audit.Event{
		Timestamp:  now,
		Subject:    "alice",
		Action:     "sign",
		Resource:   "keys",
		ResourceID: "key-1",
		Outcome:    audit.OutcomeAllow,
		Details:    map[string]string{"transport": "grpc", "remote_addr": "10.0.0.7", "role": "operator"},
	})
	require.NoError(t, err)

	page, err := sink.Query(ctx, qrdbsdk.NodeAuditFilter{Actor: "alice"})
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	ev := page.Events[0]
	assert.Equal(t, "alice", ev.Actor)
	assert.Equal(t, "acme", ev.TenantID)
	assert.Equal(t, "sign", ev.Action)
	assert.Equal(t, "keys", ev.Resource)
	assert.Equal(t, audit.OutcomeAllow, ev.Outcome)
	assert.Equal(t, "10.0.0.7", ev.ClientIP)
	assert.Equal(t, "operator", ev.Role)
	assert.Equal(t, "key-1", ev.Attributes["resource_id"])
	assert.Equal(t, "grpc", ev.Attributes["transport"])
	assert.True(t, ev.Timestamp.Equal(now))
}

func TestEmit_NoIdentityFoldsOntoSystemTenant(t *testing.T) {
	rec := &audittest.Recorder{}

	require.NoError(t, audit.Emit(context.Background(), rec, &audit.Event{Subject: "system", Action: "ca_init"}))
	require.NoError(t, audit.Emit(
		auth.WithIdentity(context.Background(), &auth.Identity{Subject: "bob"}), rec,
		&audit.Event{Subject: "bob", Action: "seal"}))

	records := rec.Records()
	require.Len(t, records, 2)
	for _, r := range records {
		assert.Equal(t, qrdbsdk.SystemTenantID, r.TenantID)
	}
}

func TestEmit_SinkFailureIsTypedGateError(t *testing.T) {
	cause := errors.New("disk full")

	err := audit.Emit(context.Background(), &audittest.Failing{Err: cause}, &audit.Event{Action: "unseal"})

	var gate *qrdbsdk.AuditGateError
	require.ErrorAs(t, err, &gate)
	assert.Equal(t, "unseal", gate.Component)
	assert.ErrorIs(t, err, cause)
}

func TestEmit_NilEvent(t *testing.T) {
	err := audit.Emit(context.Background(), &audittest.Recorder{}, nil)

	assert.ErrorIs(t, err, audit.ErrNilEvent)
}

func TestEmit_NilSinkIsNotAFailure(t *testing.T) {
	assert.NoError(t, audit.Emit(context.Background(), nil, &audit.Event{Action: "seal"}))
}
