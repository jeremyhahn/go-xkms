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

package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// This file covers service_audit.go (go-xkms #705, batch A): QueryAudit and
// its auditEventToProto projection shipped without a test.

// grpcFakeAuditClient is an in-memory qrdbtransport.AuditClient echoing the
// filter it was called with, so a test can pin the field mapping both
// directions.
type grpcFakeAuditClient struct {
	lastFilter qrdbtransport.AuditFilter
	page       *qrdbtransport.AuditPage
	err        error
}

var _ qrdbtransport.AuditClient = (*grpcFakeAuditClient)(nil)

func (f *grpcFakeAuditClient) EmitAudit(context.Context, qrdbtransport.AuditEvent) error {
	return errors.New("not used")
}

func (f *grpcFakeAuditClient) QueryAudit(_ context.Context, filter qrdbtransport.AuditFilter) (*qrdbtransport.AuditPage, error) {
	f.lastFilter = filter
	if f.err != nil {
		return nil, f.err
	}
	return f.page, nil
}

func newAuditGRPCService(t *testing.T, client *grpcFakeAuditClient) *Service {
	t.Helper()
	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetAuditClient(client)
	return NewService(nil, nil, xkmsSvc)
}

func TestServiceQueryAudit_Success(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	client := &grpcFakeAuditClient{page: &qrdbtransport.AuditPage{
		Events: []qrdbtransport.AuditEvent{{
			Timestamp: ts, Actor: "alice", Resource: "key", Action: "sign", Outcome: "success",
			Attributes: map[string]any{"ip": "127.0.0.1"}, RequestID: "req-1", PrevHash: "hash-0",
		}},
		Next: "cursor-1", Total: 1,
	}}
	svc := newAuditGRPCService(t, client)

	resp, err := svc.QueryAudit(context.Background(), &pb.QueryAuditRequest{
		Actor: "alice", Resource: "key", Limit: 10, Cursor: "start",
	})
	require.NoError(t, err)
	assert.Equal(t, "cursor-1", resp.Next)
	assert.Equal(t, int32(1), resp.Total)
	require.Len(t, resp.Events, 1)
	assert.Equal(t, "alice", resp.Events[0].Actor)
	assert.Equal(t, "sign", resp.Events[0].Action)
	assert.Equal(t, ts, resp.Events[0].Timestamp.AsTime())
	assert.Equal(t, "127.0.0.1", resp.Events[0].Attributes.AsMap()["ip"])

	// The filter the client sent reaches the audit backend unchanged.
	assert.Equal(t, "alice", client.lastFilter.Actor)
	assert.Equal(t, "key", client.lastFilter.Resource)
	assert.Equal(t, 10, client.lastFilter.Limit)
	assert.Equal(t, "start", client.lastFilter.Cursor)
}

func TestServiceQueryAudit_NilAttributes(t *testing.T) {
	client := &grpcFakeAuditClient{page: &qrdbtransport.AuditPage{
		Events: []qrdbtransport.AuditEvent{{Actor: "alice", Action: "sign"}},
	}}
	svc := newAuditGRPCService(t, client)

	resp, err := svc.QueryAudit(context.Background(), &pb.QueryAuditRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Events, 1)
	assert.Nil(t, resp.Events[0].Attributes, "a nil attributes map never panics and stays nil, not an empty Struct")
}

func TestServiceQueryAudit_NilRequest(t *testing.T) {
	svc := newAuditGRPCService(t, &grpcFakeAuditClient{})
	_, err := svc.QueryAudit(context.Background(), nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceQueryAudit_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.QueryAudit(context.Background(), &pb.QueryAuditRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceQueryAudit_BackendError(t *testing.T) {
	client := &grpcFakeAuditClient{err: errors.New("chain read failed")}
	svc := newAuditGRPCService(t, client)
	_, err := svc.QueryAudit(context.Background(), &pb.QueryAuditRequest{})
	assert.Equal(t, codes.Internal, status.Code(err))
}
