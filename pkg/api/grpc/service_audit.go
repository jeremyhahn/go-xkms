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

package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// auditEventToProto projects a transport.AuditEvent onto its protobuf form.
// A nil Attributes map converts to a nil Struct rather than panicking.
func auditEventToProto(e transport.AuditEvent) (*pb.AuditEvent, error) {
	var attrs *structpb.Struct
	if e.Attributes != nil {
		s, err := structpb.NewStruct(e.Attributes)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to encode audit attributes: "+err.Error())
		}
		attrs = s
	}
	return &pb.AuditEvent{
		Timestamp:  timestamppb.New(e.Timestamp),
		Actor:      e.Actor,
		TenantId:   e.TenantID,
		Role:       e.Role,
		Resource:   e.Resource,
		Action:     e.Action,
		Outcome:    e.Outcome,
		Attributes: attrs,
		ClientIp:   e.ClientIP,
		RequestId:  e.RequestID,
		PrevHash:   e.PrevHash,
	}, nil
}

// QueryAudit returns one page of audit events from the tamper-evident audit
// chain owned by the embedded qrdb node.
func (s *Service) QueryAudit(ctx context.Context, req *pb.QueryAuditRequest) (*pb.QueryAuditResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := s.authorize(ctx, auth.ResourceAudit, auth.ActionRead, ""); err != nil {
		return nil, err
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	filter := &transport.AuditFilter{
		Actor:    req.GetActor(),
		Resource: req.GetResource(),
		Action:   req.GetAction(),
		Outcome:  req.GetOutcome(),
		TenantID: req.GetTenantId(),
		Limit:    int(req.GetLimit()),
		Cursor:   req.GetCursor(),
	}
	if ts := req.GetFrom(); ts != nil {
		filter.From = ts.AsTime()
	}
	if ts := req.GetTo(); ts != nil {
		filter.To = ts.AsTime()
	}

	page, err := svc.QueryAudit(ctx, filter)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	events := make([]*pb.AuditEvent, len(page.Events))
	for i, e := range page.Events {
		pe, cErr := auditEventToProto(e)
		if cErr != nil {
			return nil, cErr
		}
		events[i] = pe
	}

	return &pb.QueryAuditResponse{
		Events: events,
		Next:   page.Next,
		Total:  int32(page.Total), // #nosec G115 - audit page totals fit in int32
	}, nil
}
