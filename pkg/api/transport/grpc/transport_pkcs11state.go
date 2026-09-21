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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// The PKCS11State* client methods carry a remote-mode PKCS#11 module's durable
// token and object state to xkmsd over gRPC. They are the client half of
// pkg/api/grpc/service_pkcs11state.go; a module's remote storage.Backend type-
// asserts the transport to the narrow client interface these satisfy.

// PKCS11StatePut stores a record.
func (t *Transport) PKCS11StatePut(ctx context.Context, req *transport.PKCS11StatePutRequest) (*transport.PKCS11StatePutResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	if _, err := t.client.PKCS11StatePut(ctx, &pb.PKCS11StatePutRequest{
		TenantId: req.TenantID, Token: req.Token, Key: req.Key, Value: req.Value,
	}); err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11 state put failed", Err: err}
	}
	return &transport.PKCS11StatePutResponse{}, nil
}

// PKCS11StatePutIfAbsent atomically stores a record only if the key is absent.
func (t *Transport) PKCS11StatePutIfAbsent(ctx context.Context, req *transport.PKCS11StatePutIfAbsentRequest) (*transport.PKCS11StatePutIfAbsentResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.PKCS11StatePutIfAbsent(ctx, &pb.PKCS11StatePutIfAbsentRequest{
		TenantId: req.TenantID, Token: req.Token, Key: req.Key, Value: req.Value,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11 state put-if-absent failed", Err: err}
	}
	return &transport.PKCS11StatePutIfAbsentResponse{Stored: resp.Stored}, nil
}

// PKCS11StateCAS atomically stores New only if the current value equals Expected
// ExpectAbsent is a legacy field now redefined as "PutIfAbsent with New as the
// value" rather than "require absent" (#186); see
// transport.PKCS11StateCASRequest's doc comment for the full contract.
func (t *Transport) PKCS11StateCAS(ctx context.Context, req *transport.PKCS11StateCASRequest) (*transport.PKCS11StateCASResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.PKCS11StateCAS(ctx, &pb.PKCS11StateCASRequest{
		TenantId: req.TenantID, Token: req.Token, Key: req.Key,
		Expected: req.Expected, New: req.New, ExpectAbsent: req.ExpectAbsent,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11 state compare-and-swap failed", Err: err}
	}
	return &transport.PKCS11StateCASResponse{Swapped: resp.Swapped, Current: resp.Current}, nil
}

// PKCS11StateCAD atomically removes a record only if its current value equals
// Expected; the guard is evaluated by the server.
func (t *Transport) PKCS11StateCAD(ctx context.Context, req *transport.PKCS11StateCADRequest) (*transport.PKCS11StateCADResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.PKCS11StateCAD(ctx, &pb.PKCS11StateCADRequest{
		TenantId: req.TenantID, Token: req.Token, Key: req.Key, Expected: req.Expected,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11 state compare-and-delete failed", Err: err}
	}
	return &transport.PKCS11StateCADResponse{Deleted: resp.Deleted}, nil
}

// PKCS11StateGet retrieves a record.
func (t *Transport) PKCS11StateGet(ctx context.Context, req *transport.PKCS11StateGetRequest) (*transport.PKCS11StateGetResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.PKCS11StateGet(ctx, &pb.PKCS11StateGetRequest{
		TenantId: req.TenantID, Token: req.Token, Key: req.Key,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11 state get failed", Err: err}
	}
	return &transport.PKCS11StateGetResponse{Value: resp.Value, Found: resp.Found}, nil
}

// PKCS11StateDelete removes a record.
func (t *Transport) PKCS11StateDelete(ctx context.Context, req *transport.PKCS11StateDeleteRequest) (*transport.PKCS11StateDeleteResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	if _, err := t.client.PKCS11StateDelete(ctx, &pb.PKCS11StateDeleteRequest{
		TenantId: req.TenantID, Token: req.Token, Key: req.Key,
	}); err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11 state delete failed", Err: err}
	}
	return &transport.PKCS11StateDeleteResponse{}, nil
}

// PKCS11StateList lists namespace-relative keys under a prefix.
func (t *Transport) PKCS11StateList(ctx context.Context, req *transport.PKCS11StateListRequest) (*transport.PKCS11StateListResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.PKCS11StateList(ctx, &pb.PKCS11StateListRequest{
		TenantId: req.TenantID, Token: req.Token, Prefix: req.Prefix,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11 state list failed", Err: err}
	}
	return &transport.PKCS11StateListResponse{Keys: resp.Keys}, nil
}
