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

package quic

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// The PKCS11State* client methods carry a remote-mode PKCS#11 module's durable
// token and object state to xkmsd over QUIC (HTTP/3, JSON). They are the client
// half of pkg/api/quic/handlers_pkcs11state.go. Every call is a POST with the
// opaque record in the JSON body, so a binary value is never smuggled through a
// URL path or query.

const (
	pkcs11StatePutPath         = "/api/v1/pkcs11state/put"
	pkcs11StatePutIfAbsentPath = "/api/v1/pkcs11state/put-if-absent"
	pkcs11StateCASPath         = "/api/v1/pkcs11state/compare-and-swap"
	pkcs11StateCADPath         = "/api/v1/pkcs11state/compare-and-delete"
	pkcs11StateGetPath         = "/api/v1/pkcs11state/get"
	pkcs11StateDeletePath      = "/api/v1/pkcs11state/delete"
	pkcs11StateListPath        = "/api/v1/pkcs11state/list"
)

// PKCS11StatePut stores a record.
func (t *Transport) PKCS11StatePut(ctx context.Context, req *transport.PKCS11StatePutRequest) (*transport.PKCS11StatePutResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	if _, err := t.doRawRequest(ctx, http.MethodPost, pkcs11StatePutPath, req); err != nil {
		return nil, err
	}
	return &transport.PKCS11StatePutResponse{}, nil
}

// PKCS11StatePutIfAbsent atomically stores a record only if the key is absent.
func (t *Transport) PKCS11StatePutIfAbsent(ctx context.Context, req *transport.PKCS11StatePutIfAbsentRequest) (*transport.PKCS11StatePutIfAbsentResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.doRawRequest(ctx, http.MethodPost, pkcs11StatePutIfAbsentPath, req)
	if err != nil {
		return nil, err
	}
	var resp transport.PKCS11StatePutIfAbsentResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse pkcs11 state put-if-absent response", Err: err}
	}
	return &resp, nil
}

// PKCS11StateCAS atomically stores New only if the current value equals Expected
// (or, when ExpectAbsent is set, only if the key is absent).
func (t *Transport) PKCS11StateCAS(ctx context.Context, req *transport.PKCS11StateCASRequest) (*transport.PKCS11StateCASResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.doRawRequest(ctx, http.MethodPost, pkcs11StateCASPath, req)
	if err != nil {
		return nil, err
	}
	var resp transport.PKCS11StateCASResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse pkcs11 state compare-and-swap response", Err: err}
	}
	return &resp, nil
}

// PKCS11StateCAD atomically removes a record only if its current value equals
// Expected; the guard is evaluated by the server.
func (t *Transport) PKCS11StateCAD(ctx context.Context, req *transport.PKCS11StateCADRequest) (*transport.PKCS11StateCADResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.doRawRequest(ctx, http.MethodPost, pkcs11StateCADPath, req)
	if err != nil {
		return nil, err
	}
	var resp transport.PKCS11StateCADResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse pkcs11 state compare-and-delete response", Err: err}
	}
	return &resp, nil
}

// PKCS11StateGet retrieves a record.
func (t *Transport) PKCS11StateGet(ctx context.Context, req *transport.PKCS11StateGetRequest) (*transport.PKCS11StateGetResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.doRawRequest(ctx, http.MethodPost, pkcs11StateGetPath, req)
	if err != nil {
		return nil, err
	}
	var resp transport.PKCS11StateGetResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse pkcs11 state get response", Err: err}
	}
	return &resp, nil
}

// PKCS11StateDelete removes a record.
func (t *Transport) PKCS11StateDelete(ctx context.Context, req *transport.PKCS11StateDeleteRequest) (*transport.PKCS11StateDeleteResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	if _, err := t.doRawRequest(ctx, http.MethodPost, pkcs11StateDeletePath, req); err != nil {
		return nil, err
	}
	return &transport.PKCS11StateDeleteResponse{}, nil
}

// PKCS11StateList lists namespace-relative keys under a prefix.
func (t *Transport) PKCS11StateList(ctx context.Context, req *transport.PKCS11StateListRequest) (*transport.PKCS11StateListResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.doRawRequest(ctx, http.MethodPost, pkcs11StateListPath, req)
	if err != nil {
		return nil, err
	}
	var resp transport.PKCS11StateListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse pkcs11 state list response", Err: err}
	}
	return &resp, nil
}
