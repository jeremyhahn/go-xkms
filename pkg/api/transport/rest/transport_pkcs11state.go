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

package rest

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// The PKCS11State* client methods carry a remote-mode PKCS#11 module's durable
// token and object state to xkmsd over REST (HTTP, JSON). They are the client
// half of pkg/api/rest/pkcs11state_handlers.go. Because the module cannot import
// this package (an import cycle via pkg/auth), a REST client is constructed by
// the composition root and injected into the module via WithClient. Every call
// is a POST with the opaque record in the JSON body.

// pkcs11StateClient is the contract the module's remote storage backend
// type-asserts a transport to. Asserting it here fails the build if these
// REST methods drift, without this package importing the module (which would
// close an import cycle).
type pkcs11StateClient interface {
	PKCS11StatePut(ctx context.Context, req *transport.PKCS11StatePutRequest) (*transport.PKCS11StatePutResponse, error)
	PKCS11StatePutIfAbsent(ctx context.Context, req *transport.PKCS11StatePutIfAbsentRequest) (*transport.PKCS11StatePutIfAbsentResponse, error)
	PKCS11StateCAS(ctx context.Context, req *transport.PKCS11StateCASRequest) (*transport.PKCS11StateCASResponse, error)
	PKCS11StateCAD(ctx context.Context, req *transport.PKCS11StateCADRequest) (*transport.PKCS11StateCADResponse, error)
	PKCS11StateGet(ctx context.Context, req *transport.PKCS11StateGetRequest) (*transport.PKCS11StateGetResponse, error)
	PKCS11StateDelete(ctx context.Context, req *transport.PKCS11StateDeleteRequest) (*transport.PKCS11StateDeleteResponse, error)
	PKCS11StateList(ctx context.Context, req *transport.PKCS11StateListRequest) (*transport.PKCS11StateListResponse, error)
}

var _ pkcs11StateClient = (*Transport)(nil)

const (
	restPKCS11StatePutPath         = "/api/v1/pkcs11state/put"
	restPKCS11StatePutIfAbsentPath = "/api/v1/pkcs11state/put-if-absent"
	restPKCS11StateCASPath         = "/api/v1/pkcs11state/compare-and-swap"
	restPKCS11StateCADPath         = "/api/v1/pkcs11state/compare-and-delete"
	restPKCS11StateGetPath         = "/api/v1/pkcs11state/get"
	restPKCS11StateDeletePath      = "/api/v1/pkcs11state/delete"
	restPKCS11StateListPath        = "/api/v1/pkcs11state/list"
)

// PKCS11StatePut stores a record.
func (t *Transport) PKCS11StatePut(ctx context.Context, req *transport.PKCS11StatePutRequest) (*transport.PKCS11StatePutResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	if _, err := t.DoRawRequest(ctx, http.MethodPost, restPKCS11StatePutPath, req); err != nil {
		return nil, err
	}
	return &transport.PKCS11StatePutResponse{}, nil
}

// PKCS11StatePutIfAbsent atomically stores a record only if the key is absent.
func (t *Transport) PKCS11StatePutIfAbsent(ctx context.Context, req *transport.PKCS11StatePutIfAbsentRequest) (*transport.PKCS11StatePutIfAbsentResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, restPKCS11StatePutIfAbsentPath, req)
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
// ExpectAbsent is a legacy field now redefined as "PutIfAbsent with New as the
// value" rather than "require absent" (#186); see
// transport.PKCS11StateCASRequest's doc comment for the full contract.
func (t *Transport) PKCS11StateCAS(ctx context.Context, req *transport.PKCS11StateCASRequest) (*transport.PKCS11StateCASResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, restPKCS11StateCASPath, req)
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
	data, err := t.DoRawRequest(ctx, http.MethodPost, restPKCS11StateCADPath, req)
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
	data, err := t.DoRawRequest(ctx, http.MethodPost, restPKCS11StateGetPath, req)
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
	if _, err := t.DoRawRequest(ctx, http.MethodPost, restPKCS11StateDeletePath, req); err != nil {
		return nil, err
	}
	return &transport.PKCS11StateDeleteResponse{}, nil
}

// PKCS11StateList lists namespace-relative keys under a prefix.
func (t *Transport) PKCS11StateList(ctx context.Context, req *transport.PKCS11StateListRequest) (*transport.PKCS11StateListResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	data, err := t.DoRawRequest(ctx, http.MethodPost, restPKCS11StateListPath, req)
	if err != nil {
		return nil, err
	}
	var resp transport.PKCS11StateListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse pkcs11 state list response", Err: err}
	}
	return &resp, nil
}
