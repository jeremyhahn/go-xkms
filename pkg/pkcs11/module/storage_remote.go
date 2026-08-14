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

package module

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	grpctransport "github.com/jeremyhahn/go-xkms/pkg/api/transport/grpc"
	quictransport "github.com/jeremyhahn/go-xkms/pkg/api/transport/quic"
	unixtransport "github.com/jeremyhahn/go-xkms/pkg/api/transport/unix"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Every transport that can back remote storage is pinned to the
// PKCS11StateClient contract, so a signature drift fails the build. gRPC, Unix
// and QUIC are auto-constructed by the module; REST is injected by the
// composition root (the module cannot import transport/rest — see
// initializeClient), and it satisfies the same interface, checked in that
// package. A transport that does not implement these is refused at runtime with
// ErrRemoteClientUnsupported.
var (
	_ PKCS11StateClient = (*grpctransport.Transport)(nil)
	_ PKCS11StateClient = (*unixtransport.Transport)(nil)
	_ PKCS11StateClient = (*quictransport.Transport)(nil)
)

// PKCS11StateClient is the narrow slice of the transport the remote storage
// backend needs: the five PKCS#11-state RPCs. transport.Client — and each
// concrete network transport (gRPC, Unix, and REST/QUIC once they implement
// these) — satisfies it structurally, exactly as transport.Client already
// satisfies PKCS11Transport. Defining it here rather than widening
// PKCS11Transport keeps a mock crypto transport from having to implement
// persistence it does not provide.
type PKCS11StateClient interface {
	PKCS11StatePut(ctx context.Context, req *transport.PKCS11StatePutRequest) (*transport.PKCS11StatePutResponse, error)
	PKCS11StatePutIfAbsent(ctx context.Context, req *transport.PKCS11StatePutIfAbsentRequest) (*transport.PKCS11StatePutIfAbsentResponse, error)
	PKCS11StateCAS(ctx context.Context, req *transport.PKCS11StateCASRequest) (*transport.PKCS11StateCASResponse, error)
	PKCS11StateGet(ctx context.Context, req *transport.PKCS11StateGetRequest) (*transport.PKCS11StateGetResponse, error)
	PKCS11StateDelete(ctx context.Context, req *transport.PKCS11StateDeleteRequest) (*transport.PKCS11StateDeleteResponse, error)
	PKCS11StateList(ctx context.Context, req *transport.PKCS11StateListRequest) (*transport.PKCS11StateListResponse, error)
}

// remoteBackend is a storage.Backend that persists the module's token and object
// records in xkmsd over the active transport, so a remote-mode module keeps NO
// local on-disk state (D3): the server is the single source of truth. It is a
// thin translator — the module's own ModuleStorage layer serialises the records;
// this backend only moves opaque bytes keyed by (tenant, token, key).
type remoteBackend struct {
	client   PKCS11StateClient
	tenantID string
	token    string
}

// newRemoteBackend builds a remote storage.Backend. token is the token label the
// records are namespaced under; tenantID is empty for a system-scoped module (the
// server may further scope by the authenticated identity).
func newRemoteBackend(client PKCS11StateClient, tenantID, token string) (storage.Backend, error) {
	if client == nil {
		return nil, ErrRemoteClientRequired
	}
	if token == "" {
		return nil, ErrRemoteTokenRequired
	}
	return &remoteBackend{client: client, tenantID: tenantID, token: token}, nil
}

// remoteBackend provides a linearizable value-CAS (backed by the server's Raft
// transaction), so it satisfies storage.CompareAndSwapper in addition to
// storage.Backend. The lockout-counter update path type-asserts for this.
var _ storage.CompareAndSwapper = (*remoteBackend)(nil)

func (b *remoteBackend) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := b.client.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{
		TenantID: b.tenantID, Token: b.token, Key: key,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "remote state get", Err: err}
	}
	if !resp.Found {
		return nil, storage.ErrNotFound
	}
	return resp.Value, nil
}

func (b *remoteBackend) Put(ctx context.Context, key string, value []byte) error {
	if _, err := b.client.PKCS11StatePut(ctx, &transport.PKCS11StatePutRequest{
		TenantID: b.tenantID, Token: b.token, Key: key, Value: value,
	}); err != nil {
		return &errs.Wrapped{Msg: "remote state put", Err: err}
	}
	return nil
}

func (b *remoteBackend) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	resp, err := b.client.PKCS11StatePutIfAbsent(ctx, &transport.PKCS11StatePutIfAbsentRequest{
		TenantID: b.tenantID, Token: b.token, Key: key, Value: value,
	})
	if err != nil {
		return false, &errs.Wrapped{Msg: "remote state put-if-absent", Err: err}
	}
	return resp.Stored, nil
}

// CompareAndSwap atomically stores newValue only if the current value equals
// expected (or, when expected is nil, only if the key is absent), returning the
// current value on a failed swap. It backs the multi-client lockout-counter
// update: several remote-mode modules sharing one server-side token increment the
// same failed-attempt counter, and only a value-CAS keeps those concurrent
// read-modify-write updates from clobbering each other.
//
// A nil expected is sent as ExpectAbsent so the server can tell "require absent"
// apart from "require the empty value" — JSON cannot distinguish an omitted byte
// slice from an empty one.
func (b *remoteBackend) CompareAndSwap(ctx context.Context, key string, expected, newValue []byte) (bool, []byte, error) {
	resp, err := b.client.PKCS11StateCAS(ctx, &transport.PKCS11StateCASRequest{
		TenantID:     b.tenantID,
		Token:        b.token,
		Key:          key,
		Expected:     expected,
		New:          newValue,
		ExpectAbsent: expected == nil,
	})
	if err != nil {
		return false, nil, &errs.Wrapped{Msg: "remote state compare-and-swap", Err: err}
	}
	return resp.Swapped, resp.Current, nil
}

func (b *remoteBackend) Delete(ctx context.Context, key string) error {
	if _, err := b.client.PKCS11StateDelete(ctx, &transport.PKCS11StateDeleteRequest{
		TenantID: b.tenantID, Token: b.token, Key: key,
	}); err != nil {
		return &errs.Wrapped{Msg: "remote state delete", Err: err}
	}
	return nil
}

func (b *remoteBackend) List(ctx context.Context, prefix string) ([]string, error) {
	resp, err := b.client.PKCS11StateList(ctx, &transport.PKCS11StateListRequest{
		TenantID: b.tenantID, Token: b.token, Prefix: prefix,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "remote state list", Err: err}
	}
	return resp.Keys, nil
}

// Scan lists the keys under a prefix and fetches each, mirroring how the local
// ModuleStorage already composes list-then-get. The server has no streaming
// scan RPC because the module's own persistence never needs one.
func (b *remoteBackend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	keys, err := b.List(ctx, prefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		value, err := b.Get(ctx, key)
		if err != nil {
			return err
		}
		if err := fn(key, value); err != nil {
			return err
		}
	}
	return nil
}

func (b *remoteBackend) Exists(ctx context.Context, key string) (bool, error) {
	resp, err := b.client.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{
		TenantID: b.tenantID, Token: b.token, Key: key,
	})
	if err != nil {
		return false, &errs.Wrapped{Msg: "remote state exists", Err: err}
	}
	return resp.Found, nil
}

// Close is a no-op: the transport is owned by the Module, which closes it in
// Finalize, so the backend must not close it out from under the crypto path.
func (b *remoteBackend) Close() error { return nil }
