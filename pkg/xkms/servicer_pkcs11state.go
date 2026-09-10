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

package xkms

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// ErrPKCS11StateStoreUnavailable is returned when a PKCS#11-state RPC arrives
// but the deployment did not enable the remote-state store.
var ErrPKCS11StateStoreUnavailable = errors.New("xkms: PKCS#11 remote state store is not enabled")

// ErrPKCS11StateTokenRequired is returned when a request omits the token label,
// which every record is namespaced by.
var ErrPKCS11StateTokenRequired = errors.New("xkms: PKCS#11 state request requires a token")

// The PKCS11State* methods are the server side of the remote-mode PKCS#11
// module's persistence: the module serialises its own token/object records and
// this service stores them, namespaced by (tenant, token), in the embedded qrdb
// node. Values are opaque here — the service never parses a module record.

// PKCS11StatePut stores a record.
func (s *XKMSService) PKCS11StatePut(ctx context.Context, req *transport.PKCS11StatePutRequest) (*transport.PKCS11StatePutResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.Token == "" {
		return nil, ErrPKCS11StateTokenRequired
	}
	if s.pkcs11StateStore == nil {
		return nil, ErrPKCS11StateStoreUnavailable
	}
	if err := s.pkcs11StateStore.Put(ctx, req.TenantID, req.Token, req.Key, req.Value); err != nil {
		return nil, err
	}
	return &transport.PKCS11StatePutResponse{}, nil
}

// PKCS11StatePutIfAbsent atomically stores a record only if the key is absent.
func (s *XKMSService) PKCS11StatePutIfAbsent(ctx context.Context, req *transport.PKCS11StatePutIfAbsentRequest) (*transport.PKCS11StatePutIfAbsentResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.Token == "" {
		return nil, ErrPKCS11StateTokenRequired
	}
	if s.pkcs11StateStore == nil {
		return nil, ErrPKCS11StateStoreUnavailable
	}
	stored, err := s.pkcs11StateStore.PutIfAbsent(ctx, req.TenantID, req.Token, req.Key, req.Value)
	if err != nil {
		return nil, err
	}
	return &transport.PKCS11StatePutIfAbsentResponse{Stored: stored}, nil
}

// PKCS11StateCAS atomically stores New only if the current value equals Expected
// (or, when ExpectAbsent is set, only if the key is absent). It backs the
// multi-client lockout-counter value-CAS.
func (s *XKMSService) PKCS11StateCAS(ctx context.Context, req *transport.PKCS11StateCASRequest) (*transport.PKCS11StateCASResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.Token == "" {
		return nil, ErrPKCS11StateTokenRequired
	}
	if s.pkcs11StateStore == nil {
		return nil, ErrPKCS11StateStoreUnavailable
	}
	// A nil expected value tells the store "require absent"; ExpectAbsent makes
	// that intent explicit on the wire (JSON cannot distinguish an omitted byte
	// slice from an empty one otherwise).
	var expected []byte
	if !req.ExpectAbsent {
		expected = req.Expected
	}
	swapped, current, err := s.pkcs11StateStore.CompareAndSwap(ctx, req.TenantID, req.Token, req.Key, expected, req.New)
	if err != nil {
		return nil, err
	}
	return &transport.PKCS11StateCASResponse{Swapped: swapped, Current: current}, nil
}

// PKCS11StateCAD atomically removes a record only if its current value equals
// Expected. It backs the guarded release over the remote backend; an absent key
// or a different value is reported as Deleted=false without an error.
func (s *XKMSService) PKCS11StateCAD(ctx context.Context, req *transport.PKCS11StateCADRequest) (*transport.PKCS11StateCADResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.Token == "" {
		return nil, ErrPKCS11StateTokenRequired
	}
	if s.pkcs11StateStore == nil {
		return nil, ErrPKCS11StateStoreUnavailable
	}
	deleted, err := s.pkcs11StateStore.CompareAndDelete(ctx, req.TenantID, req.Token, req.Key, req.Expected)
	if err != nil {
		return nil, err
	}
	return &transport.PKCS11StateCADResponse{Deleted: deleted}, nil
}

// PKCS11StateGet retrieves a record.
func (s *XKMSService) PKCS11StateGet(ctx context.Context, req *transport.PKCS11StateGetRequest) (*transport.PKCS11StateGetResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.Token == "" {
		return nil, ErrPKCS11StateTokenRequired
	}
	if s.pkcs11StateStore == nil {
		return nil, ErrPKCS11StateStoreUnavailable
	}
	value, found, err := s.pkcs11StateStore.Get(ctx, req.TenantID, req.Token, req.Key)
	if err != nil {
		return nil, err
	}
	return &transport.PKCS11StateGetResponse{Value: value, Found: found}, nil
}

// PKCS11StateDelete removes a record.
func (s *XKMSService) PKCS11StateDelete(ctx context.Context, req *transport.PKCS11StateDeleteRequest) (*transport.PKCS11StateDeleteResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.Token == "" {
		return nil, ErrPKCS11StateTokenRequired
	}
	if s.pkcs11StateStore == nil {
		return nil, ErrPKCS11StateStoreUnavailable
	}
	if err := s.pkcs11StateStore.Delete(ctx, req.TenantID, req.Token, req.Key); err != nil {
		return nil, err
	}
	return &transport.PKCS11StateDeleteResponse{}, nil
}

// PKCS11StateList lists namespace-relative keys under a prefix.
func (s *XKMSService) PKCS11StateList(ctx context.Context, req *transport.PKCS11StateListRequest) (*transport.PKCS11StateListResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.Token == "" {
		return nil, ErrPKCS11StateTokenRequired
	}
	if s.pkcs11StateStore == nil {
		return nil, ErrPKCS11StateStoreUnavailable
	}
	keys, err := s.pkcs11StateStore.List(ctx, req.TenantID, req.Token, req.Prefix)
	if err != nil {
		return nil, err
	}
	return &transport.PKCS11StateListResponse{Keys: keys}, nil
}
