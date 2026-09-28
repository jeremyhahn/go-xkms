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
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// ErrPKCS11StateStoreUnavailable is returned when a PKCS#11-state RPC arrives
// but the deployment did not enable the remote-state store.
var ErrPKCS11StateStoreUnavailable = errors.New("xkms: PKCS#11 remote state store is not enabled")

// ErrPKCS11StateTokenRequired is returned when a request omits the token label,
// which every record is namespaced by.
var ErrPKCS11StateTokenRequired = errors.New("xkms: PKCS#11 state request requires a token")

// ErrPKCS11StateTenantMismatch is returned when a request names a tenant other
// than the authenticated caller's. The tenant a record lives under is always the
// caller's own; the request field exists only so a module configured with its
// tenant can state it, and a statement that disagrees is refused rather than
// silently rewritten, so a misconfigured module fails loudly instead of reading
// an empty namespace and initialising a fresh token over it.
var ErrPKCS11StateTenantMismatch = errors.New("xkms: PKCS#11 state tenant_id does not match the authenticated identity's tenant")

// ErrPKCS11StateTokenSeparator is returned when a token label contains '/'.
// The store keys records as pkcs11state/<tenant>/<token>/<key>, so a '/' in the
// token would let token "a/b" alias key "b/..." of token "a". Keys may contain
// '/' — the module's own keys are hierarchical ("pkcs11/tokens/0") and the key
// is the final segment, so it cannot reach outside its token.
var ErrPKCS11StateTokenSeparator = errors.New("xkms: PKCS#11 state token must not contain '/'")

// IsPKCS11StateRequestError reports whether err is a fault in the PKCS#11-state
// request itself — a missing or malformed token label, or a tenant other than
// the caller's — so every transport answers it as an invalid argument rather
// than a server failure.
func IsPKCS11StateRequestError(err error) bool {
	return errors.Is(err, ErrPKCS11StateTokenRequired) ||
		errors.Is(err, ErrPKCS11StateTokenSeparator) ||
		errors.Is(err, ErrPKCS11StateTenantMismatch)
}

// The PKCS11State* methods are the server side of the remote-mode PKCS#11
// module's persistence: the module serialises its own token/object records and
// this service stores them, namespaced by (tenant, token), in one shared store.
// Values are opaque here — the service never parses a module record.
//
// The tenant is never taken from the request. pkcs11StateScope derives it from
// the authenticated identity, so every operation is confined to the caller's
// own namespace whatever the body says.

// pkcs11StateScope validates the (tenant, token) a request addresses and
// returns the tenant namespace to use, which is the caller's own.
//
// The namespace is scopedTenantIDFromContext's: a tenant identity's tenant, or
// "" for a platform-scoped caller (the reserved system tenant or no identity),
// which is where system-scope records have always lived. A supplied tenant is
// accepted only when it names that same namespace — empty, or the caller's own
// tenant, with the system tenant ID and "" treated as one — so a module that
// states its configured tenant keeps working and one that names another tenant
// is refused. The comparison involves only the caller's identity, so the
// refusal reveals nothing about the other tenant.
func (s *XKMSService) pkcs11StateScope(ctx context.Context, suppliedTenant, token string) (string, error) {
	if token == "" {
		return "", ErrPKCS11StateTokenRequired
	}
	if strings.Contains(token, "/") {
		return "", ErrPKCS11StateTokenSeparator
	}
	if s.pkcs11StateStore == nil {
		return "", ErrPKCS11StateStoreUnavailable
	}
	tenantID := scopedTenantIDFromContext(ctx)
	if suppliedTenant == "" {
		return tenantID, nil
	}
	supplied := suppliedTenant
	if qrdbsdk.IsSystemTenant(supplied) {
		supplied = ""
	}
	if supplied != tenantID {
		return "", ErrPKCS11StateTenantMismatch
	}
	return tenantID, nil
}

// PKCS11StatePut stores a record.
func (s *XKMSService) PKCS11StatePut(ctx context.Context, req *transport.PKCS11StatePutRequest) (*transport.PKCS11StatePutResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	tenantID, err := s.pkcs11StateScope(ctx, req.TenantID, req.Token)
	if err != nil {
		return nil, err
	}
	if err := s.pkcs11StateStore.Put(ctx, tenantID, req.Token, req.Key, req.Value); err != nil {
		return nil, err
	}
	return &transport.PKCS11StatePutResponse{}, nil
}

// PKCS11StatePutIfAbsent atomically stores a record only if the key is absent.
func (s *XKMSService) PKCS11StatePutIfAbsent(ctx context.Context, req *transport.PKCS11StatePutIfAbsentRequest) (*transport.PKCS11StatePutIfAbsentResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	tenantID, err := s.pkcs11StateScope(ctx, req.TenantID, req.Token)
	if err != nil {
		return nil, err
	}
	stored, err := s.pkcs11StateStore.PutIfAbsent(ctx, tenantID, req.Token, req.Key, req.Value)
	if err != nil {
		return nil, err
	}
	return &transport.PKCS11StatePutIfAbsentResponse{Stored: stored}, nil
}

// PKCS11StateCAS atomically stores New only if the key exists and its current
// value equals Expected exactly. It backs the multi-client lockout-counter
// value-CAS. The create-if-absent precondition is served by the dedicated
// PKCS11StatePutIfAbsent RPC.
func (s *XKMSService) PKCS11StateCAS(ctx context.Context, req *transport.PKCS11StateCASRequest) (*transport.PKCS11StateCASResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	tenantID, err := s.pkcs11StateScope(ctx, req.TenantID, req.Token)
	if err != nil {
		return nil, err
	}
	swapped, current, err := s.pkcs11StateStore.CompareAndSwap(ctx, tenantID, req.Token, req.Key, req.Expected, req.New)
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
	tenantID, err := s.pkcs11StateScope(ctx, req.TenantID, req.Token)
	if err != nil {
		return nil, err
	}
	deleted, err := s.pkcs11StateStore.CompareAndDelete(ctx, tenantID, req.Token, req.Key, req.Expected)
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
	tenantID, err := s.pkcs11StateScope(ctx, req.TenantID, req.Token)
	if err != nil {
		return nil, err
	}
	value, found, err := s.pkcs11StateStore.Get(ctx, tenantID, req.Token, req.Key)
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
	tenantID, err := s.pkcs11StateScope(ctx, req.TenantID, req.Token)
	if err != nil {
		return nil, err
	}
	if err := s.pkcs11StateStore.Delete(ctx, tenantID, req.Token, req.Key); err != nil {
		return nil, err
	}
	return &transport.PKCS11StateDeleteResponse{}, nil
}

// PKCS11StateList lists namespace-relative keys under a prefix.
func (s *XKMSService) PKCS11StateList(ctx context.Context, req *transport.PKCS11StateListRequest) (*transport.PKCS11StateListResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	tenantID, err := s.pkcs11StateScope(ctx, req.TenantID, req.Token)
	if err != nil {
		return nil, err
	}
	keys, err := s.pkcs11StateStore.List(ctx, tenantID, req.Token, req.Prefix)
	if err != nil {
		return nil, err
	}
	return &transport.PKCS11StateListResponse{Keys: keys}, nil
}
