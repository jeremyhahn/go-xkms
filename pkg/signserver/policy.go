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

package signserver

import (
	"context"
	"strings"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// counterPrefix is the token-record prefix of a module's PIN-lockout
// counters (pkg/pkcs11/module, ModuleStorage.failedAttemptKey). A remote-mode
// module charges and refunds C_Login attempts there; it is the only token
// state a sign-only consumer writes.
const counterPrefix = "pkcs11/counters/token/"

// tokenRequest is the part of every PKCS11State* request the policy reads.
type tokenRequest interface {
	GetToken() string
}

// keyedTokenRequest is a PKCS11State* request naming one record.
type keyedTokenRequest interface {
	tokenRequest
	GetKey() string
}

// rule decides one RPC. It returns nil to admit the request.
type rule func(p *policy, req any) error

// rules is the complete set of RPCs a sign-only slot serves. A method absent
// from it is refused: the policy is an allowlist, so an RPC added to the
// keystore service later is closed here until it is named.
var rules = map[string]rule{
	pb.KeystoreService_Health_FullMethodName:                 (*policy).admitHealth,
	pb.KeystoreService_Sign_FullMethodName:                   (*policy).admitSign,
	pb.KeystoreService_PKCS11StateGet_FullMethodName:         (*policy).admitTokenRead,
	pb.KeystoreService_PKCS11StateList_FullMethodName:        (*policy).admitTokenRead,
	pb.KeystoreService_PKCS11StatePut_FullMethodName:         (*policy).admitCounterWrite,
	pb.KeystoreService_PKCS11StatePutIfAbsent_FullMethodName: (*policy).admitCounterWrite,
	pb.KeystoreService_PKCS11StateCAS_FullMethodName:         (*policy).admitCounterWrite,
	pb.KeystoreService_PKCS11StateCAD_FullMethodName:         (*policy).admitCounterWrite,
	pb.KeystoreService_PKCS11StateDelete_FullMethodName:      (*policy).admitCounterWrite,
}

// policy is the sign-only allowlist the server installs as a gRPC
// interceptor, after the peer-credential check has admitted the connection.
type policy struct {
	slots map[string]map[string]struct{}
	keys  *atomic.Pointer[keySet]
}

// unary admits a unary RPC only when its rule does.
func (p *policy) unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	decide, ok := rules[info.FullMethod]
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "signserver: "+info.FullMethod+" is not served on a sign-only slot")
	}
	if err := decide(p, req); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	return handler(ctx, req)
}

// stream refuses every streaming RPC: a sign-only slot needs none.
func (p *policy) stream(_ any, _ grpc.ServerStream, info *grpc.StreamServerInfo, _ grpc.StreamHandler) error {
	return status.Error(codes.PermissionDenied, "signserver: "+info.FullMethod+" is not served on a sign-only slot")
}

// admitHealth admits the liveness probe every transport sends on Connect.
// Its answer is a status and the build version; it reads no key or token.
func (p *policy) admitHealth(any) error { return nil }

// admitSign admits a signature only with a key a slot names.
func (p *policy) admitSign(req any) error {
	sign, ok := req.(*pb.SignRequest)
	if !ok {
		return ErrRequestShape
	}
	if !p.keys.Load().admits(sign.GetBackend(), sign.GetKeyId()) {
		return ErrKeyNotAdmitted
	}
	return nil
}

// admitTokenRead admits reading a configured slot's token records.
func (p *policy) admitTokenRead(req any) error {
	r, ok := req.(tokenRequest)
	if !ok {
		return ErrRequestShape
	}
	if _, known := p.slots[r.GetToken()]; !known {
		return ErrUnknownSlot
	}
	return nil
}

// admitCounterWrite admits a write only to a configured slot's PIN-lockout
// counters. Token state, PIN verifiers and key objects are written by the
// embedder through CreateKey, never by the consumer.
func (p *policy) admitCounterWrite(req any) error {
	r, ok := req.(keyedTokenRequest)
	if !ok {
		return ErrRequestShape
	}
	if _, known := p.slots[r.GetToken()]; !known {
		return ErrUnknownSlot
	}
	if !strings.HasPrefix(r.GetKey(), counterPrefix) {
		return ErrTokenWriteDenied
	}
	return nil
}
