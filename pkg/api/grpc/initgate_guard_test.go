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
	"strings"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/initgate"
	"github.com/stretchr/testify/assert"
)

// initCeremonyRPCNames are the gRPC method names an init ceremony RPC would
// plausibly carry, in every naming the transport-neutral operations map to.
// The guard below asserts NONE of them is declared on the KeystoreService:
// the gRPC transport (and the unix transport, which serves the same
// generated service on a unix domain socket) deliberately exposes no init
// ceremony surface, so it carries no pre-operational authentication
// exemption. If one of these names ever appears on the ServiceDesc, this
// test fails, forcing the author to declare the method in
// initgate.Table's GRPC column and wire the state-gated exemption into the
// interceptor chain before shipping.
var initCeremonyRPCNames = []string{
	"GetInitStatus",
	"InitStatus",
	"InitGetStatus",
	"ClaimCertBegin",
	"ClaimCertComplete",
	"InitClaimCertBegin",
	"InitClaimCertComplete",
	"ClaimShareBegin",
	"ClaimShareComplete",
	"InitClaimShareBegin",
	"InitClaimShareComplete",
	"SignCSRInit",
	"InitSignCSR",
}

// TestInitGate_KeystoreServiceDeclaresNoCeremonyRPC pins the fact that the
// gRPC transport exposes no init ceremony verb: the ceremony surface lives
// on REST, QUIC and MCP, all of which derive their pre-operational
// exemption from pkg/api/initgate.
func TestInitGate_KeystoreServiceDeclaresNoCeremonyRPC(t *testing.T) {
	declared := make(map[string]struct{},
		len(pb.KeystoreService_ServiceDesc.Methods)+len(pb.KeystoreService_ServiceDesc.Streams))
	for _, m := range pb.KeystoreService_ServiceDesc.Methods {
		declared[m.MethodName] = struct{}{}
	}
	for _, s := range pb.KeystoreService_ServiceDesc.Streams {
		declared[s.StreamName] = struct{}{}
	}

	for _, name := range initCeremonyRPCNames {
		_, ok := declared[name]
		assert.Falsef(t, ok,
			"KeystoreService declares init ceremony RPC %q; declare it in initgate.Table and wire the pre-operational gate before shipping", name)
	}
}

// TestInitGate_GRPCDerivationEmptyAndServiceQualified asserts the canonical
// table's gRPC derivation is empty (no gate wiring exists on this transport,
// so a non-empty derivation would be a silently unenforced exemption) and
// that any future entry must be a fully-qualified FullMethod path, never a
// bare tail that could collide across co-registered services.
func TestInitGate_GRPCDerivationEmptyAndServiceQualified(t *testing.T) {
	methods := initgate.GRPCPublicMethods()
	assert.Empty(t, methods,
		"initgate GRPC derivation is non-empty but no gRPC gate wiring exists; wire the gate before declaring gRPC names")

	for _, op := range initgate.Ops {
		if m := initgate.Table[op].GRPC; m != "" {
			assert.Truef(t, strings.HasPrefix(m, "/"),
				"initgate GRPC name %q must be a fully-qualified /service/method path", m)
		}
	}
}
