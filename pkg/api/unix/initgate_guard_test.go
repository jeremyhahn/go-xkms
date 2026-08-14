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

package unix

import (
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/initgate"
	"github.com/stretchr/testify/assert"
)

// TestInitGate_UnixServesNoCeremonyRPC pins the init-ceremony posture of the
// unix transport. The unix server registers exactly one gRPC service — the
// generated xkms.v1.KeystoreService (see Start in grpc_server.go) — and that
// service declares no init ceremony RPC, so the unix socket exposes no
// ceremony verb and needs no pre-operational authentication exemption. Its
// trust boundary is the socket's file mode and directory permissions.
//
// If a ceremony RPC is ever added to the KeystoreService, the initgate GRPC
// derivation stops being empty, this test fails, and the author must wire
// the state-gated exemption into this listener (which today runs the service
// with a nil authorizer under WithLocalTrust) before shipping.
func TestInitGate_UnixServesNoCeremonyRPC(t *testing.T) {
	assert.Empty(t, initgate.GRPCPublicMethods(),
		"initgate declares gRPC ceremony methods but the unix listener has no pre-operational gate wired")

	// The ceremony surface every other transport mounts must not appear on
	// the service this listener registers under any of its wire spellings.
	declared := make(map[string]struct{}, len(pb.KeystoreService_ServiceDesc.Methods))
	for _, m := range pb.KeystoreService_ServiceDesc.Methods {
		declared[m.MethodName] = struct{}{}
	}
	for _, s := range pb.KeystoreService_ServiceDesc.Streams {
		declared[s.StreamName] = struct{}{}
	}
	for _, name := range []string{
		"GetInitStatus", "InitStatus", "InitGetStatus",
		"ClaimCertBegin", "ClaimCertComplete",
		"InitClaimCertBegin", "InitClaimCertComplete",
		"ClaimShareBegin", "ClaimShareComplete",
		"InitClaimShareBegin", "InitClaimShareComplete",
		"SignCSRInit", "InitSignCSR",
	} {
		_, ok := declared[name]
		assert.Falsef(t, ok,
			"unix-served KeystoreService declares init ceremony RPC %q without an initgate exemption wired", name)
	}
}
