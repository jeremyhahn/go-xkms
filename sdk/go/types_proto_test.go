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

package xkms

import (
	"testing"

	"google.golang.org/grpc"
)

// stubKeystoreServiceServer satisfies ProtoKeystoreServiceServer by
// embedding the forward-compatible Unimplemented type; ProtoRegister only
// needs a value of the right type, never a working implementation.
type stubKeystoreServiceServer struct {
	ProtoUnimplementedKeystoreServiceServer
}

// TestProtoRegister pins that the convenience wrapper registers the service
// on the given *grpc.Server without panicking — a regression here (e.g. a
// typo'd service descriptor) would otherwise only surface at runtime on the
// first RPC.
func TestProtoRegister(t *testing.T) {
	server := grpc.NewServer()
	ProtoRegister(server, &stubKeystoreServiceServer{})

	info := server.GetServiceInfo()
	if _, ok := info["xkms.v1.KeystoreService"]; !ok {
		t.Fatalf("KeystoreService not registered; got services: %v", info)
	}
}
